// Cargo.toml 额外依赖
// dashmap = "5"
// once_cell = "1"      （如果你喜欢换掉 lazy_static） 

use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rustls::{pki_types::ServerName, version::TLS12, ClientConfig, RootCertStore};
use sha2::Sha256;
use serde::Deserialize;
use std::{
    sync::{atomic::{AtomicI32, Ordering}, Arc, LazyLock},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, split, WriteHalf},
    net::TcpStream,
    time::sleep,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use uuid::Uuid;
use dashmap::DashMap;                   // ❷ 并发 HashMap

/* ---------- 配置 ---------- */
#[derive(Debug, Deserialize)]
struct Settings { coinbase: CoinbaseCfg }

#[derive(Debug, Deserialize)]
struct CoinbaseCfg {
    key: String,
    secret: String,
    passphrase: String,
    heartbeat_ms: Option<u64>,
    order_host:   Option<String>,
    port:         Option<u16>,
}
impl Settings {
    fn load() -> Self {
        let raw = std::fs::read_to_string("config.toml").expect("无法读取 config.toml");
        toml::from_str(&raw).expect("TOML 解析失败")
    }
}

/* ---------- TLS ---------- */
static TLS_CFG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&TLS12])
            .with_root_certificates(store)
            .with_no_client_auth(),
    )
});
static SEQ_NO: AtomicI32 = AtomicI32::new(1);

const SOH: char = '\x01';               // FIX 分隔

/* ---------- 工具 ---------- */
fn sign(secret_b64: &str, msg: &str) -> String {
    let key = general_purpose::STANDARD.decode(secret_b64).expect("secret 不是合法 base64");
    let mut mac: Hmac<Sha256> = Hmac::new_from_slice(&key).unwrap();
    mac.update(msg.as_bytes());
    general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

fn build_fix(fields: &[(i32, String)]) -> String {
    // 计算 BodyLength(9) 时，不包含 8= 头和 9= 本身，但包含 SOH
    let mut body = String::new();
    for (tag, val) in fields { body.push_str(&format!("{tag}={val}{SOH}")); }
    let len = body.len();
    let mut msg = format!("8=FIXT.1.1{SOH}9={len}{SOH}{body}");
    let cksum: u32 = msg.bytes().map(|b| b as u32).sum();
    msg.push_str(&format!("10={:03}{SOH}", cksum % 256));
    msg
}

fn next_seq() -> String {
    SEQ_NO.fetch_add(1, Ordering::SeqCst).to_string()
}

async fn send(msg: &str, w: &mut WriteHalf<TlsStream<TcpStream>>) {
    w.write_all(msg.as_bytes()).await.unwrap();
    w.flush().await.unwrap();
}

/* ---------- 主 ---------- */
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default().unwrap();
    /* 读取配置 */
    let cfg = Settings::load();
    let hb_gap = Duration::from_millis(cfg.coinbase.heartbeat_ms.unwrap_or(5_000));
    let host   = cfg.coinbase.order_host.clone()
                              .unwrap_or_else(|| "fix-ord.exchange.coinbase.com".into());
    let port   = cfg.coinbase.port.unwrap_or(6121);

    /* TCP + TLS */
    let stream = TcpStream::connect((host.as_str(), port)).await.expect("TCP 连接失败");
    let connector = TlsConnector::from(TLS_CFG.clone());
    let domain = ServerName::try_from(host.clone()).unwrap();
    let tls = connector.connect(domain, stream).await.expect("TLS 失败");
    let (reader, mut writer) = split(tls);

    /* Logon */
    let ts = Utc::now().format("%Y%m%d-%H:%M:%S.%3f").to_string();

    // ❸ Coinbase 文档里要求 “timestamp + 'A' + seqNum + apiKey + passphrase” *不带* SOH
    let raw_to_sign = format!("{ts}A1{}{}", cfg.coinbase.key, cfg.coinbase.passphrase);
    let sig = sign(&cfg.coinbase.secret, &raw_to_sign);

    let logon = build_fix(&[
        (35, "A".into()),
        (49, cfg.coinbase.key.clone()),
        (56, "Coinbase".into()),
        (34, "1".into()),
        (52, ts),
        (98, "0".into()),               // 加密 0=无
        (108, "30".into()),             // HeartBtInt
        (141, "Y".into()),              // 重传标志
        (553, cfg.coinbase.key.clone()),
        (554, cfg.coinbase.passphrase.clone()),
        (95, sig.len().to_string()),
        (96, sig),
        (1137,"9".into()),              // 发送扩展字段
    ]);
    send(&logon, &mut writer).await;

    /* 共享 HashMap ❹ */
    let pending: Arc<DashMap<String, i64>> = Arc::new(DashMap::new());

    /* Heartbeat / TestRequest 任务 */
    {
        let mut w = writer;                     // 把 writer 移进子任务
        let key = cfg.coinbase.key.clone();
        let pend = pending.clone();
        tokio::spawn(async move {
            loop {
                sleep(hb_gap).await;
                let id = Uuid::new_v4().to_string();
                pend.insert(id.clone(), Utc::now().timestamp_millis());

                let tr = build_fix(&[
                    (35,"1".into()),           // TestRequest
                    (49,key.clone()),
                    (56,"Coinbase".into()),
                    (34,next_seq()),
                    (52,Utc::now().format("%Y%m%d-%H:%M:%S.%3f").to_string()),
                    (112,id.clone()),          // TestReqID
                ]);
                send(&tr, &mut w).await;
            }
        });
    }

    /* 读循环 + RTT 统计 */
    let mut reader = BufReader::new(reader);
    let mut head   = Vec::<u8>::with_capacity(64);
    let mut lenbuf = Vec::<u8>::with_capacity(32);
    let mut body   = Vec::<u8>::with_capacity(8192);

    loop {
        head.clear();
        if reader.read_until(b'\x01', &mut head).await.unwrap() == 0 {
            eprintln!("连接断开"); break;
        }
        if !head.starts_with(b"8=FIX") { continue; }

        lenbuf.clear();
        reader.read_until(b'\x01', &mut lenbuf).await.unwrap();
        let len: usize = std::str::from_utf8(&lenbuf[2..lenbuf.len()-1]).unwrap().parse().unwrap();

        body.resize(len + 7, 0);   // (含 10=xxx<SOH>)
        reader.read_exact(&mut body).await.unwrap();
        let msg = String::from_utf8_lossy(&body);

        /* 只关心 Heartbeat 回包 */
        if msg.starts_with("35=0") {
            if let Some(pos) = msg.find("112=") {
                let id = &msg[pos+4..].split('\x01').next().unwrap();
                if let Some((_, t0)) = pending.remove(*id) {          // ❺ 和 Heartbeat 共享
                    let rtt = Utc::now().timestamp_millis() - t0;
                    println!("RTT = {rtt} ms (id={id})");
                }
            }
        }
    }
}