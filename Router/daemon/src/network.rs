//! Reconnecting transport. Packet collection and the XDP watchdog stay alive offline.
use super::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use sqlx::Row;
use tokio_tungstenite::{
    Connector,
    tungstenite::{Message, client::IntoClientRequest},
};

pub async fn initialize(db: &sqlx::SqlitePool) -> anyhow::Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT,network_id TEXT NOT NULL,mac TEXT NOT NULL,bytes_in INTEGER NOT NULL,bytes_out INTEGER NOT NULL,unique_external_ips INTEGER NOT NULL,total_connections INTEGER NOT NULL,passed_connections INTEGER NOT NULL,dropped_connections INTEGER NOT NULL,anomaly_flags_count INTEGER NOT NULL,heuristic_flags_count INTEGER NOT NULL,infra_alert_count INTEGER NOT NULL,port_entropy REAL NOT NULL)").execute(db).await?;
    let cols = sqlx::query("PRAGMA table_info(reports)")
        .fetch_all(db)
        .await?;
    for (col, def) in [
        ("report_key", "TEXT NOT NULL DEFAULT ''"),
        ("captured_at", "INTEGER NOT NULL DEFAULT 0"),
    ] {
        if !cols.iter().any(|r| r.get::<String, _>("name") == col) {
            sqlx::query(&format!("ALTER TABLE reports ADD COLUMN {col} {def}"))
                .execute(db)
                .await?;
        }
    }
    sqlx::query("UPDATE reports SET report_key=lower(hex(randomblob(16))) WHERE report_key=''")
        .execute(db)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS policy_cache(network_id TEXT PRIMARY KEY,data TEXT NOT NULL)",
    )
    .execute(db)
    .await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS outbound_events(id INTEGER PRIMARY KEY AUTOINCREMENT,payload TEXT NOT NULL,network_id TEXT NOT NULL DEFAULT '')").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS local_blocks(network_id TEXT NOT NULL,mac TEXT NOT NULL,PRIMARY KEY(network_id,mac))").execute(db).await?;
    Ok(())
}

pub async fn remember_block(
    db: &sqlx::SqlitePool,
    network: &str,
    mac: &[u8; 6],
    blocked: bool,
) -> Result<(), sqlx::Error> {
    let sql = if blocked {
        "INSERT OR IGNORE INTO local_blocks(network_id,mac) VALUES (?,?)"
    } else {
        "DELETE FROM local_blocks WHERE network_id=? AND mac=?"
    };
    sqlx::query(sql)
        .bind(network)
        .bind(format_mac(mac))
        .execute(db)
        .await?;
    Ok(())
}

pub fn valid_policy(v: &Value) -> bool {
    matches!(v["mode"].as_str(), Some("observe" | "enforce"))
        && v["revision"].as_i64().is_some()
        && v["trusted_macs"].as_array().is_some_and(|a| {
            a.iter()
                .all(|v| v.as_str().is_some_and(|s| parse_mac(s).is_some()))
        })
}
pub fn may_isolate(policy: &Value, mac: &[u8; 6]) -> bool {
    let mac = format_mac(mac);
    policy["mode"] == "enforce"
        && policy["trusted_macs"].as_array().is_some_and(|a| {
            !a.iter()
                .any(|m| m.as_str().is_some_and(|m| m.eq_ignore_ascii_case(&mac)))
        })
}
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Option<Vec<_>> = s
        .split(':')
        .map(|p| {
            if p.len() == 2 {
                u8::from_str_radix(p, 16).ok()
            } else {
                None
            }
        })
        .collect();
    parts?.try_into().ok()
}
pub async fn load_policy(db: &sqlx::SqlitePool, network: &str) -> Value {
    sqlx::query_scalar::<_, String>("SELECT data FROM policy_cache WHERE network_id=?")
        .bind(network)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .filter(valid_policy)
        .unwrap_or(json!({"mode":"observe","revision":-1,"trusted_macs":[]}))
}
pub async fn save_policy(
    db: &sqlx::SqlitePool,
    network: &str,
    policy: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO policy_cache VALUES (?,?) ON CONFLICT(network_id) DO UPDATE SET data=excluded.data").bind(network).bind(policy.to_string()).execute(db).await?;
    Ok(())
}
pub async fn event(db: &sqlx::SqlitePool, network: &str, value: &Value) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO outbound_events(payload,network_id) VALUES (?,?)")
        .bind(value.to_string())
        .bind(network)
        .execute(db)
        .await?;
    // Bound storage during long outages; command requests will replay after reconnect.
    sqlx::query("DELETE FROM outbound_events WHERE id NOT IN (SELECT id FROM outbound_events ORDER BY id DESC LIMIT 2000)").execute(db).await?;
    Ok(())
}
pub async fn store_report(
    db: &sqlx::SqlitePool,
    network: &str,
    mac: [u8; 6],
    totals: DeviceTotals,
) -> Result<(), sqlx::Error> {
    let n: u32 = totals.port_counts.values().sum();
    let entropy = if n == 0 {
        0.0
    } else {
        totals
            .port_counts
            .values()
            .map(|count| {
                let p = *count as f64 / n as f64;
                -p * p.log2()
            })
            .sum()
    };
    let captured = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    sqlx::query("INSERT INTO reports(network_id,mac,bytes_in,bytes_out,unique_external_ips,total_connections,passed_connections,dropped_connections,anomaly_flags_count,heuristic_flags_count,infra_alert_count,port_entropy,report_key,captured_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,lower(hex(randomblob(16))),?)")
        .bind(network).bind(format_mac(&mac)).bind(totals.bytes_in as i64).bind(totals.bytes_out as i64).bind(totals.unique_external_ips.len().round() as i64)
        .bind(totals.total_connections as i64).bind(totals.passed_connections as i64).bind(totals.dropped_connections as i64).bind(totals.anomaly_flags_count as i64)
        .bind(totals.heuristic_flags_count as i64).bind(totals.infra_alert_count as i64).bind(entropy).bind(captured).execute(db).await?;
    let removed = sqlx::query(
        "DELETE FROM reports WHERE id NOT IN (SELECT id FROM reports ORDER BY id DESC LIMIT 10000)",
    )
    .execute(db)
    .await?
    .rows_affected();
    if removed > 0 {
        eprintln!("Outbox capacity reached: discarded {removed} oldest reports");
    }
    Ok(())
}

fn encode(r: &ReportForDb) -> Vec<u8> {
    let mut b = flatbuffers::FlatBufferBuilder::new();
    let network = b.create_string(&r.network_id);
    let mac = b.create_string(&r.mac);
    let id = b.create_string(&r.report_key);
    let report = TelemetryReport::create(
        &mut b,
        &TelemetryReportArgs {
            network_id: Some(network),
            mac: Some(mac),
            report_id: Some(id),
            captured_at: r.captured_at,
            bytes_in: r.bytes_in as u64,
            bytes_out: r.bytes_out as u64,
            unique_external_ips: r.unique_external_ips as u32,
            total_connections: r.total_connections as u32,
            passed_connections: r.passed_connections as u32,
            dropped_connections: r.dropped_connections as u32,
            anomaly_flags_count: r.anomaly_flags_count as u32,
            heuristic_flags_count: r.heuristic_flags_count as u32,
            infra_alert_count: r.infra_alert_count as u32,
            port_entropy_score: r.port_entropy as f32,
            ..Default::default()
        },
    );
    let msg = RouterMessage::create(
        &mut b,
        &RouterMessageArgs {
            payload_type: IncomingPayload::TelemetryReport,
            payload: Some(report.as_union_value()),
        },
    );
    b.finish(msg, None);
    b.finished_data().to_vec()
}

async fn command(
    msg: Message,
    db: &sqlx::SqlitePool,
    network: &str,
    tx: &mpsc::Sender<ExecutionCommand>,
) -> anyhow::Result<()> {
    match msg {
        Message::Text(s) => {
            let v: Value = serde_json::from_str(&s)?;
            match v["type"].as_str() {
                Some("policy") if valid_policy(&v) => {
                    tx.send(ExecutionCommand::SetPolicy(v)).await?
                }
                Some("device_command") => {
                    if let (Some(mac), Some(id), Some(desired)) = (
                        v["mac"].as_str().and_then(parse_mac),
                        v["id"].as_i64(),
                        v["state"].as_str(),
                    ) {
                        if matches!(desired, "blocked" | "allowed") {
                            tx.send(ExecutionCommand::SetDeviceState {
                                mac,
                                id,
                                blocked: desired == "blocked",
                                automatic: v["automatic"].as_bool().unwrap_or(true),
                                revision: v["policy_revision"].as_i64().unwrap_or(-1),
                            })
                            .await?;
                        }
                    }
                }
                Some("telemetry_ack") => {
                    if let Some(id) = v["report_id"].as_str() {
                        sqlx::query("DELETE FROM reports WHERE network_id=? AND report_key=?")
                            .bind(network)
                            .bind(id)
                            .execute(db)
                            .await?;
                    }
                }
                _ => {}
            }
        }
        Message::Binary(bytes) => {
            let response = flatbuffers::root::<RouterResponse>(&bytes)?;
            if let Some(intel) = response.threat_intel() {
                if let Some(domains) = intel.ad_domains() {
                    tx.send(ExecutionCommand::UpdateAdList(
                        domains.iter().map(str::to_owned).collect(),
                    ))
                    .await?;
                }
                if let Some(ips) = intel.banned_ips() {
                    tx.send(ExecutionCommand::UpdateBannedIps(
                        ips.iter().filter_map(|s| s.parse().ok()).collect(),
                    ))
                    .await?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

struct ConnectionSettings {
    base_url: String,
    secret: String,
    certificate: Option<std::path::PathBuf>,
    xdp_attached: bool,
}

pub async fn run(
    db: sqlx::SqlitePool,
    network: String,
    interface: String,
    tx: mpsc::Sender<ExecutionCommand>,
    cancel: CancellationToken,
) {
    let settings = ConnectionSettings {
        base_url: std::env::var("CIPHER_SERVER_URL")
            .unwrap_or_else(|_| "wss://localhost:3000".into()),
        secret: std::env::var("ROUTER_SECRET").unwrap_or_default(),
        certificate: std::env::var("CIPHER_CA_CERT").ok().map(Into::into),
        xdp_attached: true,
    };
    run_with(settings, db, network, interface, tx, cancel).await;
}
async fn run_with(
    settings: ConnectionSettings,
    db: sqlx::SqlitePool,
    network: String,
    interface: String,
    tx: mpsc::Sender<ExecutionCommand>,
    cancel: CancellationToken,
) {
    let mut delay = 1;
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            result=session(&settings,&db,&network,&interface,&tx)=> {
                eprintln!("Cloud connection ended ({}). Collection continues; retrying in {delay}s.",result.err().map(|e|e.to_string()).unwrap_or_else(||"closed".into()));
            }
        }
        tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
        delay = (delay * 2).min(15);
    }
}

async fn send(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    message: Message,
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), socket.send(message)).await??;
    Ok(())
}

async fn session(
    settings: &ConnectionSettings,
    db: &sqlx::SqlitePool,
    network: &str,
    interface: &str,
    tx: &mpsc::Sender<ExecutionCommand>,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/api/router/ws/{}",
        settings.base_url.trim_end_matches('/'),
        network
    );
    anyhow::ensure!(
        url.starts_with("wss://"),
        "CIPHER_SERVER_URL must use wss://"
    );
    let mut req = url.into_client_request()?;
    req.headers_mut().insert(
        "Authorization",
        format!("ApiKey {}", settings.secret).parse()?,
    );
    let mut tls = native_tls::TlsConnector::builder();
    if let Some(path) = &settings.certificate {
        tls.add_root_certificate(native_tls::Certificate::from_pem(&std::fs::read(path)?)?);
    }
    let connector = Connector::NativeTls(tls.build()?);
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector)),
    )
    .await??;
    println!("Cloud reconnected; synchronizing policy and queued reports.");
    let mut tick = interval(Duration::from_secs(1));
    let mut heartbeat = time::Instant::now() - Duration::from_secs(10);
    let mut last_received = time::Instant::now();
    let mut inflight: FxHashMap<String, time::Instant> = FxHashMap::default();
    loop {
        tokio::select! {
            msg=socket.next()=> {
                match msg {
                    Some(Ok(Message::Close(_)))|None=>return Ok(()),
                    Some(Ok(msg))=>{last_received=time::Instant::now();command(msg,db,network,tx).await?;},
                    Some(Err(e))=>return Err(e.into()),
                }
            }
            _=tick.tick()=> {
                if last_received.elapsed().as_secs()>30 {anyhow::bail!("Server heartbeat timed out");}
                if heartbeat.elapsed().as_secs()>=10 {
                    send(&mut socket, Message::Text(json!({"type":"heartbeat","interface":interface,"xdp_attached":settings.xdp_attached,"simulated":!settings.xdp_attached}).to_string().into())).await?;
                    send(&mut socket, Message::Ping(Vec::new().into())).await?;
                    heartbeat=time::Instant::now();
                }
                let rows=sqlx::query("SELECT id,payload FROM outbound_events WHERE network_id=? ORDER BY id LIMIT 100").bind(network).fetch_all(db).await?;
                for row in rows {
                    send(&mut socket, Message::Text(row.get::<String,_>("payload").into())).await?;
                    sqlx::query("DELETE FROM outbound_events WHERE id=?").bind(row.get::<i64,_>("id")).execute(db).await?;
                }
                inflight.retain(|_,at|at.elapsed().as_secs()<10);
                let rows=sqlx::query_as::<_,ReportForDb>("SELECT * FROM reports WHERE network_id=? ORDER BY id LIMIT 50").bind(network).fetch_all(db).await?;
                for row in rows {
                    if !inflight.contains_key(&row.report_key) {
                        send(&mut socket, Message::Binary(encode(&row).into())).await?;
                        inflight.insert(row.report_key,time::Instant::now());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trust_and_observe_override_automatic_isolation() {
        let mac = [2, 0, 0, 0, 0, 10];
        assert!(!may_isolate(
            &json!({"mode":"observe","trusted_macs":[]}),
            &mac
        ));
        assert!(!may_isolate(
            &json!({"mode":"enforce","trusted_macs":["02:00:00:00:00:0a"]}),
            &mac
        ));
        assert!(may_isolate(
            &json!({"mode":"enforce","trusted_macs":[]}),
            &mac
        ));
        assert!(!may_isolate(&json!({}), &mac));
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use std::process::{Child, Command, Stdio};
    struct Fixture {
        child: Option<Child>,
        dir: std::path::PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    fn start_server(dir: &std::path::Path, port: u16) -> Child {
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/cipher_backend");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("server.log"))
            .unwrap();
        Command::new(binary).env("CIPHER_ENV_FILE",dir.join("no-env")).env("CIPHER_DB",dir.join("server.db"))
            .env("CIPHER_BIND",format!("127.0.0.1:{port}")).env("CIPHER_TLS_CERT",dir.join("cert.pem")).env("CIPHER_TLS_KEY",dir.join("key.pem"))
            .env("JWT_SECRET","isolated-transport-test-secret").env("ROUTER_SECRET","isolated-transport-key")
            .env("LLM_API_KEY","").env("LLM_MODEL","").env_remove("CIPHER_THREAT_INTEL_FILE")
            .stdout(log.try_clone().unwrap()).stderr(log).spawn().expect("Build the server with cargo build --workspace before the transport integration test")
    }
    async fn await_empty(db: &sqlx::SqlitePool, dir: &std::path::Path) {
        for _ in 0..300 {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports")
                .fetch_one(db)
                .await
                .unwrap();
            if count == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "Outbox not acknowledged: {}",
            std::fs::read_to_string(dir.join("server.log")).unwrap_or_default()
        );
    }
    fn totals() -> DeviceTotals {
        DeviceTotals {
            bytes_in: 5000,
            bytes_out: 1000,
            total_connections: 10,
            passed_connections: 10,
            ..Default::default()
        }
    }

    #[tokio::test]
    #[ignore = "requires the built backend and openssl; run cargo test -p daemon transport_reconnects -- --ignored"]
    async fn transport_reconnects_and_replays_durable_outbox() {
        let dir = std::env::temp_dir().join(format!("cipher-transport-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut fixture = Fixture {
            child: None,
            dir: dir.clone(),
        };
        let status = Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout",
            ])
            .arg(dir.join("key.pem"))
            .arg("-out")
            .arg(dir.join("cert.pem"))
            .args([
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let db = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(dir.join("sensor.db"))
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        initialize(&db).await.unwrap();
        let network = "TRANSPORT_TEST";
        let policy = json!({"mode":"enforce","revision":12,"trusted_macs":["02:00:00:00:00:01"]});
        save_policy(&db, network, &policy).await.unwrap();
        assert_eq!(load_policy(&db, network).await, policy);
        remember_block(&db, network, &[2, 0, 0, 0, 0, 1], true)
            .await
            .unwrap();
        store_report(&db, network, [2, 0, 0, 0, 0, 1], totals())
            .await
            .unwrap();
        let settings = ConnectionSettings {
            base_url: format!("wss://localhost:{port}"),
            secret: "isolated-transport-key".into(),
            certificate: Some(dir.join("cert.pem")),
            xdp_attached: false,
        };
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(100);
        let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let task = tokio::spawn(run_with(
            settings,
            db.clone(),
            network.into(),
            "transport-test".into(),
            tx,
            cancel.clone(),
        ));
        // Start with no cloud: the sensor retains its queued report.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reports")
                .fetch_one(&db)
                .await
                .unwrap(),
            1
        );
        fixture.child = Some(start_server(&dir, port));
        await_empty(&db, &dir).await;
        fixture.child.as_mut().unwrap().kill().unwrap();
        fixture.child.as_mut().unwrap().wait().unwrap();
        fixture.child = None;
        store_report(&db, network, [2, 0, 0, 0, 0, 1], totals())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reports")
                .fetch_one(&db)
                .await
                .unwrap(),
            1
        );
        fixture.child = Some(start_server(&dir, port));
        await_empty(&db, &dir).await;
        cancel.cancel();
        task.await.unwrap();
        drain.await.unwrap();
        db.close().await;
        let reopened = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(dir.join("sensor.db")))
            .await
            .unwrap();
        assert_eq!(load_policy(&reopened, network).await, policy);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM local_blocks")
                .fetch_one(&reopened)
                .await
                .unwrap(),
            1
        );
        reopened.close().await;
    }
}
