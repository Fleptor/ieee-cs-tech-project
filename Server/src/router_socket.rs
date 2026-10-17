use crate::{ai::NetworkBaseline, models::*, router_generated::*};
use axum::extract::ws::{Message, WebSocket};
use serde_json::{Value, json};
use sqlx::Row;

static NEXT_CONNECTION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub async fn handle(mut socket: WebSocket, network: String, state: AppState) {
    let connection_id = NEXT_CONNECTION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    {
        let mut sensors = state.sensors.write().await;
        if sensors
            .get(&network)
            .is_some_and(|s| chrono::Utc::now().timestamp() - s.last_heartbeat < 25)
        {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
        sensors.insert(
            network.clone(),
            SensorStatus {
                last_heartbeat: chrono::Utc::now().timestamp(),
                interface: String::new(),
                xdp_attached: false,
                simulated: false,
                policy_revision: -1,
                connection_id,
            },
        );
    }
    // Replay unacknowledged actions; reapply confirmed blocks after daemon map recreation.
    let _ = sqlx::query(
        "UPDATE device_commands SET status='pending' WHERE network_id=? AND status='sent'",
    )
    .bind(&network)
    .execute(&state.db)
    .await;
    let _ = sqlx::query("INSERT INTO device_commands (network_id,mac,state,created_at) SELECT network_id,mac,state,? FROM devices d WHERE network_id=? AND state='blocked' AND NOT EXISTS(SELECT 1 FROM device_commands c WHERE c.network_id=d.network_id AND c.mac=d.mac AND c.status='pending')")
        .bind(chrono::Utc::now().timestamp()).bind(&network).execute(&state.db).await;
    let intel_bytes = {
        let intel = state.threat_intel.read().await;
        let mut b = flatbuffers::FlatBufferBuilder::new();
        let ips: Vec<_> = intel
            .banned_ips
            .iter()
            .map(|s| b.create_string(s))
            .collect();
        let domains: Vec<_> = intel
            .ad_domains
            .iter()
            .map(|s| b.create_string(s))
            .collect();
        let ips = b.create_vector(&ips);
        let domains = b.create_vector(&domains);
        let intel = ThreatIntelPayload::create(
            &mut b,
            &ThreatIntelPayloadArgs {
                banned_ips: Some(ips),
                ad_domains: Some(domains),
            },
        );
        let status = b.create_string("threat_intel");
        let response = RouterResponse::create(
            &mut b,
            &RouterResponseArgs {
                status: Some(status),
                mac: None,
                threat_intel: Some(intel),
            },
        );
        b.finish(response, None);
        b.finished_data().to_vec()
    };
    let mut policy_sent = (-1_i64, std::time::Instant::now());
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut last_message = std::time::Instant::now();
    if socket.send(Message::Binary(intel_bytes)).await.is_ok() {
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if last_message.elapsed().as_secs() > 30 { break; }
                    if state.sensors.read().await.get(&network).is_none_or(|s|s.connection_id!=connection_id) {break;}
                    let _=sqlx::query("UPDATE device_commands SET status='superseded',detail='Automatic request expired' WHERE network_id=? AND automatic=1 AND status IN ('pending','sent') AND created_at<?")
                        .bind(&network).bind(chrono::Utc::now().timestamp()-60).execute(&state.db).await;
                    let Ok(policy) = crate::policy::wire_policy(&state.db,&network).await else { continue; };
                    let revision=policy["revision"].as_i64().unwrap_or(0);
                    let acked=state.sensors.read().await.get(&network).map(|s|s.policy_revision).unwrap_or(-1);
                    if policy_sent.0!=revision || (acked!=revision && policy_sent.1.elapsed().as_secs()>=5) {
                        if socket.send(Message::Text(policy.to_string())).await.is_err() { break; }
                        policy_sent=(revision,std::time::Instant::now());
                    }
                    let now=chrono::Utc::now().timestamp();
                    let _=sqlx::query("UPDATE device_commands SET status=CASE WHEN attempts>=3 THEN 'failed' ELSE 'pending' END,detail='Sensor acknowledgment timed out' WHERE network_id=? AND status='sent' AND sent_at<?")
                        .bind(&network).bind(now-10).execute(&state.db).await;
                    let rows = sqlx::query("SELECT id,mac,state,automatic FROM device_commands WHERE network_id=? AND status='pending' ORDER BY id LIMIT 50")
                        .bind(&network).fetch_all(&state.db).await.unwrap_or_default();
                    let mut disconnected = false;
                    for r in rows {
                        let id: i64 = r.get("id");
                        let command = json!({"type":"device_command","id":id,"mac":r.get::<String,_>("mac"),"state":r.get::<String,_>("state"),"automatic":r.get::<bool,_>("automatic"),"policy_revision":revision});
                        if socket.send(Message::Text(command.to_string())).await.is_err() { disconnected = true; break; }
                        let _ = sqlx::query("UPDATE device_commands SET status='sent',attempts=attempts+1,sent_at=? WHERE id=? AND status='pending'").bind(now).bind(id).execute(&state.db).await;
                    }
                    if disconnected { break; }
                }
                msg = socket.recv() => {
                    let Some(Ok(msg)) = msg else { break };
                    if state.sensors.read().await.get(&network).is_none_or(|s|s.connection_id!=connection_id) {break;}
                    last_message = std::time::Instant::now();
                    match msg {
                        Message::Close(_) => break,
                        Message::Text(text) => {
                            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                                match v["type"].as_str() {
                                    Some("heartbeat") => {
                                        let revision=state.sensors.read().await.get(&network).map(|s|s.policy_revision).unwrap_or(-1);
                                        state.sensors.write().await.insert(network.clone(), SensorStatus {
                                            last_heartbeat: chrono::Utc::now().timestamp(),
                                            interface: v["interface"].as_str().unwrap_or("").to_string(),
                                            xdp_attached: v["xdp_attached"].as_bool().unwrap_or(false),
                                            simulated: v["simulated"].as_bool().unwrap_or(false),
                                            policy_revision: revision,
                                            connection_id,
                                        });
                                    }
                                    Some("policy_ack") => {
                                        if v["applied"].as_bool()==Some(true) {
                                            if let Some(sensor)=state.sensors.write().await.get_mut(&network) {
                                                sensor.policy_revision=v["revision"].as_i64().unwrap_or(-1);
                                            }
                                        }
                                    }
                                    Some("edge_alert") => {
                                        if let Some(mac)=v["mac"].as_str().and_then(crate::policy::normalize_mac) {
                                            let now=chrono::Utc::now().timestamp();
                                            let recent: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_logs WHERE network_id=? AND mac=? AND threat_name='Edge heuristic alert' AND timestamp>datetime(?,'unixepoch'))")
                                                .bind(&network).bind(&mac).bind(now-120).fetch_one(&state.db).await.unwrap_or(true);
                                            if !recent { let _=sqlx::query("INSERT INTO audit_logs(network_id,mac,threat_name,confidence,explanation,action) VALUES (?,?,'Edge heuristic alert',0,?,?)")
                                                .bind(&network).bind(&mac).bind(v["reason"].as_str().unwrap_or("Local heuristic flagged activity"))
                                                .bind(v["action"].as_str().unwrap_or("alert_only")).execute(&state.db).await; }
                                        }
                                    }
                                    Some("edge_action") => {
                                        let mac = v["mac"].as_str().unwrap_or("");
                                        if valid_mac(mac) && v["state"] == "blocked" {
                                            let _ = sqlx::query("INSERT INTO devices (network_id,mac,hostname,ip,manufacturer,state,last_seen) VALUES (?,?,'','','','blocked',?) ON CONFLICT(network_id,mac) DO UPDATE SET state='blocked'")
                                                .bind(&network).bind(mac).bind(chrono::Utc::now().to_rfc3339()).execute(&state.db).await;
                                            let _ = sqlx::query("INSERT INTO audit_logs (network_id,mac,threat_name,confidence,explanation) VALUES (?,?,'Edge isolation',0,?)")
                                                .bind(&network).bind(mac).bind(v["reason"].as_str().unwrap_or("Local heuristic applied a MAC block")).execute(&state.db).await;
                                        }
                                    }
                                    Some("command_ack") => {
                                        if let Some(id) = v["id"].as_i64() {
                                            let applied = v["applied"].as_bool().unwrap_or(false);
                                            let detail = v["detail"].as_str().unwrap_or("");
                                            if let Ok(mut tx) = state.db.begin().await {
                                                if applied {
                                                    let _ = sqlx::query("UPDATE devices SET state=(SELECT state FROM device_commands WHERE id=?) WHERE network_id=? AND mac=(SELECT mac FROM device_commands WHERE id=? AND network_id=? AND status IN ('pending','sent'))")
                                                        .bind(id).bind(&network).bind(id).bind(&network).execute(&mut *tx).await;
                                                }
                                                let _ = sqlx::query("UPDATE device_commands SET status=?,detail=? WHERE id=? AND network_id=? AND status IN ('pending','sent')")
                                                    .bind(if applied {"applied"} else {"failed"}).bind(detail).bind(id).bind(&network).execute(&mut *tx).await;
                                                let _ = tx.commit().await;
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Message::Binary(bytes) => {
                            if let Ok(envelope) = flatbuffers::root::<RouterMessage>(&bytes) {
                                if let Some(t) = envelope.payload_as_telemetry_report() {
                                    if t.network_id() != Some(network.as_str()) { continue; }
                                    let mac = t.mac().unwrap_or_default();
                                    if !valid_mac(mac) || !t.port_entropy_score().is_finite() { continue; }
                                    let report_id=t.report_id().filter(|id|!id.is_empty() && id.len()<=100);
                                    let duplicate=if let Some(id)=report_id {
                                        sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM telemetry_receipts WHERE network_id=? AND report_id=?)").bind(&network).bind(id).fetch_one(&state.db).await.unwrap_or(false)
                                    }else{false};
                                    let result=if duplicate {Ok(())}else{analyze(&state,&network,&t).await};
                                    match result {
                                        Ok(())=>if let Some(id)=report_id {
                                            let saved=sqlx::query("INSERT OR IGNORE INTO telemetry_receipts VALUES (?,?,?)").bind(&network).bind(id).bind(chrono::Utc::now().timestamp()).execute(&state.db).await;
                                            if saved.is_ok() {let _=socket.send(Message::Text(json!({"type":"telemetry_ack","report_id":id}).to_string())).await;}
                                        },
                                        Err(e)=>eprintln!("Telemetry analysis failed: {e}"),
                                    }
                                } else if let Some(r) = envelope.payload_as_register_request() {
                                    if r.network_id() != Some(network.as_str()) || !valid_mac(r.mac().unwrap_or_default()) { continue; }
                                    let _ = sqlx::query("INSERT INTO devices (network_id,mac,hostname,ip,manufacturer,state,last_seen) VALUES (?,?,?,?,?,'allowed',?) ON CONFLICT(network_id,mac) DO UPDATE SET hostname=excluded.hostname,ip=excluded.ip,manufacturer=excluded.manufacturer,last_seen=excluded.last_seen")
                                        .bind(&network).bind(r.mac().unwrap_or_default().to_uppercase()).bind(r.hostname().unwrap_or_default()).bind(r.ip().unwrap_or_default()).bind(r.manufacturer().unwrap_or_default()).bind(chrono::Utc::now().to_rfc3339()).execute(&state.db).await;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    let mut sensors = state.sensors.write().await;
    if sensors
        .get(&network)
        .is_some_and(|s| s.connection_id == connection_id)
    {
        sensors.remove(&network);
    }
    eprintln!("Sensor disconnected: {network}");
}

fn valid_mac(mac: &str) -> bool {
    let parts: Vec<_> = mac.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
}

async fn analyze(state: &AppState, network: &str, t: &TelemetryReport<'_>) -> anyhow::Result<()> {
    let guard = state.mutation.lock().await;
    let now = chrono::Utc::now().timestamp();
    if t.captured_at() > 0 && (now - t.captured_at() > 60 || t.captured_at() > now + 30) {
        crate::dashboard::record_telemetry(state, network, t, 0, false).await?;
        return Ok(());
    }
    let mac = t.mac().unwrap_or_default().to_uppercase();
    let saved: Option<String> =
        sqlx::query_scalar("SELECT data FROM baselines WHERE network_id=? AND mac=?")
            .bind(network)
            .bind(&mac)
            .fetch_optional(&state.db)
            .await?;
    let mut baseline: NetworkBaseline = saved
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .unwrap_or_default();
    let evidence = baseline.observe([
        t.bytes_in() as f64,
        t.bytes_out() as f64,
        t.dropped_connections() as f64,
        t.port_entropy_score() as f64,
    ]);
    crate::dashboard::record_telemetry(state, network, t, baseline.samples(), evidence.is_some())
        .await?;
    sqlx::query("INSERT INTO baselines(network_id,mac,data) VALUES (?,?,?) ON CONFLICT(network_id,mac) DO UPDATE SET data=excluded.data")
        .bind(network).bind(&mac).bind(serde_json::to_string(&baseline)?).execute(&state.db).await?;
    let Some(evidence) = evidence else {
        return Ok(());
    };
    let now = chrono::Utc::now().timestamp();
    let last: Option<i64> =
        sqlx::query_scalar("SELECT last_alert FROM alert_cooldowns WHERE network_id=? AND mac=?")
            .bind(network)
            .bind(&mac)
            .fetch_optional(&state.db)
            .await?;
    if last.is_some_and(|at| now - at < state.supervisor.cooldown) {
        return Ok(());
    }
    sqlx::query("INSERT INTO alert_cooldowns VALUES (?,?,?) ON CONFLICT(network_id,mac) DO UPDATE SET last_alert=excluded.last_alert")
        .bind(network).bind(&mac).bind(now).execute(&state.db).await?;
    let policy = crate::policy::wire_policy(&state.db, network).await?;
    let revision = policy["revision"].as_i64().unwrap_or(0);
    let history: Vec<String> = sqlx::query_scalar(
        "SELECT payload FROM telemetry WHERE network_id=? AND mac=? ORDER BY id DESC LIMIT 6",
    )
    .bind(network)
    .bind(&mac)
    .fetch_all(&state.db)
    .await?;
    let history: Vec<Value> = history
        .iter()
        .filter_map(|s| serde_json::from_str::<Value>(s).ok())
        .map(|mut v| {
            v.as_object_mut().unwrap().remove("mac");
            v
        })
        .collect();
    let context = json!({"measurements":evidence,"recent_reports":history,"semantics":"Sampled packet events and payload bytes in reporting windows; single-interface attribution may be incomplete."});
    let id=sqlx::query("INSERT INTO audit_logs(network_id,mac,threat_name,confidence,explanation,review_status,evidence) VALUES (?,?,'Statistical anomaly',0,?,'pending',?)")
        .bind(network).bind(&mac).bind(evidence.reasons.join("; ")).bind(context.to_string()).execute(&state.db).await?.last_insert_rowid();
    let permit = if state.supervisor.configured() {
        state.supervisor.slots.clone().try_acquire_owned().ok()
    } else {
        None
    };
    if permit.is_none() {
        let status = if state.supervisor.configured() {
            "busy"
        } else {
            "unavailable"
        };
        sqlx::query("UPDATE audit_logs SET review_status=? WHERE id=?")
            .bind(status)
            .bind(id)
            .execute(&state.db)
            .await?;
        return Ok(());
    }
    drop(guard);
    let state = state.clone();
    let network = network.to_owned();
    tokio::spawn(async move {
        let _permit = permit;
        let result = state.supervisor.review(&context).await;
        let _guard = state.mutation.lock().await;
        if let Err(error) = finish_review(
            &state,
            &network,
            &mac,
            id,
            revision,
            evidence.reasons.len(),
            result,
        )
        .await
        {
            eprintln!("Persist supervisor review: {error}");
        }
    });
    Ok(())
}

async fn finish_review(
    state: &AppState,
    network: &str,
    mac: &str,
    id: i64,
    revision: i64,
    signals: usize,
    result: anyhow::Result<crate::ai::LlmVerdict>,
) -> anyhow::Result<()> {
    match result {
        Err(error) => {
            sqlx::query("UPDATE audit_logs SET review_status='failed',explanation=explanation || ? WHERE id=?")
                .bind(format!(". Supervisor unavailable: {error}. Review manually.")).bind(id).execute(&state.db).await?;
        }
        Ok(v) => {
            let policy = crate::policy::wire_policy(&state.db, network).await?;
            let trusted: bool =
                sqlx::query_scalar("SELECT trusted FROM devices WHERE network_id=? AND mac=?")
                    .bind(network)
                    .bind(mac)
                    .fetch_one(&state.db)
                    .await?;
            let disposition: String =
                sqlx::query_scalar("SELECT disposition FROM audit_logs WHERE id=?")
                    .bind(id)
                    .fetch_one(&state.db)
                    .await?;
            let action = if trusted {
                "trusted_device"
            } else if disposition != "open" || policy["revision"].as_i64() != Some(revision) {
                "superseded"
            } else if policy["mode"] != "enforce" {
                "observe_only"
            } else if !v.should_block {
                "review_only"
            } else if v.confidence < 85 || signals < 2 {
                "insufficient_evidence"
            } else {
                "isolation_requested"
            };
            if action == "isolation_requested" {
                crate::policy::queue(&state.db, network, mac, "blocked", true).await?;
            }
            sqlx::query("UPDATE audit_logs SET threat_name=?,confidence=?,explanation=?,review_status='complete',action=? WHERE id=?")
                .bind(v.threat_name).bind(i64::from(v.confidence)).bind(v.human_explanation).bind(action).bind(id).execute(&state.db).await?;
        }
    }
    Ok(())
}
