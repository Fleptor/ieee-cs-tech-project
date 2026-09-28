use crate::{ai::NetworkBaseline, models::*, router_generated::*};
use axum::extract::ws::{Message, WebSocket};
use serde_json::{Value, json};
use sqlx::Row;
use std::collections::HashMap;

pub async fn handle(mut socket: WebSocket, network: String, state: AppState) {
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
    let mut baselines: HashMap<String, NetworkBaseline> = HashMap::new();
    let mut commands = state.tx.subscribe();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut last_message = std::time::Instant::now();
    if socket.send(Message::Binary(intel_bytes)).await.is_ok() {
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if last_message.elapsed().as_secs() > 30 { break; }
                    let rows = sqlx::query("SELECT id,mac,state FROM device_commands WHERE network_id=? AND status='pending' ORDER BY id LIMIT 50")
                        .bind(&network).fetch_all(&state.db).await.unwrap_or_default();
                    let mut disconnected = false;
                    for r in rows {
                        let id: i64 = r.get("id");
                        let command = json!({"type":"device_command","id":id,"mac":r.get::<String,_>("mac"),"state":r.get::<String,_>("state")});
                        if socket.send(Message::Text(command.to_string())).await.is_err() { disconnected = true; break; }
                        let _ = sqlx::query("UPDATE device_commands SET status='sent' WHERE id=? AND status='pending'").bind(id).execute(&state.db).await;
                    }
                    if disconnected { break; }
                }
                Ok(cmd) = commands.recv() => {
                    if cmd.network_id == network {
                        let _ = sqlx::query("INSERT INTO device_commands (network_id,mac,state,created_at) VALUES (?,?,?,?)")
                            .bind(&network).bind(cmd.mac).bind(cmd.state.to_string()).bind(chrono::Utc::now().timestamp()).execute(&state.db).await;
                    }
                }
                msg = socket.recv() => {
                    let Some(Ok(msg)) = msg else { break };
                    last_message = std::time::Instant::now();
                    match msg {
                        Message::Close(_) => break,
                        Message::Text(text) => {
                            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                                match v["type"].as_str() {
                                    Some("heartbeat") => {
                                        state.sensors.write().await.insert(network.clone(), SensorStatus {
                                            last_heartbeat: chrono::Utc::now().timestamp(),
                                            interface: v["interface"].as_str().unwrap_or("").to_string(),
                                            xdp_attached: v["xdp_attached"].as_bool().unwrap_or(false),
                                        });
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
                                    let baseline = baselines.entry(mac.into()).or_default();
                                    let anomaly = baseline.process_telemetry(t.bytes_in(),t.bytes_out(),t.dropped_connections(),t.port_entropy_score());
                                    let samples = if baseline.means.is_some() {50} else {baseline.training_buffer.len()};
                                    if let Err(e) = crate::dashboard::record_telemetry(&state,&network,&t,samples,anomaly).await { eprintln!("Telemetry storage: {e}"); }
                                    if anomaly {
                                        let state = state.clone(); let network = network.clone(); let mac = mac.to_string();
                                        let metrics = (t.bytes_in(),t.bytes_out(),t.dropped_connections(),t.port_entropy_score());
                                        tokio::spawn(async move {
                                            let result = crate::ai::consult_llm_supervisor(&mac,metrics.0,metrics.1,metrics.2,metrics.3).await;
                                            let (name,confidence,explanation,block) = match result {
                                                Ok(v) => (v.threat_name, i64::from(v.confidence),v.human_explanation,v.should_block),
                                                Err(_) => ("Statistical anomaly".into(),0,"The statistical baseline flagged unusual activity. Supervisor review is unavailable; review this device manually.".into(),false)
                                            };
                                            let _ = sqlx::query("INSERT INTO audit_logs (network_id,mac,threat_name,confidence,explanation) VALUES (?,?,?,?,?)")
                                                .bind(&network).bind(&mac).bind(name).bind(confidence).bind(explanation).execute(&state.db).await;
                                            if block {
                                                let _ = state.tx.send(DeviceCommand {network_id:network, mac,state:crate::models::DeviceState::Blocked});
                                            }
                                        });
                                    }
                                } else if let Some(r) = envelope.payload_as_register_request() {
                                    if r.network_id() != Some(network.as_str()) || !valid_mac(r.mac().unwrap_or_default()) { continue; }
                                    let _ = sqlx::query("INSERT INTO devices (network_id,mac,hostname,ip,manufacturer,state,last_seen) VALUES (?,?,?,?,?,'allowed',?) ON CONFLICT(network_id,mac) DO UPDATE SET hostname=excluded.hostname,ip=excluded.ip,manufacturer=excluded.manufacturer,last_seen=excluded.last_seen")
                                        .bind(&network).bind(r.mac()).bind(r.hostname().unwrap_or_default()).bind(r.ip().unwrap_or_default()).bind(r.manufacturer().unwrap_or_default()).bind(chrono::Utc::now().to_rfc3339()).execute(&state.db).await;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    state.sensors.write().await.remove(&network);
    eprintln!("Sensor disconnected: {network}");
}

fn valid_mac(mac: &str) -> bool {
    let parts: Vec<_> = mac.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
}
