use axum::{extract::{State, Path, ws::{WebSocketUpgrade, WebSocket , Message}}, http::StatusCode, Json};
use std::collections::HashMap;
use crate::models::*;
use crate::auth::*;
use crate::SharedDatabase;

// can only be used by me 
#[axum::debug_handler]
pub async fn make_network_and_assign_admin(State(db):State<SharedDatabase>, Json(payload): Json<Network>) -> Result<StatusCode, AppError>{
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM networks WHERE network_id = ?", payload.network_id)
        .fetch_optional(&db)
        .await?;
    if existing.is_some() {
        println!("Warning, Network already exists {}",payload.network_id);
        return Err(AppError::Conflict);
    }
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM users WHERE username = ?",payload.username)
        .fetch_optional(&db)
        .await?;
    if existing.is_none() {
        println!("Warning, no such user {}",payload.username);
        return Err(AppError::Conflict);
    }
    sqlx::query!("INSERT INTO networks (network_id, username, is_admin) VALUES (?, ?, ?)", payload.network_id, payload.username, 1)
        .execute(&db)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

#[axum::debug_handler]
pub async fn change_admin_of_network(State(db): State<SharedDatabase>, Json(payload): Json<ChangeAdminRequest>) -> Result<StatusCode, AppError>{
    let old_admin = sqlx::query!("SELECT 1 AS exists_flag FROM networks Where network_id = ? AND username = ? AND is_admin = ?", payload.network_id, payload.old_admin, 1)
        .fetch_optional(&db)
        .await?;
    if old_admin.is_none() {
        return Err(AppError::Conflict);
    }
    verify_user(&db, &payload.old_admin, &payload.old_admin_password).await?;

    let new_admin = sqlx::query!("SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?", payload.network_id, payload.new_admin)
        .fetch_optional(&db)
        .await?;
    if new_admin.is_none(){
        return Err(AppError::Conflict);
    }
    sqlx::query!("UPDATE networks SET is_admin = ? WHERE network_id = ? AND username = ?", 1, payload.network_id, payload.new_admin)
        .execute(&db)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

#[axum::debug_handler]
pub async fn router_ws_handler(ws: WebSocketUpgrade, Path(network_id): Path<String>, State(state): State<AppState>, _key: RouterKey) -> axum::response::Response {
    println!("--> [WS Handshake] Physical Router attempting persistent connection for Network: {}...", network_id);
    ws.on_upgrade(move |socket| handle_router_socket(socket, network_id, state))
}

async fn handle_router_socket(mut socket: WebSocket, network_id: String, state: AppState) {
    println!("🟢 [WS] Physical Router successfully connected for Network: {}", network_id);
    if let Err(e) = socket.send(Message::Text("CIPHER Control Plane: Authorized & Connected".to_string())).await {
        println!("🔴 [WS ERROR] Failed to send welcome handshake: {}", e);
        return; 
    }
    
    // --- PUSH DYNAMIC GLOBAL THREAT INTEL ON CONNECT (FROM RAM CACHE) ---
    let (bad_ips, bad_domains) = {
        let intel = state.threat_intel.read().await;
        (intel.banned_ips.clone(), intel.ad_domains.clone())
    };

    println!("🌍 [THREAT INTEL] Pushing {} IPs and {} Ad Domains to Router from Cache...", bad_ips.len(), bad_domains.len());
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    
    let mut ips_offsets = Vec::new();
    for ip in &bad_ips { ips_offsets.push(builder.create_string(ip)); }
    let ips_vec = builder.create_vector(&ips_offsets);
    
    let mut dom_offsets = Vec::new();
    for dom in &bad_domains { dom_offsets.push(builder.create_string(dom)); }
    let dom_vec = builder.create_vector(&dom_offsets);
    
    let intel_offset = crate::router_generated::ThreatIntelPayload::create(
        &mut builder,
        &crate::router_generated::ThreatIntelPayloadArgs {
            ad_domains: Some(dom_vec),
            banned_ips: Some(ips_vec),
        }
    );
    
    let status_str = builder.create_string("threat_intel");
    let mut res_builder = crate::router_generated::RouterResponseBuilder::new(&mut builder);
    res_builder.add_status(status_str);
    res_builder.add_threat_intel(intel_offset);
    let res = res_builder.finish();
    builder.finish(res, None);
    
    if let Err(e) = socket.send(Message::Binary(builder.finished_data().to_vec())).await {
        println!("🔴 [WS ERROR] Failed to send Threat Intel: {}", e);
        return;
    }

    // 1. Initialize the Layer 1 ML Memory Bank for this specific router
    let mut baselines: HashMap<String, crate::ai::NetworkBaseline> = HashMap::new();
    let mut rx = state.tx.subscribe();
    
    loop {
        tokio::select! {
            Ok(cmd) = rx.recv() => {
                if cmd.network_id == network_id {
                    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
                    let command_msg = format!("command_{}", cmd.state);
                    let status_str = builder.create_string(&command_msg);
                    let mac_str = builder.create_string(&cmd.mac);

                    let mut res_builder = crate::router_generated::RouterResponseBuilder::new(&mut builder);
                    res_builder.add_status(status_str);
                    res_builder.add_mac(mac_str);
                    let res = res_builder.finish();
                    builder.finish(res, None);

                    if let Err(net_err) = socket.send(Message::Binary(builder.finished_data().to_vec())).await {
                        println!("🔴 [WS ERROR] Socket died while sending Kill Command: {}", net_err);
                        break;
                    }
                    println!("⚡ [WS] Pushed real-time execution command to physical router for MAC: {}", cmd.mac);
                }
            }

            Some(msg) = socket.recv() => {
                if let Ok(Message::Binary(bytes)) = msg {
                    match flatbuffers::root::<crate::router_generated::RouterMessage>(&bytes) {                
                        Ok(envelope) => {
                            match envelope.payload_type() {
                                crate::router_generated::IncomingPayload::RegisterRequest => {
                                    if let Some(request) = envelope.payload_as_register_request() {
                                        let req_network_id = request.network_id().unwrap_or_default();
                                        let mac = request.mac().unwrap_or_default();
                                        let hostname = request.hostname().unwrap_or_default();
                                        let ip = request.ip().unwrap_or_default();
                                        let manufacturer = request.manufacturer().unwrap_or_default();

                                        let existing = sqlx::query!("SELECT 1 AS exists_flag FROM devices WHERE mac = ?", mac)
                                            .fetch_optional(&state.db).await.unwrap_or(None);

                                        let status_msg = if existing.is_none() {
                                            if let Err(db_err) = sqlx::query!("INSERT INTO devices (network_id, mac, hostname, ip, manufacturer, state, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                                                req_network_id, mac, hostname, ip, manufacturer, "allowed", "Active Now")
                                                .execute(&state.db).await 
                                            {
                                                println!("🔴 [DB ERROR] Failed to insert new device {}: {}", mac, db_err);
                                                continue;
                                            }
                                            println!("🟢 [WS] Real-Time Device Registered: {}", mac);
                                            "success"
                                        } else {
                                            "conflict"
                                        };

                                        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
                                        let status_str = builder.create_string(status_msg);
                                        let mac_str = builder.create_string(mac);

                                        let mut res_builder = crate::router_generated::RouterResponseBuilder::new(&mut builder);
                                        res_builder.add_status(status_str);
                                        res_builder.add_mac(mac_str);
                                        let res = res_builder.finish();
                                        builder.finish(res, None);

                                        if let Err(net_err) = socket.send(Message::Binary(builder.finished_data().to_vec())).await {
                                            println!("🔴 [WS ERROR] Socket died while sending response: {}", net_err);
                                            break;
                                        }
                                    }
                                },
                                crate::router_generated::IncomingPayload::ChangeStateRequest => {
                                    if let Some(request) = envelope.payload_as_change_state_request() {
                                        let req_network_id = request.network_id().unwrap_or_default();
                                        let mac = request.mac().unwrap_or_default();
                                        let state_str = request.state().unwrap_or_default();

                                        let result = sqlx::query!("UPDATE devices SET state = ? WHERE network_id = ? AND mac = ?", state_str, req_network_id, mac)
                                            .execute(&state.db).await;
                                        let status_msg = match result {
                                            Ok(res) if res.rows_affected() != 0 => {
                                                println!("🟢 [WS] Router updated device {} state to {}", mac, state_str);
                                                "success"
                                            },
                                            _ => {
                                                println!("🔴 [WS DB] Router failed to update device {}", mac);
                                                "not_found"
                                            }
                                        };
                                        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
                                        let status_str = builder.create_string(status_msg);
                                        let mac_str = builder.create_string(mac);

                                        let mut res_builder = crate::router_generated::RouterResponseBuilder::new(&mut builder);
                                        res_builder.add_status(status_str);
                                        res_builder.add_mac(mac_str);
                                        let res = res_builder.finish();
                                        builder.finish(res, None);

                                        if let Err(net_err) = socket.send(Message::Binary(builder.finished_data().to_vec())).await {
                                            println!("🔴 [WS ERROR] Socket died while sending state change response: {}", net_err);
                                            break;
                                        }
                                    }
                                },
                                crate::router_generated::IncomingPayload::TelemetryReport => {
                                    if let Some(telemetry) = envelope.payload_as_telemetry_report() {
                                        let mac = telemetry.mac().unwrap_or_default().to_string();
                                        let network_id_req = telemetry.network_id().unwrap_or_default().to_string();
                                        
                                        let bytes_in = telemetry.bytes_in();
                                        let bytes_out = telemetry.bytes_out();
                                        let drops = telemetry.dropped_connections();
                                        let entropy = telemetry.port_entropy_score();

                                        // 1. Get or create the device's math baseline in Server RAM
                                        let baseline = baselines.entry(mac.clone()).or_insert_with(crate::ai::NetworkBaseline::default);

                                        // 2. LAYER 1: THE REFLEX (Native Rust ML - Microseconds)
                                        let is_anomaly = baseline.process_telemetry(bytes_in, bytes_out, drops, entropy);

                                        if is_anomaly {
                                            // 3. LAYER 2: THE REASON (LLM Supervisor - Asynchronous)
                                            let tx_clone = state.tx.clone();
                                            let db_clone = state.db.clone();
                                            let mac_clone = mac.clone();
                                            let net_id_clone = network_id_req.clone();
                                            
                                            tokio::spawn(async move {
                                                match crate::ai::consult_llm_supervisor(&mac_clone, bytes_in, bytes_out, drops, entropy).await {
                                                    Ok(verdict) => {
                                                        println!("\n🤖 [LLM VERDICT] Threat: {} | Confidence: {}%", verdict.threat_name, verdict.confidence);
                                                        println!("📋 [LLM REPORT] {}", verdict.human_explanation);
                                                        
                                                        // --- 1. SAVE THE REPORT FOR THE FRONTEND (RUNTIME QUERY) ---
                                                        let _ = sqlx::query("INSERT INTO audit_logs (network_id, mac, threat_name, confidence, explanation) VALUES (?, ?, ?, ?, ?)")
                                                            .bind(&net_id_clone)
                                                            .bind(&mac_clone)
                                                            .bind(&verdict.threat_name)
                                                            .bind(verdict.confidence as i64)
                                                            .bind(&verdict.human_explanation)
                                                            .execute(&db_clone).await;
                                                        
                                                        if verdict.should_block {
                                                            println!("🚨 [ACTION] LLM authorized block. Isolating MAC {}...", mac_clone);
                                                            
                                                            // --- 2. SYNC THE SERVER DATABASE (RUNTIME QUERY) ---
                                                            let _ = sqlx::query("UPDATE devices SET state = 'blocked' WHERE network_id = ? AND mac = ?")
                                                                .bind(&net_id_clone)
                                                                .bind(&mac_clone)
                                                                .execute(&db_clone).await;

                                                            // --- 3. EXECUTE THE PHYSICAL KILL ---
                                                            let cmd = DeviceCommand {
                                                                network_id: net_id_clone,
                                                                mac: mac_clone.clone(),
                                                                state: DeviceState::Blocked,
                                                            };
                                                            let _ = tx_clone.send(cmd);
                                                        } else {
                                                            println!("✅ [ACTION] LLM vetoed the Layer 1 block (False Positive Detected).");
                                                        }
                                                    }
                                                    Err(e) => println!("⚠️ [LLM ERROR] Supervisor unreachable: {}", e),
                                                }
                                            });
                                        }
                                    }
                                },
                                _ => {
                                    println!("⚠️ [WS] Unknown Payload Type received!");
                                }
                            }
                        }
                        Err(_) => {
                            println!("⚠️ [SECURITY] Received malformed binary envelope! Rejecting payload.");
                        }
                    };
                } else if let Ok(Message::Close(_)) = msg {
                    println!("🔴 [WS] Router disconnected naturally.");
                    break;
                }
            }
        }
    }
    println!("🔴 [WS] Connection severed for Network {}.", network_id);
}

#[axum::debug_handler]
pub async fn signup_user(State(db): State<SharedDatabase>, Json(payload): Json<User>) -> Result<String, AppError>{
    let hashed_password = password_hasher(&payload.password);
    let result = sqlx::query!("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", payload.username, payload.email, hashed_password)
        .execute(&db)
        .await;
    match result {
        Ok(_) => {
            let jwt =  create_jwt(&payload.username, &payload.email)?;
            return Ok(jwt);
        }
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            return Err(AppError::Conflict);
        }
        Err(e) => {
            return Err(AppError::DatabaseError(e))
        }
    }
}

#[axum::debug_handler]
pub async fn login_user(State(db): State<SharedDatabase>, Json(payload): Json<User>) -> Result<String, AppError>{
    let Some(password) = sqlx::query_scalar!("SELECT password FROM users WHERE username = ? OR email = ?", payload.username, payload.email)
        .fetch_optional(&db)
        .await?
        else {
            return Err(AppError::Unauthorized);
        };
    if verify_password(&payload.password, &password) {
        let jwt =  create_jwt(&payload.username, &payload.email)? ;
        return Ok(jwt);
    }
    Err(AppError::Unauthorized)
}

#[axum::debug_handler]
pub async fn add_network_to_user(State(db): State<SharedDatabase>, claims: Claims, Json(payload): Json<Network>) -> Result<StatusCode, AppError> {
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?", payload.network_id, claims.username)
        .fetch_optional(&db)
        .await?;
    if existing.is_none() {
        return Err(AppError::Conflict);
    }
    let Some(username)= sqlx::query_scalar!("SELECT username FROM networks WHERE network_id = ? AND is_admin = ?", payload.network_id, 1)
        .fetch_optional(&db)
        .await?
    else {
        return Err(AppError::Conflict);
    };
    let _email: String = sqlx::query_scalar!("SELECT email FROM users WHERE username = ?", username)
        .fetch_one(&db)
        .await?;
    return Ok(StatusCode::ACCEPTED);
}

#[axum::debug_handler]
pub async fn get_devices(State(db): State<SharedDatabase>, claims: Claims, Json(network_id): Json<String>) -> Result<Json<Vec<NetworkDevice>>, AppError> {
    println!("--> [GET] /api/devices (Zero-allocation read)");
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?", network_id, claims.username)
        .fetch_optional(&db)
        .await?;
    if existing.is_none() {
        return Err(AppError::Conflict);
    }
    let devices: Vec<NetworkDevice> = sqlx::query_as!(NetworkDevice, "SELECT * FROM devices WHERE network_id = ?", network_id)
        .fetch_all(&db)
        .await?;
    Ok(Json(devices))
}

#[axum::debug_handler]
pub async fn get_single_device(State(db): State<SharedDatabase>, claims: Claims, Json(payload): Json<NormalRequest>) -> Result<Json<NetworkDevice>, AppError> {
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?", payload.network_id, claims.username)
        .fetch_optional(&db)
        .await?;
    if existing.is_none() {
        return Err(AppError::Conflict);
    }
    if let Some(device)= sqlx::query_as!(NetworkDevice, "SELECT * FROM devices WHERE mac = ? AND network_id = ?", payload.mac, payload.network_id)
        .fetch_optional(&db)
        .await? {
        println!("SUCCESS: Device {} is found.", device.hostname);
        return Ok(Json(device));
    }
        println!("Warning, device {} not found", payload.mac);
        Err(AppError::NotFound)
}

#[axum::debug_handler]
pub async fn change_state(State(db): State<SharedDatabase>, claims: Claims, Json(payload): Json<ChangeStateRequest>) -> Result<Json<Vec<NetworkDevice>>, AppError> {
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?", payload.network_id, claims.username)
        .fetch_optional(&db)
        .await?;
    if existing.is_none() {
        return Err(AppError::Conflict);
    }
    let state_str = payload.state.to_string();
    let result = sqlx::query!("UPDATE devices SET state = ?  WHERE network_id = ? AND mac = ?", state_str, payload.network_id, payload.mac)
        .execute(&db)
        .await?;
    if result.rows_affected() != 0 {
        println!("Device {} state changed.", payload.mac);
        let devices: Vec<NetworkDevice> = sqlx::query_as!(NetworkDevice, "SELECT * FROM devices WHERE network_id = ?", payload.network_id)
            .fetch_all(&db)
            .await?;
        return Ok(Json(devices));
    }
    else {
        println!("Warning, device {} not found", payload.mac);
        Err(AppError::NotFound)
    }
}

#[axum::debug_handler]
pub async fn delete_device(State(db): State<SharedDatabase>, claims: Claims, Json(payload): Json<NormalRequest>) -> Result<Json<Vec<NetworkDevice>>, AppError> {
    println!("--> [Delete] /api/devices - Targeting Mac: {}", payload.mac);
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?", payload.network_id, claims.username)
        .fetch_optional(&db)
        .await?;
    if existing.is_none() {
        return Err(AppError::Conflict);
    }
    let result = sqlx::query!("DELETE FROM devices WHERE mac = ? AND network_id = ?", payload.mac, payload.network_id)
        .execute(&db)
        .await?;
    if result.rows_affected() != 0 {
        println!("SUCCESS: Device {} has been deleted", payload.mac);
        let devices: Vec<NetworkDevice> = sqlx::query_as!(NetworkDevice, "SELECT * FROM devices WHERE network_id = ?", payload.network_id)
            .fetch_all(&db)
            .await?;
        return Ok(Json(devices));
    }
    println!("WARNING: Could not find device with MAC: {}", payload.mac);
    Err(AppError::NotFound)
}