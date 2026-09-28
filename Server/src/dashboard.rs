//! Operator API. The browser never receives the router key or impersonates a sensor.
use crate::models::*;
use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};
use sqlx::Row;

pub async fn initialize(db: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    for sql in [
        "CREATE TABLE IF NOT EXISTS telemetry (id INTEGER PRIMARY KEY AUTOINCREMENT, network_id TEXT NOT NULL, mac TEXT NOT NULL, received_at INTEGER NOT NULL, payload TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS telemetry_network_time ON telemetry(network_id, received_at)",
        "CREATE TABLE IF NOT EXISTS device_commands (id INTEGER PRIMARY KEY AUTOINCREMENT, network_id TEXT NOT NULL, mac TEXT NOT NULL, state TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', detail TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS commands_network ON device_commands(network_id, id)",
    ] {
        sqlx::query(sql).execute(db).await?;
    }
    // Remove only the wholly blank placeholder left by the original prototype.
    sqlx::query("DELETE FROM devices WHERE network_id='' AND mac='' AND hostname='' AND ip='' AND manufacturer='' AND state='' AND last_seen=''")
        .execute(db).await?;
    Ok(())
}

pub async fn authorize(
    db: &sqlx::SqlitePool,
    claims: &Claims,
    network: &str,
    admin: bool,
) -> Result<(), AppError> {
    let role: Option<bool> =
        sqlx::query_scalar("SELECT is_admin FROM networks WHERE network_id = ? AND username = ?")
            .bind(network)
            .bind(&claims.username)
            .fetch_optional(db)
            .await?;
    if role.is_none() || (admin && role != Some(true)) {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

pub async fn networks(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<Value>, AppError> {
    let networks = sqlx::query_as::<_, Network>(
        "SELECT * FROM networks WHERE username = ? ORDER BY network_id",
    )
    .bind(&claims.username)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        json!({"username": claims.username, "networks": networks}),
    ))
}

pub async fn snapshot(
    State(state): State<AppState>,
    claims: Claims,
    Path(network): Path<String>,
) -> Result<Json<Value>, AppError> {
    authorize(&state.db, &claims, &network, false).await?;
    let devices = sqlx::query_as::<_, NetworkDevice>(
        "SELECT * FROM devices WHERE network_id = ? ORDER BY last_seen DESC",
    )
    .bind(&network)
    .fetch_all(&state.db)
    .await?;
    let now = chrono::Utc::now().timestamp();
    let rows = sqlx::query("SELECT payload FROM telemetry WHERE network_id = ? AND received_at >= ? ORDER BY id DESC LIMIT 5000")
        .bind(&network).bind(now - 3600).fetch_all(&state.db).await?;
    let telemetry: Vec<Value> = rows
        .iter()
        .rev()
        .filter_map(|r| serde_json::from_str(r.get::<&str, _>("payload")).ok())
        .collect();
    let audit =
        sqlx::query("SELECT * FROM audit_logs WHERE network_id = ? ORDER BY id DESC LIMIT 100")
            .bind(&network)
            .fetch_all(&state.db)
            .await?;
    let incidents: Vec<Value> = audit.iter().map(|r| json!({"id":r.get::<i64,_>("id"),"mac":r.get::<String,_>("mac"),"threat_name":r.get::<String,_>("threat_name"),"confidence":r.get::<i64,_>("confidence"),"explanation":r.get::<String,_>("explanation"),"timestamp":r.get::<Option<String>,_>("timestamp")})).collect();
    let rows = sqlx::query(
        "SELECT * FROM device_commands WHERE network_id = ? ORDER BY id DESC LIMIT 100",
    )
    .bind(&network)
    .fetch_all(&state.db)
    .await?;
    let commands: Vec<Value> = rows.iter().map(|r| json!({"id":r.get::<i64,_>("id"),"mac":r.get::<String,_>("mac"),"state":r.get::<String,_>("state"),"status":r.get::<String,_>("status"),"detail":r.get::<String,_>("detail"),"created_at":r.get::<i64,_>("created_at")})).collect();
    let sensor = state.sensors.read().await.get(&network).cloned();
    let online = sensor.as_ref().is_some_and(|s| now - s.last_heartbeat < 25);
    Ok(Json(
        json!({"network_id": network, "server_time": now, "sensor_online": online, "sensor":sensor,
        "llm_configured":std::env::var("LLM_API_KEY").is_ok_and(|k| !k.is_empty()), "devices":devices,
        "telemetry":telemetry,"telemetry_limit":5000,"incidents":incidents,"commands":commands,
        "threat_intel":*state.threat_intel.read().await}),
    ))
}

pub async fn command(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<ChangeStateRequest>,
) -> Result<Json<Value>, AppError> {
    authorize(&state.db, &claims, &payload.network_id, true).await?;
    if payload.state == DeviceState::Suspicious {
        return Err(AppError::Conflict);
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE network_id = ? AND mac = ?)")
            .bind(&payload.network_id)
            .bind(&payload.mac)
            .fetch_one(&state.db)
            .await?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let mut tx = state.db.begin().await?;
    // A newer desired state supersedes any unsatisfied request for this device.
    sqlx::query("UPDATE device_commands SET status = 'superseded' WHERE network_id = ? AND mac = ? AND status IN ('pending','sent')")
        .bind(&payload.network_id).bind(&payload.mac).execute(&mut *tx).await?;
    let id = sqlx::query(
        "INSERT INTO device_commands (network_id,mac,state,created_at) VALUES (?,?,?,?)",
    )
    .bind(&payload.network_id)
    .bind(&payload.mac)
    .bind(payload.state.to_string())
    .bind(chrono::Utc::now().timestamp())
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();
    tx.commit().await?;
    Ok(Json(json!({"id":id,"status":"pending"})))
}

pub async fn record_telemetry(
    state: &AppState,
    network: &str,
    t: &crate::router_generated::TelemetryReport<'_>,
    learning: usize,
    anomaly: bool,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let mac = t.mac().unwrap_or_default();
    let payload = json!({"mac":mac,"received_at":now,"bytes_in":t.bytes_in(),"bytes_out":t.bytes_out(),
        "total_connections":t.total_connections(),"passed_connections":t.passed_connections(),"dropped_connections":t.dropped_connections(),
        "anomaly_flags_count":t.anomaly_flags_count(),"heuristic_flags_count":t.heuristic_flags_count(),"infra_alert_count":t.infra_alert_count(),
        "unique_external_ips":t.unique_external_ips(),"port_entropy_score":t.port_entropy_score(),"baseline_samples":learning,"is_anomaly":anomaly});
    let mut tx = state.db.begin().await?;
    // The current daemon sends telemetry without a separate registration message.
    sqlx::query("INSERT INTO devices (network_id,mac,hostname,ip,manufacturer,state,last_seen) VALUES (?,?,'','','','allowed',?) ON CONFLICT(network_id,mac) DO UPDATE SET last_seen=excluded.last_seen")
        .bind(network).bind(mac).bind(chrono::Utc::now().to_rfc3339()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO telemetry (network_id,mac,received_at,payload) VALUES (?,?,?,?)")
        .bind(network)
        .bind(mac)
        .bind(now)
        .bind(payload.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM telemetry WHERE received_at < ?")
        .bind(now - 86400)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
