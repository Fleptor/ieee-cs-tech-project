use crate::models::*;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;

pub fn normalize_mac(mac: &str) -> Option<String> {
    let parts: Vec<_> = mac.split(':').collect();
    (parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok()))
    .then(|| mac.to_uppercase())
}

pub async fn initialize(db: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    for (table, column, definition) in [
        ("devices", "trusted", "INTEGER NOT NULL DEFAULT 0"),
        ("device_commands", "automatic", "INTEGER NOT NULL DEFAULT 0"),
        ("device_commands", "attempts", "INTEGER NOT NULL DEFAULT 0"),
        ("device_commands", "sent_at", "INTEGER NOT NULL DEFAULT 0"),
        (
            "audit_logs",
            "review_status",
            "TEXT NOT NULL DEFAULT 'not_requested'",
        ),
        ("audit_logs", "disposition", "TEXT NOT NULL DEFAULT 'open'"),
        ("audit_logs", "action", "TEXT NOT NULL DEFAULT 'alert_only'"),
        ("audit_logs", "evidence", "TEXT NOT NULL DEFAULT '{}'"),
        ("audit_logs", "note", "TEXT NOT NULL DEFAULT ''"),
    ] {
        let exists = sqlx::query(&format!("PRAGMA table_info({table})"))
            .fetch_all(db)
            .await?
            .iter()
            .any(|r| r.get::<String, _>("name") == column);
        if !exists {
            sqlx::query(&format!(
                "ALTER TABLE {table} ADD COLUMN {column} {definition}"
            ))
            .execute(db)
            .await?;
        }
    }
    for sql in [
        "CREATE TABLE IF NOT EXISTS telemetry_receipts(network_id TEXT NOT NULL,report_id TEXT NOT NULL,received_at INTEGER NOT NULL,PRIMARY KEY(network_id,report_id))",
        "CREATE INDEX IF NOT EXISTS receipts_time ON telemetry_receipts(received_at)",
        "CREATE TABLE IF NOT EXISTS network_policy (network_id TEXT PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'observe', revision INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS baselines (network_id TEXT NOT NULL, mac TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(network_id,mac))",
        "CREATE TABLE IF NOT EXISTS alert_cooldowns (network_id TEXT NOT NULL, mac TEXT NOT NULL, last_alert INTEGER NOT NULL, PRIMARY KEY(network_id,mac))",
        "CREATE TABLE IF NOT EXISTS operator_audit (id INTEGER PRIMARY KEY,network_id TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL,created_at INTEGER NOT NULL)",
    ] {
        sqlx::query(sql).execute(db).await?;
    }
    sqlx::query("UPDATE audit_logs SET review_status='interrupted',action='alert_only' WHERE review_status='pending'").execute(db).await?;
    // Preserve existing rows; canonicalize only when there is no conflicting device identity.
    sqlx::query("UPDATE OR IGNORE devices SET mac=upper(mac)")
        .execute(db)
        .await?;
    Ok(())
}

pub async fn wire_policy(db: &sqlx::SqlitePool, network: &str) -> Result<Value, sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO network_policy(network_id) VALUES (?)")
        .bind(network)
        .execute(db)
        .await?;
    let row = sqlx::query("SELECT mode,revision FROM network_policy WHERE network_id=?")
        .bind(network)
        .fetch_one(db)
        .await?;
    let trusted: Vec<String> =
        sqlx::query_scalar("SELECT mac FROM devices WHERE network_id=? AND trusted=1 ORDER BY mac")
            .bind(network)
            .fetch_all(db)
            .await?;
    Ok(
        json!({"type":"policy","revision":row.get::<i64,_>("revision"),"mode":row.get::<String,_>("mode"),"trusted_macs":trusted}),
    )
}

pub(crate) async fn audit(
    db: &sqlx::SqlitePool,
    network: &str,
    actor: &str,
    action: &str,
    detail: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO operator_audit(network_id,actor,action,detail,created_at) VALUES (?,?,?,?,?)",
    )
    .bind(network)
    .bind(actor)
    .bind(action)
    .bind(detail)
    .bind(chrono::Utc::now().timestamp())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn queue(
    db: &sqlx::SqlitePool,
    network: &str,
    mac: &str,
    desired: &str,
    automatic: bool,
) -> Result<i64, sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE device_commands SET status='superseded' WHERE network_id=? AND mac=? AND status IN ('pending','sent')")
        .bind(network).bind(mac).execute(&mut *tx).await?;
    let id = sqlx::query(
        "INSERT INTO device_commands(network_id,mac,state,automatic,created_at) VALUES (?,?,?,?,?)",
    )
    .bind(network)
    .bind(mac)
    .bind(desired)
    .bind(automatic)
    .bind(chrono::Utc::now().timestamp())
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();
    tx.commit().await?;
    Ok(id)
}

async fn require_device(state: &AppState, network: &str, mac: &str) -> Result<(), AppError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE network_id=? AND mac=?)")
            .bind(network)
            .bind(mac)
            .fetch_one(&state.db)
            .await?;
    if !exists {
        return Err(AppError::NotFound);
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct TrustRequest {
    network_id: String,
    mac: String,
    trusted: bool,
}
pub async fn trust(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<TrustRequest>,
) -> Result<Json<Value>, AppError> {
    crate::dashboard::authorize(&state.db, &claims, &payload.network_id, true).await?;
    let mac = normalize_mac(&payload.mac).ok_or(AppError::Conflict)?;
    let _guard = state.mutation.lock().await;
    require_device(&state, &payload.network_id, &mac).await?;
    wire_policy(&state.db, &payload.network_id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE devices SET trusted=? WHERE network_id=? AND mac=?")
        .bind(payload.trusted)
        .bind(&payload.network_id)
        .bind(&mac)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE network_policy SET revision=revision+1 WHERE network_id=?")
        .bind(&payload.network_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE device_commands SET status='superseded' WHERE network_id=? AND mac=? AND automatic=1 AND status IN ('pending','sent')")
        .bind(&payload.network_id).bind(&mac).execute(&mut *tx).await?;
    tx.commit().await?;
    let command_id = if payload.trusted {
        Some(queue(&state.db, &payload.network_id, &mac, "allowed", false).await?)
    } else {
        None
    };
    audit(
        &state.db,
        &payload.network_id,
        &claims.username,
        if payload.trusted {
            "trust_and_restore"
        } else {
            "revoke_trust"
        },
        &mac,
    )
    .await?;
    Ok(Json(
        json!({"trusted":payload.trusted,"command_id":command_id,"policy":wire_policy(&state.db,&payload.network_id).await?}),
    ))
}

#[derive(Deserialize)]
pub struct PolicyRequest {
    pub network_id: String,
    pub mode: String,
}
pub async fn set_policy(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<PolicyRequest>,
) -> Result<Json<Value>, AppError> {
    crate::dashboard::authorize(&state.db, &claims, &payload.network_id, true).await?;
    if !matches!(payload.mode.as_str(), "observe" | "enforce") {
        return Err(AppError::Conflict);
    }
    let _guard = state.mutation.lock().await;
    wire_policy(&state.db, &payload.network_id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE network_policy SET mode=?,revision=revision+1 WHERE network_id=?")
        .bind(&payload.mode)
        .bind(&payload.network_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE device_commands SET status='superseded' WHERE network_id=? AND automatic=1 AND status IN ('pending','sent')")
        .bind(&payload.network_id).execute(&mut *tx).await?;
    tx.commit().await?;
    audit(
        &state.db,
        &payload.network_id,
        &claims.username,
        "response_mode",
        &payload.mode,
    )
    .await?;
    Ok(Json(wire_policy(&state.db, &payload.network_id).await?))
}

pub async fn reset_baseline(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<NormalRequest>,
) -> Result<Json<Value>, AppError> {
    crate::dashboard::authorize(&state.db, &claims, &payload.network_id, true).await?;
    let mac = normalize_mac(&payload.mac).ok_or(AppError::Conflict)?;
    let _guard = state.mutation.lock().await;
    require_device(&state, &payload.network_id, &mac).await?;
    wire_policy(&state.db, &payload.network_id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM baselines WHERE network_id=? AND mac=?")
        .bind(&payload.network_id)
        .bind(&mac)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM alert_cooldowns WHERE network_id=? AND mac=?")
        .bind(&payload.network_id)
        .bind(&mac)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE network_policy SET revision=revision+1 WHERE network_id=?")
        .bind(&payload.network_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit(
        &state.db,
        &payload.network_id,
        &claims.username,
        "reset_baseline",
        &mac,
    )
    .await?;
    Ok(Json(json!({"status":"learning","samples":0})))
}

#[derive(Deserialize)]
pub struct ReviewRequest {
    network_id: String,
    id: i64,
    disposition: String,
    #[serde(default)]
    note: String,
}
pub async fn review_incident(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<ReviewRequest>,
) -> Result<Json<Value>, AppError> {
    crate::dashboard::authorize(&state.db, &claims, &payload.network_id, true).await?;
    if !matches!(
        payload.disposition.as_str(),
        "open" | "resolved" | "false_positive"
    ) || payload.note.len() > 2000
    {
        return Err(AppError::Conflict);
    }
    let _guard = state.mutation.lock().await;
    let affected =
        sqlx::query("UPDATE audit_logs SET disposition=?,note=? WHERE id=? AND network_id=?")
            .bind(&payload.disposition)
            .bind(&payload.note)
            .bind(payload.id)
            .bind(&payload.network_id)
            .execute(&state.db)
            .await?
            .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        &state.db,
        &payload.network_id,
        &claims.username,
        "incident_review",
        &format!("{}: {}", payload.id, payload.disposition),
    )
    .await?;
    Ok(Json(json!({"status":payload.disposition})))
}

#[derive(Deserialize)]
pub struct NetworkRequest {
    pub network_id: String,
}
pub async fn check_supervisor(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<NetworkRequest>,
) -> Result<Json<Value>, AppError> {
    crate::dashboard::authorize(&state.db, &claims, &payload.network_id, true).await?;
    let _permit = state
        .supervisor
        .slots
        .try_acquire()
        .map_err(|_| AppError::Conflict)?;
    {
        let mut health = state.supervisor.health.lock().await;
        let now = chrono::Utc::now().timestamp();
        if health.last_attempt.is_some_and(|at| now - at < 5) {
            return Err(AppError::Conflict);
        }
        health.last_attempt = Some(now);
    }
    let result = state.supervisor.review(&json!({"purpose":"connection test, no enforcement","observed_bytes_in":1000,"observed_bytes_out":100,"observed_drops":0,"context":"Synthetic benign connectivity check; describe the limits of these observations."})).await;
    audit(
        &state.db,
        &payload.network_id,
        &claims.username,
        "supervisor_check",
        if result.is_ok() { "success" } else { "failed" },
    )
    .await?;
    Ok(Json(
        json!({"ok":result.is_ok(),"supervisor":state.supervisor.status().await}),
    ))
}

#[derive(Deserialize)]
pub struct ExportQuery {
    #[serde(default = "export_limit")]
    limit: i64,
}
fn export_limit() -> i64 {
    10000
}
pub async fn export_telemetry(
    State(state): State<AppState>,
    claims: Claims,
    Path(network): Path<String>,
    Query(query): Query<ExportQuery>,
) -> Result<Json<Value>, AppError> {
    crate::dashboard::authorize(&state.db, &claims, &network, false).await?;
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT payload FROM telemetry WHERE network_id=? ORDER BY id DESC LIMIT ?",
    )
    .bind(&network)
    .bind(query.limit.clamp(1, 10000))
    .fetch_all(&state.db)
    .await?;
    let reports: Vec<Value> = rows
        .iter()
        .rev()
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect();
    Ok(Json(
        json!({"network_id":network,"reports":reports,"limit":query.limit.clamp(1,10000),"source":"observed sensor reports"}),
    ))
}
