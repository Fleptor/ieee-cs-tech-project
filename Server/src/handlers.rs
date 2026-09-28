use axum::{
    Json,
    extract::{Path, State, ws::WebSocketUpgrade},
    http::StatusCode,
};

use crate::SharedDatabase;
use crate::auth::*;
use crate::models::*;

// can only be used by me
#[axum::debug_handler]
pub async fn make_network_and_assign_admin(
    _key: RouterKey,
    State(db): State<SharedDatabase>,
    Json(payload): Json<Network>,
) -> Result<StatusCode, AppError> {
    let existing = sqlx::query!(
        "SELECT 1 AS exists_flag FROM networks WHERE network_id = ?",
        payload.network_id
    )
    .fetch_optional(&db)
    .await?;
    if existing.is_some() {
        println!("Warning, Network already exists {}", payload.network_id);
        return Err(AppError::Conflict);
    }
    let existing = sqlx::query!(
        "SELECT 1 AS exists_flag FROM users WHERE username = ?",
        payload.username
    )
    .fetch_optional(&db)
    .await?;
    if existing.is_none() {
        println!("Warning, no such user {}", payload.username);
        return Err(AppError::Conflict);
    }
    sqlx::query!(
        "INSERT INTO networks (network_id, username, is_admin) VALUES (?, ?, ?)",
        payload.network_id,
        payload.username,
        1
    )
    .execute(&db)
    .await?;
    Ok(StatusCode::ACCEPTED)
}

#[axum::debug_handler]
pub async fn change_admin_of_network(
    State(db): State<SharedDatabase>,
    Json(payload): Json<ChangeAdminRequest>,
) -> Result<StatusCode, AppError> {
    let old_admin = sqlx::query!("SELECT 1 AS exists_flag FROM networks Where network_id = ? AND username = ? AND is_admin = ?", payload.network_id, payload.old_admin, 1)
        .fetch_optional(&db)
        .await?;
    if old_admin.is_none() {
        return Err(AppError::Conflict);
    }
    verify_user(&db, &payload.old_admin, &payload.old_admin_password).await?;

    let new_admin = sqlx::query!(
        "SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?",
        payload.network_id,
        payload.new_admin
    )
    .fetch_optional(&db)
    .await?;
    if new_admin.is_none() {
        return Err(AppError::Conflict);
    }
    sqlx::query!(
        "UPDATE networks SET is_admin = ? WHERE network_id = ? AND username = ?",
        1,
        payload.network_id,
        payload.new_admin
    )
    .execute(&db)
    .await?;
    Ok(StatusCode::ACCEPTED)
}

#[axum::debug_handler]
pub async fn router_ws_handler(
    ws: WebSocketUpgrade,
    Path(network_id): Path<String>,
    State(state): State<AppState>,
    _key: RouterKey,
) -> axum::response::Response {
    println!(
        "--> [WS Handshake] Physical Router attempting persistent connection for Network: {}...",
        network_id
    );
    ws.on_upgrade(move |socket| crate::router_socket::handle(socket, network_id, state))
}

#[axum::debug_handler]
pub async fn signup_user(
    State(db): State<SharedDatabase>,
    Json(payload): Json<User>,
) -> Result<String, AppError> {
    if payload.username.trim().is_empty()
        || !payload.email.contains('@')
        || payload.password.len() < 8
    {
        return Err(AppError::Conflict);
    }
    let hashed_password = password_hasher(&payload.password);
    let mut tx = db.begin().await?;
    match sqlx::query("INSERT INTO users (username,email,password) VALUES (?,?,?)")
        .bind(&payload.username)
        .bind(&payload.email)
        .bind(hashed_password)
        .execute(&mut *tx)
        .await
    {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => return Err(AppError::Conflict),
        Err(e) => return Err(e.into()),
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await?;
    // Local bootstrap: the first account owns the configured physical network.
    if count == 1 {
        let network = std::env::var("CIPHER_NETWORK_ID").unwrap_or_else(|_| "NET_123".into());
        sqlx::query("INSERT INTO networks (network_id,username,is_admin) VALUES (?,?,1)")
            .bind(network)
            .bind(&payload.username)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    create_jwt(&payload.username, &payload.email)
}

#[axum::debug_handler]
pub async fn login_user(
    State(db): State<SharedDatabase>,
    Json(payload): Json<User>,
) -> Result<String, AppError> {
    let user = if !payload.username.is_empty() {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE username=?")
            .bind(&payload.username)
            .fetch_optional(&db)
            .await?
    } else {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email=?")
            .bind(&payload.email)
            .fetch_optional(&db)
            .await?
    }
    .ok_or(AppError::Unauthorized)?;
    if !verify_password(&payload.password, &user.password) {
        return Err(AppError::Unauthorized);
    }
    create_jwt(&user.username, &user.email)
}

#[axum::debug_handler]
pub async fn add_network_to_user(
    State(db): State<SharedDatabase>,
    claims: Claims,
    Json(payload): Json<Network>,
) -> Result<StatusCode, AppError> {
    let existing = sqlx::query!(
        "SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?",
        payload.network_id,
        claims.username
    )
    .fetch_optional(&db)
    .await?;
    if existing.is_none() {
        return Err(AppError::Conflict);
    }
    let Some(username) = sqlx::query_scalar!(
        "SELECT username FROM networks WHERE network_id = ? AND is_admin = ?",
        payload.network_id,
        1
    )
    .fetch_optional(&db)
    .await?
    else {
        return Err(AppError::Conflict);
    };
    let _email: String =
        sqlx::query_scalar!("SELECT email FROM users WHERE username = ?", username)
            .fetch_one(&db)
            .await?;
    return Ok(StatusCode::ACCEPTED);
}

#[axum::debug_handler]
pub async fn get_devices(
    State(db): State<SharedDatabase>,
    claims: Claims,
    Json(network_id): Json<String>,
) -> Result<Json<Vec<NetworkDevice>>, AppError> {
    println!("--> [GET] /api/devices (Zero-allocation read)");
    let existing = sqlx::query!(
        "SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?",
        network_id,
        claims.username
    )
    .fetch_optional(&db)
    .await?;
    if existing.is_none() {
        return Err(AppError::Conflict);
    }
    let devices: Vec<NetworkDevice> = sqlx::query_as!(
        NetworkDevice,
        "SELECT * FROM devices WHERE network_id = ?",
        network_id
    )
    .fetch_all(&db)
    .await?;
    Ok(Json(devices))
}

#[axum::debug_handler]
pub async fn get_single_device(
    State(db): State<SharedDatabase>,
    claims: Claims,
    Json(payload): Json<NormalRequest>,
) -> Result<Json<NetworkDevice>, AppError> {
    let existing = sqlx::query!(
        "SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?",
        payload.network_id,
        claims.username
    )
    .fetch_optional(&db)
    .await?;
    if existing.is_none() {
        return Err(AppError::Conflict);
    }
    if let Some(device) = sqlx::query_as!(
        NetworkDevice,
        "SELECT * FROM devices WHERE mac = ? AND network_id = ?",
        payload.mac,
        payload.network_id
    )
    .fetch_optional(&db)
    .await?
    {
        println!("SUCCESS: Device {} is found.", device.hostname);
        return Ok(Json(device));
    }
    println!("Warning, device {} not found", payload.mac);
    Err(AppError::NotFound)
}

#[axum::debug_handler]
pub async fn delete_device(
    State(db): State<SharedDatabase>,
    claims: Claims,
    Json(payload): Json<NormalRequest>,
) -> Result<Json<Vec<NetworkDevice>>, AppError> {
    crate::dashboard::authorize(&db, &claims, &payload.network_id, true).await?;
    println!("--> [Delete] /api/devices - Targeting Mac: {}", payload.mac);
    let existing = sqlx::query!(
        "SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?",
        payload.network_id,
        claims.username
    )
    .fetch_optional(&db)
    .await?;
    if existing.is_none() {
        return Err(AppError::Conflict);
    }
    let protected: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE network_id=? AND mac=? AND state!='allowed') OR EXISTS(SELECT 1 FROM device_commands WHERE network_id=? AND mac=? AND status IN ('pending','sent'))")
        .bind(&payload.network_id).bind(&payload.mac).bind(&payload.network_id).bind(&payload.mac).fetch_one(&db).await?;
    if protected {
        return Err(AppError::Conflict);
    }
    let result = sqlx::query!(
        "DELETE FROM devices WHERE mac = ? AND network_id = ?",
        payload.mac,
        payload.network_id
    )
    .execute(&db)
    .await?;
    if result.rows_affected() != 0 {
        println!("SUCCESS: Device {} has been deleted", payload.mac);
        let devices: Vec<NetworkDevice> = sqlx::query_as!(
            NetworkDevice,
            "SELECT * FROM devices WHERE network_id = ?",
            payload.network_id
        )
        .fetch_all(&db)
        .await?;
        return Ok(Json(devices));
    }
    println!("WARNING: Could not find device with MAC: {}", payload.mac);
    Err(AppError::NotFound)
}
