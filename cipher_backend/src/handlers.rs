use axum::{extract::State, http::StatusCode, Json};
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

// still needs work
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
    //send_email(email);
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
pub async fn register_device(State(db): State<SharedDatabase>, _key: RouterKey, Json(payload): Json<RegisterRequest>) -> Result<Json<NetworkDevice>, AppError> {
    println!("--> [POST] /api/devices - New MAC: {}", payload.mac);
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM devices WHERE mac = ?", payload.mac)
        .fetch_optional(&db)
        .await?;
    if existing.is_some() {
        println!("WARNING: Device {} is already connected", payload.mac);
        return Err(AppError::Conflict);
    }
    sqlx::query!("INSERT INTO devices (network_id, mac, hostname, ip, manufacturer, state, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)", payload.network_id, payload.mac, payload.hostname, payload.ip, payload.manufacturer, "allowed", "Active Now")
        .execute(&db)
        .await?;
    println!("Device {}, has been added", payload.hostname);
    let new_device = NetworkDevice {
        network_id: payload.network_id,
        mac: payload.mac,
        hostname:payload.hostname,
        ip:payload.ip,
        manufacturer:payload.manufacturer,
        state:DeviceState::Allowed,
        last_seen:"Active Now".to_string()
    };
    Ok(Json(new_device))
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