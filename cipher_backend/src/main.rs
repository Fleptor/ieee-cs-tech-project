use axum::{Json, Router, extract::State, http::StatusCode, routing::{post, delete}};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
//use lettre::{Message, SmtpTransport, Transport};
//use rand::Rng;
mod models;
use crate::models::{
    AppError, ChangeAdminRequest, ChangeStateRequest, DeviceState, 
    Network, NetworkDevice, NormalRequest, RegisterRequest, User
};

type SharedDatabase = sqlx::SqlitePool;

/*
async fn send_email(address:&str){
    let email = Message::builder()
        .from("CIPHER Security <noreply@cipher.local>".parse().unwrap())
        .to(address.parse().unwrap())
        .subject("Network Access Request")
        .body(format!("A new user has requested access to your network. Your approval code is: {}", code))
        .unwrap();
    let mailer = SmtpTransport::builder_dangerous("127.0.0.1").build();
    println!("📧 MOCK EMAIL SENT TO {}: Code [{}]", address, code);
}
*/

async fn verify_user(db: &SharedDatabase, username: &str, password: &str) -> Result<Result<(), StatusCode>, AppError> {
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM users WHERE username = ? AND password = ?", username, password)
        .fetch_optional(db)
        .await?;
    if existing.is_some(){
        return Ok(Ok(()));
    }
    Ok(Err(StatusCode::UNAUTHORIZED))
}

// can only be used by me 
async fn make_network_and_assign_admin(State(db):State<SharedDatabase>, Json(payload): Json<Network>) -> Result<StatusCode, AppError>{
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM networks WHERE network_id = ?", payload.network_id)
        .fetch_optional(&db)
        .await?;
    if existing.is_some() {
        println!("Warning, Network already exists {}",payload.network_id);
        return Ok(StatusCode::CONFLICT);
    }
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM users WHERE username = ?",payload.username)
        .fetch_optional(&db)
        .await?;
    if existing.is_none() {
        println!("Warning, no such user {}",payload.username);
        return Ok(StatusCode::CONFLICT);
    }
    sqlx::query!("INSERT INTO networks (network_id, username, is_admin) VALUES (?, ?, ?)", payload.network_id, payload.username, 1)
        .execute(&db)
        .await
        .unwrap();
    Ok(StatusCode::ACCEPTED)
}

async fn change_admin_of_network(State(db): State<SharedDatabase>, Json(payload): Json<ChangeAdminRequest>) -> Result<StatusCode, AppError>{
    let old_admin = sqlx::query!("SELECT 1 AS exists_flag FROM networks Where network_id = ? AND username = ? AND is_admin = ?", payload.network_id, payload.old_admin, 1)
        .fetch_optional(&db)
        .await?;
    if old_admin.is_none() {
        return Ok(StatusCode::CONFLICT);
    }
    if let Err(auth_error) = verify_user(&db, &payload.old_admin, &payload.old_admin_password).await?{
        return Ok(auth_error);
    }
    let new_admin = sqlx::query!("SELECT 1 AS exists_flag FROM networks WHERE network_id = ? AND username = ?", payload.network_id, payload.new_admin)
        .fetch_optional(&db)
        .await?;
    if new_admin.is_none(){
        return Ok(StatusCode::CONFLICT);
    }
    sqlx::query!("UPDATE networks SET is_admin = ? WHERE network_id = ? AND username = ?", 1, payload.network_id, payload.new_admin)
        .execute(&db)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

async fn signup_user(State(db): State<SharedDatabase>, Json(payload): Json<User>) -> Result<StatusCode, AppError>{
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM users WHERE username = ?", payload.username)
        .fetch_optional(&db)
        .await?;
    if existing.is_some() {
        println!("Warning, there is a user with the name {}",payload.username);
        return Ok(StatusCode::CONFLICT);
    }
    sqlx::query!("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", payload.username, payload.email, payload.password)
        .execute(&db)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

// still needs work
async fn add_network_to_user(State(db): State<SharedDatabase>, Json(payload): Json<Network>) -> Result<StatusCode, AppError> {
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM users WHERE username = ?", payload.username)
        .fetch_optional(&db)
        .await?;
    if existing.is_none() {
        println!("Warning, there is no user with the name {}",payload.username);
        return Ok(StatusCode::CONFLICT);
    }
    let username: Option<String> = sqlx::query_scalar!("SELECT username FROM networks WHERE network_id = ? AND is_admin = ?", payload.network_id, 1)
        .fetch_optional(&db)
        .await?;
    if username.is_none() {
        return Ok(StatusCode::CONFLICT);
    }
    if let Some(name) = username {
        let email: String = sqlx::query_scalar!("SELECT email FROM users WHERE username = ?", name)
            .fetch_one(&db)
            .await?;
        //send_email(email);
        return Ok(StatusCode::ACCEPTED);
    }
    Ok(StatusCode::CONFLICT)
}

async fn login_user(State(db): State<SharedDatabase>, Json(payload): Json<User>) -> Result<StatusCode, AppError>{
    let mut password1: Option<String> = sqlx::query_scalar!("SELECT password FROM users WHERE username = ?", payload.username)
        .fetch_optional(&db)
        .await?;
    if password1.is_none() {
        password1 = sqlx::query_scalar!("SELECT password FROM users WHERE email = ?", payload.email)
        .fetch_optional(&db)
        .await?;
    }
    if let Some(password) = password1 {
        if password == payload.password {
            return Ok(StatusCode::ACCEPTED);
        }
        return Ok(StatusCode::UNAUTHORIZED);
    }
    Ok(StatusCode::CONFLICT)
}

async fn get_devices(State(db): State<SharedDatabase>, Json(payload): Json<NormalRequest>) -> Result<Result<Json<Vec<NetworkDevice>>, StatusCode>, AppError> {
    println!("--> [GET] /api/devices (Zero-allocation read)");
    if let Err(auth_error) = verify_user(&db, &payload.username, &payload.password).await?{
        return Ok(Err(auth_error));
    }
    let devices: Vec<NetworkDevice> = sqlx::query_as!(NetworkDevice, "SELECT * FROM devices WHERE network_id = ?", payload.network_id)
        .fetch_all(&db)
        .await?;
    Ok(Ok(Json(devices)))
}

async fn get_single_device(State(db): State<SharedDatabase>, axum::extract::Path(mac_address): axum::extract::Path<String>) -> Result<Result<Json<NetworkDevice>,StatusCode>, AppError> {
    let result: Option<NetworkDevice> = sqlx::query_as!(NetworkDevice, "SELECT * FROM devices WHERE mac = ?", mac_address)
        .fetch_optional(&db)
        .await?;
    if let Some(device)= result {
        println!("SUCCESS: Device {} is found.", device.hostname);
        return Ok(Ok(Json(device)));
    }
    else {
        println!("Warning, device {} not found", mac_address);
        Ok(Err(StatusCode::NOT_FOUND))
    }
}
async fn register_device(State(db): State<SharedDatabase>, Json(payload): Json<RegisterRequest>) -> Result<Result<Json<NetworkDevice>,StatusCode>, AppError> {
    println!("--> [POST] /api/devices - New MAC: {}", payload.mac);
    let existing = sqlx::query!("SELECT 1 AS exists_flag FROM devices WHERE mac = ?", payload.mac)
        .fetch_optional(&db)
        .await?;
    if existing.is_some() {
        println!("WARNING: Device {} is already connected", payload.mac);
        return Ok(Err(StatusCode::CONFLICT));
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
    Ok(Ok(Json(new_device)))
}

async fn change_state(State(db): State<SharedDatabase>, Json(payload): Json<ChangeStateRequest>) -> Result<StatusCode, AppError> {
    println!("--> [POST] /api/state - Targeting MAC: {}", payload.mac);
    let state_str = match payload.state {
    DeviceState::Allowed => "allowed",
    DeviceState::Blocked => "blocked",
    DeviceState::Suspicious => "suspicious",
    };
    let result = sqlx::query!("UPDATE devices SET state = ?  WHERE mac = ?", state_str, payload.mac)
        .execute(&db)
        .await?;
    if result.rows_affected() != 0 {
        println!("Device {} state changed.", payload.mac);
        return Ok(StatusCode::ACCEPTED);
    }
    else {
        println!("Warning, device {} not found", payload.mac);
        Ok(StatusCode::NOT_FOUND)
    }
}

async fn delete_device(State(db): State<SharedDatabase>, axum::extract::Path(mac_address): axum::extract::Path<String>) -> Result<StatusCode, AppError> {
    println!("--> [Delete] /api/devices - Targeting Mac: {}", mac_address);
    let result = sqlx::query!("DELETE FROM devices WHERE mac = ?", mac_address)
        .execute(&db)
        .await
        .unwrap();
    if result.rows_affected() != 0 {
        println!("SUCCESS: Device {} has been deleted", mac_address);
        return Ok(StatusCode::ACCEPTED);
    }
    println!("WARNING: Could not find device with MAC: {}", mac_address);
    Ok(StatusCode::NOT_FOUND)
}

async fn purge_blocked(State(db): State<SharedDatabase>, headers: axum::http::HeaderMap) -> Result<Json<Vec<NetworkDevice>>, StatusCode> {
    if let Some(password) = headers.get("password"){
        if password != "super_secret_123" {
            println!("securty alert, invalid admin password");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    else {
        println!("SECURITY ALERT: Missing admin password header!");
        return Err(StatusCode::UNAUTHORIZED); // HTTP 401
    }
    println!("--> [Delete] /api/devices - All blocked devices");
    sqlx::query!("DELETE FROM devices WHERE state = 'blocked'")
        .execute(&db)
        .await
        .unwrap();
    let devices = sqlx::query_as!(NetworkDevice, "SELECT * FROM devices").fetch_all(&db).await.unwrap_or_default();
    Ok(Json(devices))
}

#[tokio::main]
async fn main() {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename("cipher.db")
        .create_if_missing(true) // This mathematically replaces "?mode=rwc"
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal); // Type-safe WAL mode
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .unwrap();

    sqlx::query!("
        CREATE TABLE IF NOT EXISTS networks (
        network_id TEXT NOT NULL,
        username TEXT NOT NULL,
        is_admin INTEGER NOT NULL,
        PRIMARY KEY (network_id, username),
        FOREIGN KEY(username) REFERENCES users(username)
        );").execute(&db).await.unwrap();

    sqlx::query!("
        CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
        );").execute(&db).await.unwrap();

    sqlx::query!("
        CREATE TABLE IF NOT EXISTS devices (
        network_id TEXT NOT NULL,
        mac TEXT NOT NULL,
        hostname TEXT NOT NULL,
        ip TEXT NOT NULL,
        manufacturer TEXT NOT NULL,
        state TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY (network_id, mac)
        );").execute(&db).await.unwrap();

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/api/owner/set_admin", post(make_network_and_assign_admin))
        .route("/api/Main/signup", post(signup_user))
        .route("/api/Main/login", post(login_user))
        .route("/api/Main/add_network",post(add_network_to_user))
        .route("/api/Main/change_admin",post(change_admin_of_network))
        .route("/api/get_devices", post(get_devices))
        .route("/api/get_device/:mac", post(get_single_device))
        .route("/api/add_device", post(register_device))
        .route("/api/delete_device/:mac", delete(delete_device))
        .route("/api/delete_blocked", delete(purge_blocked))
        .route("/api/cheang_state", post(change_state))
        .with_state(db) // 4. PASS STATE TO AXUM
        .layer(cors);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("CIPHER Cloud Control Plane running on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}