use axum::{
    Json, Router, extract::State, http::StatusCode, routing::get
};
use lettre::{Message, SmtpTransport, Transport};
use rand::Rng;
use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
enum DeviceState { Allowed, Blocked, Suspicious }

#[derive(Serialize, Deserialize)]
struct Network {
    network_id: String,
    username: String,
    is_admin: bool,
}

#[derive(Serialize, Deserialize)]
struct User {
    username: String,
    email: String,
    password: String
}

#[derive(Serialize, Deserialize, Clone, PartialEq, sqlx::FromRow)]
struct NetworkDevice {
    network_id: String, hostname: String, ip: String, mac: String, manufacturer: String, state: DeviceState, last_seen: String
}

#[derive(Serialize, Deserialize)]
struct RegisterRequest {
    network_id: String,
    mac: String,
    hostname: String,
    ip:String,
    manufacturer: String
}

#[derive(Serialize, Deserialize)]
struct ChangeStateRequest {
    mac: String,
    state:DeviceState
}

#[derive(Deserialize)]
struct DeviceQuery {
     state: Option<String> 
}

// 1. CREATE A THREAD-SAFE SHARED STATE TYPE
// Arc = Allows multiple threads to safely share ownership
// RwLock = Allows infinite simultaneous readers, but only one writer at a time
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

// can only be used by me 
async fn make_network_and_assign_admin(State(db):State<SharedDatabase>, Json(payload): Json<Network>) -> Result<axum::http::StatusCode,axum::http::StatusCode>{
    let existing = sqlx::query("SELECT 1 FROM networks WHERE network_id = ?")
        .bind(&payload.network_id)
        .fetch_optional(&db)
        .await
        .unwrap();
    if existing.is_some() {
        println!("Warning, Network already exists {}",payload.network_id);
        return Err(axum::http::StatusCode::CONFLICT);
    }
    let existing = sqlx::query("SELECT 1 FROM users WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&db)
        .await
        .unwrap();
    if existing.is_none() {
        println!("Warning, no such user {}",payload.username);
        return Err(axum::http::StatusCode::CONFLICT);
    }
    sqlx::query("INSERT INTO networks (network_id, username, is_admin) VALUES (?, ?, ?)")
        .bind(&payload.network_id)
        .bind(&payload.username)
        .bind(1)
        .execute(&db)
        .await
        .unwrap();
    Ok(axum::http::StatusCode::ACCEPTED)
}

async fn signup_user(State(db): State<SharedDatabase>, Json(payload): Json<User>) -> Result<axum::http::StatusCode,axum::http::StatusCode>{
    let existing = sqlx::query("SELECT 1 FROM users WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&db)
        .await
        .unwrap();
    if existing.is_some() {
        println!("Warning, there is a user with the name {}",payload.username);
        return Err(axum::http::StatusCode::CONFLICT);
    }
    //send_email(&payload.email);
    sqlx::query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)")
        .bind(&payload.username)
        .bind(&payload.email)
        .bind(&payload.password)
        .execute(&db)
        .await
        .unwrap();
    Ok(axum::http::StatusCode::ACCEPTED)
}

async fn add_network_to_user() {

}

async fn login_user(){

}

// 2. INJECT STATE INTO THE HANDLER
async fn get_devices(State(db): State<SharedDatabase>, axum::extract::Query(query): axum::extract::Query<DeviceQuery>) -> Json<Vec<NetworkDevice>> {
    println!("--> [GET] /api/devices (Zero-allocation read)");
    if let Some(target_state) = query.state {
        println!("    Filtering {} state devices", target_state);
        let devices: Vec<NetworkDevice> = sqlx::query_as::<_, NetworkDevice>("SELECT * FROM devices Where state = ?")
            .bind(target_state)
            .fetch_all(&db)
            .await
            .unwrap();
        return Json(devices);
    }
    let devices: Vec<NetworkDevice> = sqlx::query_as::<_, NetworkDevice>("SELECT * FROM devices")
        .fetch_all(&db)
        .await
        .unwrap();
    Json(devices)
}

async fn get_single_device(State(db): State<SharedDatabase>, axum::extract::Path(mac_address): axum::extract::Path<String>) -> Result<Json<NetworkDevice>,axum::http::StatusCode> {
    let result = sqlx::query_as::<_,NetworkDevice>("SELECT * FROM devices WHERE mac = ?")
        .bind(&mac_address)
        .fetch_optional(&db)
        .await
        .unwrap_or(None);
    if let Some(device)= result {
        println!("SUCCESS: Device {} is found.", mac_address);
        return Ok(Json(device));
    }
    else {
        println!("Warning, device {} not found", mac_address);
        Err(axum::http::StatusCode::NOT_FOUND)
    }
}
async fn register_device(State(db): State<SharedDatabase>, Json(payload): Json<RegisterRequest>) -> Result<Json<NetworkDevice>, axum::http::StatusCode> {
    println!("--> [POST] /api/devices - New MAC: {}", payload.mac);
    let existing = sqlx::query("SELECT 1 FROM devices WHERE mac = ?")
        .bind(&payload.mac)
        .fetch_optional(&db)
        .await
        .unwrap();
    if existing.is_some() {
        println!("WARNING: Device {} is already connected", payload.mac);
        return Err(axum::http::StatusCode::CONFLICT);
    }
    sqlx::query("INSERT INTO devices (network_id, mac, hostname, ip, manufacturer, state, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(&payload.network_id)
        .bind(&payload.mac)
        .bind(&payload.hostname)
        .bind(&payload.ip)
        .bind(&payload.manufacturer)
        .bind("allowed")
        .bind("Active Now")
        .execute(&db).await.unwrap();
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

async fn change_state(State(db): State<SharedDatabase>, Json(payload): Json<ChangeStateRequest>) -> Result<Json<Vec<NetworkDevice>>, axum::http::StatusCode> {
    println!("--> [POST] /api/state - Targeting MAC: {}", payload.mac);
    let state_str = match payload.state {
    DeviceState::Allowed => "allowed",
    DeviceState::Blocked => "blocked",
    DeviceState::Suspicious => "suspicious",
    };
    let result = sqlx::query("UPDATE devices SET state = ?  WHERE mac = ?")
        .bind(state_str)
        .bind(&payload.mac)
        .execute(&db)
        .await
        .unwrap();
    if result.rows_affected() != 0 {
        println!("Device {} state changed.", payload.mac);
        let devices = sqlx::query_as::<_, NetworkDevice>("SELECT * FROM devices").fetch_all(&db).await.unwrap_or_default();
        return Ok(Json(devices));
    }
    else {
        println!("Warning, device {} not found", payload.mac);
        Err(axum::http::StatusCode::NOT_FOUND)
    }
    
}

async fn delete_device(State(db): State<SharedDatabase>, axum::extract::Path(mac_address): axum::extract::Path<String>) -> Result<Json<Vec<NetworkDevice>>, axum::http::StatusCode> {
    println!("--> [Delete] /api/devices - Targeting Mac: {}", mac_address);
    let result = sqlx::query("DELETE FROM devices WHERE mac = ?")
        .bind(&mac_address)
        .execute(&db)
        .await
        .unwrap();
    if result.rows_affected() != 0 {
        println!("SUCCESS: Device {} has been deleted", mac_address);
        let devices = sqlx::query_as::<_, NetworkDevice>("SELECT * FROM devices").fetch_all(&db).await.unwrap_or_default();
        return Ok(Json(devices));
    }
    println!("WARNING: Could not find device with MAC: {}", mac_address);
    Err(axum::http::StatusCode::NOT_FOUND)
}

async fn purge_blocked(State(db): State<SharedDatabase>, headers: axum::http::HeaderMap) -> Result<Json<Vec<NetworkDevice>>, axum::http::StatusCode> {
    if let Some(password) = headers.get("password"){
        if password != "super_secret_123" {
            println!("securty alert, invalid admin password");
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    }
    else {
        println!("SECURITY ALERT: Missing admin password header!");
        return Err(axum::http::StatusCode::UNAUTHORIZED); // HTTP 401
    }
    println!("--> [Delete] /api/devices - All blocked devices");
    sqlx::query("DELETE FROM devices WHERE state = 'blocked'")
        .execute(&db)
        .await
        .unwrap();
    let devices = sqlx::query_as::<_,NetworkDevice>("SELECT * FROM devices").fetch_all(&db).await.unwrap_or_default();
    Ok(Json(devices))
}

#[tokio::main]
async fn main() {
    // 3. INITIALIZE THE DATA ONCE ON STARTUP
    let db = sqlx::sqlite::SqlitePoolOptions::new()
    .connect("sqlite:cipher.db?mode=rwc")
    .await
    .unwrap();

    sqlx::query("
        CREATE TABLE IF NOT EXISTS networks (
        network_id TEXT NOT NULL,
        username TEXT NOT NULL,
        is_admin INTEGER NOT NULL,
        PRIMARY KEY (network_id, username),
        FOREIGN KEY(username) REFERENCES users(username)
        );").execute(&db).await.unwrap();

    sqlx::query("
        CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
        );").execute(&db).await.unwrap();

    sqlx::query("
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
        .route("/api/signup", axum::routing::post(signup_user))
        .route("/api/login", get(login_user))
        .route("/api/add_network",axum::routing::post(add_network_to_user))
        .route("/api/devices", get(get_devices))
        .route("/api/device/:mac", get(get_single_device))
        .route("/api/add_device", axum::routing::post(register_device))
        .route("/api/delete/:mac", axum::routing::delete(delete_device))
        .route("/api/delete_blocked", axum::routing::delete(purge_blocked))
        .route("/api/state", axum::routing::post(change_state))
        .with_state(db) // 4. PASS STATE TO AXUM
        .layer(cors);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("CIPHER Cloud Control Plane running on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}