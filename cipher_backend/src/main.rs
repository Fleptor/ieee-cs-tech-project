use axum::{Json, Router, extract::{State, FromRequestParts}, http::{request::Parts, StatusCode}, routing::{delete, post}};
use std::{env, net::SocketAddr, sync::OnceLock};
use tower_http::cors::{Any, CorsLayer};
use jsonwebtoken::{encode, EncodingKey, Header, decode, DecodingKey, Validation};
use chrono::{Utc, Duration};
//use lettre::{Message, SmtpTransport, Transport};
//use rand::Rng;
use rand_core::OsRng;
use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
mod models;
use crate::models::{
    AppError, ChangeAdminRequest, ChangeStateRequest, Claims, NormalRequest,
    DeviceState, Network, NetworkDevice, RegisterRequest, User
};

type SharedDatabase = sqlx::SqlitePool;
static JWT_SECRET: OnceLock<String> = OnceLock::new();
static ROUTER_SECRET: OnceLock<String> = OnceLock::new();


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

async fn verify_user(db: &SharedDatabase, username: &str, password: &str) -> Result<(), AppError> {
    let existing = sqlx::query_scalar!("SELECT password FROM users WHERE username = ? ", username)
        .fetch_optional(db)
        .await?;
    if let Some(hash_password) = existing {
        if verify_password(password, &hash_password) {
            return Ok(())
        }
    }
    Err(AppError::Unauthorized)
}

fn verify_password(password: &str, hashed_password: &str) -> bool {
    let parsed_head = match PasswordHash::new(hashed_password){
        Ok(hash) => hash,
        Err(_) => return false
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed_head).is_ok()
}

fn password_hasher(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string()
}

fn create_jwt(username: &str, email: &str) -> Result<String, AppError> {
    let Some(secret) = JWT_SECRET.get()
        else{
            return Err(AppError::NotFound);
        };

    let exp_time = Utc::now()
        .checked_add_signed(Duration::hours(2))
        .expect("valid_timestapm")
        .timestamp();
    let claims = Claims {
        username: username.to_string(),
        email: email.to_string(),
        exp: exp_time
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).map_err(AppError::TokenCreationError)
}

fn verify_jwt(token: &str) -> Result<Claims, AppError> {
    let Some(secret) = JWT_SECRET.get()
        else{
            return Err(AppError::NotFound);
        };
    let token_data = decode::<Claims>(token,&DecodingKey::from_secret(secret.as_bytes()),&Validation::default(),)
        .map_err(AppError::InvalidTokenError)?;
    Ok(token_data.claims)
}


#[axum::async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());

        let token = match auth_header {
            Some(header_value) if header_value.starts_with("Bearer ") => {
                header_value.trim_start_matches("Bearer ")
            }
            _ => return Err(AppError::Unauthorized),
        };
        verify_jwt(token)
    }
}



struct RouterKey;
#[axum::async_trait]
impl<S> FromRequestParts<S> for RouterKey
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(expected_key) = ROUTER_SECRET.get() else {
            return Err(AppError::NotFound);
        };
        
        let auth_header = parts.headers.get(axum::http::header::AUTHORIZATION).and_then(|h| h.to_str().ok());
        
        match auth_header {
            Some(header) if header == format!("ApiKey {}", expected_key) => Ok(RouterKey),
            _ => {
                println!("SECURITY ALERT: Unauthorized Router connection attempt!");
                Err(AppError::Unauthorized)
            },
        }
    }
}

// can only be used by me 
#[axum::debug_handler]
async fn make_network_and_assign_admin(State(db):State<SharedDatabase>, Json(payload): Json<Network>) -> Result<StatusCode, AppError>{
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
async fn change_admin_of_network(State(db): State<SharedDatabase>, Json(payload): Json<ChangeAdminRequest>) -> Result<StatusCode, AppError>{
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
async fn signup_user(State(db): State<SharedDatabase>, Json(payload): Json<User>) -> Result<String, AppError>{
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
async fn login_user(State(db): State<SharedDatabase>, Json(payload): Json<User>) -> Result<String, AppError>{
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
async fn add_network_to_user(State(db): State<SharedDatabase>, claims: Claims, Json(payload): Json<Network>) -> Result<StatusCode, AppError> {
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
async fn get_devices(State(db): State<SharedDatabase>, claims: Claims, Json(network_id): Json<String>) -> Result<Json<Vec<NetworkDevice>>, AppError> {
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
async fn get_single_device(State(db): State<SharedDatabase>, claims: Claims, Json(payload): Json<NormalRequest>) -> Result<Json<NetworkDevice>, AppError> {
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
async fn register_device(State(db): State<SharedDatabase>, _key: RouterKey, Json(payload): Json<RegisterRequest>) -> Result<Json<NetworkDevice>, AppError> {
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
async fn change_state(State(db): State<SharedDatabase>, claims: Claims, Json(payload): Json<ChangeStateRequest>) -> Result<Json<Vec<NetworkDevice>>, AppError> {
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
async fn delete_device(State(db): State<SharedDatabase>, claims: Claims, Json(payload): Json<NormalRequest>) -> Result<Json<Vec<NetworkDevice>>, AppError> {
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

#[tokio::main]
async fn main() {

    dotenvy::dotenv().ok();
    JWT_SECRET.set(env::var("JWT_SECRET").expect("JWT_SECRET must be set")).unwrap();
    ROUTER_SECRET.set(env::var("ROUTER_SECRET").unwrap_or_else(|_| "cipher_dev_key_123".to_string())).unwrap();

    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename("cipher.db")
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
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
        .route("/api/get_device", post(get_single_device))
        .route("/api/add_device", post(register_device))
        .route("/api/delete_device", delete(delete_device))
        .route("/api/change_state", post(change_state))
        .with_state(db)
        .layer(cors);

    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        "localhost+1.pem",
        "localhost+1-key.pem",
        ).await.expect("Failed to load TLS certificates");

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("CIPHER Cloud Control Plane running on https://{}", addr);
    
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}