use axum::http::StatusCode;
use serde::{Serialize, Deserialize};
use jsonwebtoken;
#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Network {
    pub network_id: String,
    pub username: String,
    pub is_admin: bool,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub username: String,
    pub email: String,
    pub password: String
}

#[derive(Serialize, Deserialize, Clone, PartialEq, sqlx::FromRow)]
pub struct NetworkDevice {
    pub network_id: String,
    pub hostname: String,
    pub ip: String,
    pub mac: String,
    pub manufacturer: String,
    pub state: DeviceState,
    pub last_seen: String
}

#[derive(Serialize,Deserialize)]
pub struct Claims {
    pub username: String,
    pub email: String,
    pub exp: i64
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum DeviceState { Allowed, Blocked, Suspicious }
impl From<String> for DeviceState {
    fn from(value: String) -> Self {
        match value.as_str() {
            "allowed" => DeviceState::Allowed,
            "blocked" => DeviceState::Blocked,
            "suspicious" => DeviceState::Suspicious,
            // If the database has corrupted text, default to suspicious for safety
            _ => DeviceState::Suspicious, 
        }
    }
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct ChangeAdminRequest {
    pub old_admin: String,
    pub new_admin: String,
    pub old_admin_password : String,
    pub network_id: String
}


#[derive(Serialize, Deserialize)]
pub struct NormalRequest {
    pub network_id: String,
    pub mac: String
}

#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    pub network_id: String,
    pub mac: String,
    pub hostname: String,
    pub ip:String,
    pub manufacturer: String
}

#[derive(Serialize, Deserialize)]
pub struct ChangeStateRequest {
    pub network_id: String,
    pub mac: String,
    pub state:DeviceState
}

pub enum AppError {
    DatabaseError(sqlx::Error),
    EncodingError(jsonwebtoken::errors::Error)
}

impl From<sqlx::Error> for AppError {
    fn from(inner: sqlx::Error) -> Self {
        AppError::DatabaseError(inner)
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(inner: jsonwebtoken::errors::Error) -> Self {
        AppError::EncodingError(inner)
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AppError::DatabaseError(err) => {
                println!("CRITICAL DATABASE FAULT: {:?}", err); 
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal System Fault").into_response() 
            }
            AppError::EncodingError(err) => {
                println!("CRITICAL ENCODING PROBLEM: {:?}", err); 
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal System Fault").into_response() 
            }
        }
    }
}