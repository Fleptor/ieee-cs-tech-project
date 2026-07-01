use axum::http::StatusCode;
use serde::{Serialize, Deserialize};
use jsonwebtoken::errors::Error;
use std::fmt;

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

impl fmt::Display for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_str = match self {
            DeviceState::Allowed => "allowed",
            DeviceState::Blocked => "blocked",
            DeviceState::Suspicious => "suspicious",
        };
        write!(f, "{}", state_str)
    }
}

impl From<String> for DeviceState {
    fn from(value: String) -> Self {
        match value.as_str() {
            "allowed" => DeviceState::Allowed,
            "blocked" => DeviceState::Blocked,
            "suspicious" => DeviceState::Suspicious,
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
    TokenCreationError(Error),
    InvalidTokenError(Error),
    NotFound,
    Conflict,
    Unauthorized
}

impl From<sqlx::Error> for AppError {
    fn from(inner: sqlx::Error) -> Self {
        AppError::DatabaseError(inner)
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AppError::DatabaseError(err) => {
                println!("CRITICAL DATABASE FAULT: {:?}", err); 
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal System Fault").into_response() 
            }
            AppError::TokenCreationError(err) => {
                println!("CRITICAL ENCODING PROBLEM: {:?}", err); 
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal System Fault").into_response() 
            }
            AppError::InvalidTokenError(err) => {
                println!("SECURITY ALERT: Invalid/Expired JWT: {:?}", err); 
                (StatusCode::UNAUTHORIZED, "Internal System Fault").into_response() 
            }
            AppError::NotFound => {
                println!("CRITICAL PROBLEM: {:?}", StatusCode::NOT_FOUND); 
                (StatusCode::NOT_FOUND,"no such device").into_response() 
            }
            AppError::Conflict => {
                println!("CRITICAL PROBLEM: {:?}", StatusCode::CONFLICT); 
                (StatusCode::CONFLICT,"").into_response() 
            }
            AppError::Unauthorized => {
                println!("SECURITY ALERT: {:?}", StatusCode::UNAUTHORIZED); 
                (StatusCode::UNAUTHORIZED,"").into_response() 
            }
        }
    }
}