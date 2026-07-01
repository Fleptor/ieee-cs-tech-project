use axum::{extract::FromRequestParts, http::request::Parts};
use std::{env, sync::OnceLock};
use jsonwebtoken::{encode, decode, EncodingKey, DecodingKey, Header, Validation};
use chrono::{Utc, Duration};
use rand_core::OsRng;
use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
//use lettre::{Message, SmtpTransport, Transport};
//use rand::Rng;

use crate::models::{AppError, Claims};
use crate::SharedDatabase;

pub static JWT_SECRET: OnceLock<String> = OnceLock::new();
pub static ROUTER_SECRET: OnceLock<String> = OnceLock::new();

/*
pub async fn send_email(address:&str){
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

pub fn init_secrets() {
    JWT_SECRET.set(env::var("JWT_SECRET").expect("JWT_SECRET must be set")).unwrap();
    ROUTER_SECRET.set(env::var("ROUTER_SECRET").unwrap_or_else(|_| "cipher_dev_key_123".to_string())).unwrap();
}

pub async fn verify_user(db: &SharedDatabase, username: &str, password: &str) -> Result<(), AppError> {
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

pub fn verify_password(password: &str, hashed_password: &str) -> bool {
    let parsed_head = match PasswordHash::new(hashed_password){
        Ok(hash) => hash,
        Err(_) => return false
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed_head).is_ok()
}

pub fn password_hasher(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string()
}

pub fn create_jwt(username: &str, email: &str) -> Result<String, AppError> {
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

pub fn verify_jwt(token: &str) -> Result<Claims, AppError> {
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

pub struct RouterKey;
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
