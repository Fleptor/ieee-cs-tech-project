use axum::{Router, routing::{delete, post}};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
mod auth;
mod handlers;
mod models;
use crate::handlers::*;

pub type SharedDatabase = sqlx::SqlitePool;

#[tokio::main]
async fn main() {
    
    dotenvy::dotenv().ok();
    
    auth::init_secrets();

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