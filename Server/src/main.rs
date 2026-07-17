use axum::{Router, routing::{get, post, delete}};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tokio::sync::broadcast;
mod ai;
mod auth;
mod handlers;
mod models;
use crate::handlers::*;

pub type SharedDatabase = sqlx::SqlitePool;

#[allow(dead_code, unused_imports, clippy::all, mismatched_lifetime_syntaxes, elided_lifetimes_in_paths, unsafe_op_in_unsafe_fn)]
pub mod router_generated;

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
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

     sqlx::query!("
        CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        network_id TEXT NOT NULL,
        mac TEXT NOT NULL,
        threat_name TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        explanation TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );").execute(&db).await.unwrap();

    let threat_intel = std::sync::Arc::new(tokio::sync::RwLock::new(crate::ai::GlobalThreatIntel {
        banned_ips: vec!["185.15.59.224".to_string(), "45.133.1.106".to_string()],
        ad_domains: vec!["telemetry.malware.com".to_string(), "trackers.ad-network.com".to_string()],
    }));

    let intel_cache_clone = threat_intel.clone();
    tokio::spawn(async move {
        println!("🕒 [CRON] Global Threat Intel background updater started.");
        // Wake up every 12 hours
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60 * 60 * 12)); 
        loop {
            interval.tick().await;
            match crate::ai::fetch_global_threat_intel().await {
                Ok(new_intel) => {
                    println!("✅ [CRON] Successfully pulled new Threat Intel from OSINT!");
                    // Acquire exclusive write lock to update the memory
                    let mut cache = intel_cache_clone.write().await;
                    *cache = new_intel;
                }
                Err(e) => println!("⚠️ [CRON] Failed to update Threat Intel: {}", e),
            }
        }
    });

    let (tx, _rx) = broadcast::channel(100);
    let app_state = crate::models::AppState { db, tx, threat_intel};
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/api/owner/set_admin", post(make_network_and_assign_admin))
        .route("/api/Main/signup", post(signup_user))
        .route("/api/Main/login", post(login_user))
        .route("/api/Main/add_network",post(add_network_to_user))
        .route("/api/Main/change_admin",post(change_admin_of_network))
        .route("/api/get_devices", post(get_devices))
        .route("/api/get_device", post(get_single_device))
        .route("/api/delete_device", delete(delete_device))
        .route("/api/change_state", post(change_state))
        .route("/api/router/ws/:network_id", get(router_ws_handler))
        .with_state(app_state)
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