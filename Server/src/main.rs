use axum::{
    Router,
    routing::{delete, get, post},
};
use std::net::SocketAddr;

use tower_http::services::{ServeDir, ServeFile};
mod ai;
mod auth;
mod dashboard;
mod handlers;
mod models;
mod policy;
mod router_socket;
use crate::handlers::*;

pub type SharedDatabase = sqlx::SqlitePool;

#[allow(
    dead_code,
    unused_imports,
    clippy::all,
    mismatched_lifetime_syntaxes,
    elided_lifetimes_in_paths,
    unsafe_op_in_unsafe_fn
)]
pub mod router_generated;

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if let Ok(path) = std::env::var("CIPHER_ENV_FILE") {
        dotenvy::from_path(path).ok();
    } else {
        dotenvy::dotenv().ok();
    }
    auth::init_secrets();

    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(std::env::var("CIPHER_DB").unwrap_or_else(|_| "cipher.db".into()))
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();

    sqlx::query(
        "
        CREATE TABLE IF NOT EXISTS networks (
        network_id TEXT NOT NULL,
        username TEXT NOT NULL,
        is_admin INTEGER NOT NULL,
        PRIMARY KEY (network_id, username),
        FOREIGN KEY(username) REFERENCES users(username)
        );",
    )
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "
        CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
        );",
    )
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "
        CREATE TABLE IF NOT EXISTS devices (
        network_id TEXT NOT NULL,
        mac TEXT NOT NULL,
        hostname TEXT NOT NULL,
        ip TEXT NOT NULL,
        manufacturer TEXT NOT NULL,
        state TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY (network_id, mac)
        );",
    )
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "
        CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        network_id TEXT NOT NULL,
        mac TEXT NOT NULL,
        threat_name TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        explanation TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .execute(&db)
    .await
    .unwrap();

    dashboard::initialize(&db)
        .await
        .expect("Initialize dashboard storage");
    // Only explicitly configured intelligence is eligible for enforcement.
    let intel = std::env::var("CIPHER_THREAT_INTEL_FILE")
        .ok()
        .map(|path| {
            serde_json::from_str(&std::fs::read_to_string(path).expect("Read intelligence file"))
                .expect("Invalid intelligence JSON")
        })
        .unwrap_or(crate::ai::GlobalThreatIntel {
            banned_ips: vec![],
            ad_domains: vec![],
        });
    let threat_intel = std::sync::Arc::new(tokio::sync::RwLock::new(intel));

    let supervisor = std::sync::Arc::new(ai::Supervisor::from_env());
    let app_state = crate::models::AppState {
        db,
        supervisor,
        mutation: Default::default(),
        threat_intel,
        sensors: Default::default(),
    };

    let static_path = if std::path::Path::new("ui-dashboard").exists() {
        "ui-dashboard"
    } else {
        "../ui-dashboard"
    };

    let serve_dir = ServeDir::new(static_path)
        .not_found_service(ServeFile::new(format!("{}/index.html", static_path)));

    let app = Router::new()
        .route("/api/owner/set_admin", post(make_network_and_assign_admin))
        .route("/api/Main/signup", post(signup_user))
        .route("/api/Main/login", post(login_user))
        .route("/api/session/refresh", post(auth::refresh_session))
        .route("/api/Main/add_network", post(add_network_to_user))
        .route("/api/Main/change_admin", post(change_admin_of_network))
        .route("/api/get_devices", post(get_devices))
        .route("/api/get_device", post(get_single_device))
        .route("/api/delete_device", delete(delete_device))
        .route("/api/change_state", post(dashboard::command))
        .route("/api/networks", get(dashboard::networks))
        .route("/api/dashboard/:network_id", get(dashboard::snapshot))
        .route("/api/device/trust", post(policy::trust))
        .route("/api/device/baseline/reset", post(policy::reset_baseline))
        .route("/api/policy", post(policy::set_policy))
        .route("/api/incidents/review", post(policy::review_incident))
        .route("/api/supervisor/check", post(policy::check_supervisor))
        .route("/api/telemetry/:network_id", get(policy::export_telemetry))
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/router/ws/:network_id", get(router_ws_handler))
        .fallback_service(serve_dir)
        .with_state(app_state);

    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        std::env::var("CIPHER_TLS_CERT").unwrap_or_else(|_| "localhost+1.pem".into()),
        std::env::var("CIPHER_TLS_KEY").unwrap_or_else(|_| "localhost+1-key.pem".into()),
    )
    .await
    .expect("Failed to load TLS certificates");

    let addr: SocketAddr = std::env::var("CIPHER_BIND")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse()
        .expect("Invalid CIPHER_BIND");
    println!("CIPHER Cloud Control Plane running on https://{}", addr);

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
