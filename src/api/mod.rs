pub mod admin;
pub mod oauth;
pub mod skills;
pub mod tools;
pub mod v1;

use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub router: Arc<crate::router::Router>,
    pub config: Arc<std::sync::RwLock<crate::config::SkyportConfig>>,
    pub vault: Arc<std::sync::RwLock<crate::vault::Vault>>,
    pub db: Arc<std::sync::Mutex<rusqlite::Connection>>,
    pub http_client: reqwest::Client,
    pub start_time: std::time::Instant,
    /// Requests currently awaiting an upstream response, for the live dashboard.
    pub in_flight: Arc<std::sync::atomic::AtomicUsize>,
    /// In-memory sliding-window rate limiter for global and scoped guardrails.
    pub rate_limiter: Arc<crate::rate_limiter::RateLimiter>,
    /// Discovered upstream models per provider id, with a paid/free tier.
    /// Serves /v1/models and the dashboard catalog so a harness connecting
    /// only to this gateway sees every available model.
    pub catalog: Arc<std::sync::RwLock<std::collections::HashMap<String, Vec<CatalogModel>>>>,
    /// In-flight subscription sign-ins (device flows + browser callbacks).
    pub auth_sessions: crate::api::oauth::SessionMap,
}

/// One discovered model and its cost tier: "free" (cloud free tier covers
/// normal use), "paid", or "local" (runs on the user's own hardware — no
/// provider bills, but it is not a free cloud offering either).
#[derive(Clone, Debug, serde::Serialize)]
pub struct CatalogModel {
    pub id: String,
    pub tier: String,
}
