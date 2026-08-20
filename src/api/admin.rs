use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::StreamExt as _;

use crate::api::AppState;
use crate::config::save_config;
use crate::db;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AddKeyRequest {
    pub provider: String,
    pub alias: String,
    pub api_key: String,
    pub priority: i32,
}

#[derive(Deserialize)]
pub struct TestProviderRequest {
    pub provider: String,
}

#[derive(Deserialize)]
pub struct ProviderUpdateRequest {
    pub id: String,
    pub config: crate::config::ProviderConfig,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
    providers: Vec<String>,
    in_flight: usize,
    today_cost_usd: f64,
}

// ---------------------------------------------------------------------------
// 1. GET /api/status
// ---------------------------------------------------------------------------

pub async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();

    let config = match state.config.read() {
        Ok(value) => value,
        Err(_) => return Json(serde_json::json!({"status": "error"})),
    };
    let providers: Vec<String> = config.providers.values().map(|p| p.name.clone()).collect();

    let today_cost_usd = state
        .db
        .lock()
        .ok()
        .and_then(|db| db::get_today_cost(&db).ok())
        .unwrap_or(0.0);

    Json(serde_json::json!(StatusResponse {
        status: "ok".to_string(),
        version: "0.1.0".to_string(),
        uptime_seconds: uptime,
        providers,
        in_flight: state.in_flight.load(std::sync::atomic::Ordering::Relaxed),
        today_cost_usd,
    }))
}

// ---------------------------------------------------------------------------
// 2. GET /api/keys
// ---------------------------------------------------------------------------

pub async fn list_keys(State(state): State<AppState>) -> impl IntoResponse {
    let vault = match state.vault.read() {
        Ok(value) => value,
        Err(_) => return Json(Vec::<crate::vault::VaultEntrySummary>::new()),
    };
    let keys = vault.list_keys();
    Json(keys)
}

// ---------------------------------------------------------------------------
// 3. POST /api/keys
// ---------------------------------------------------------------------------

pub async fn add_key(
    State(state): State<AppState>,
    Json(body): Json<AddKeyRequest>,
) -> impl IntoResponse {
    let provider_exists = state
        .config
        .read()
        .ok()
        .is_some_and(|config| config.providers.contains_key(&body.provider));
    if !provider_exists {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": "Unknown provider"})),
        );
    }
    if body.api_key.trim().is_empty() || body.api_key.len() > 16 * 1024 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": "API key is empty or too long"})),
        );
    }
    if !valid_identifier(body.alias.trim()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"ok": false, "error": "Key alias must use 1-64 letters, digits, dots, underscores, or hyphens"}),
            ),
        );
    }
    let mut vault = match state.vault.write() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "vault lock poisoned"})),
            )
        }
    };
    let previous = vault.entries.clone();
    if let Err(error) = vault.add_key(
        &body.provider,
        body.alias.trim(),
        &body.api_key,
        body.priority.max(0) as u32,
    ) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"ok": false, "error": error})),
        );
    }
    if vault.save().is_err() {
        vault.entries = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": "Could not persist the key"})),
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// 4. DELETE /api/keys/:alias
// ---------------------------------------------------------------------------

pub async fn remove_key(
    State(state): State<AppState>,
    Path(alias): Path<String>,
) -> impl IntoResponse {
    let mut vault = match state.vault.write() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "vault lock poisoned"})),
            )
        }
    };
    let previous = vault.entries.clone();
    if !vault.remove_key(&alias) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": "Key not found"})),
        );
    }
    if vault.save().is_err() {
        vault.entries = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": "Could not persist the key change"})),
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// 5. PUT /api/keys/:alias/disable
// ---------------------------------------------------------------------------

pub async fn disable_key(
    State(state): State<AppState>,
    Path(alias): Path<String>,
) -> impl IntoResponse {
    let mut vault = match state.vault.write() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "vault lock poisoned"})),
            )
        }
    };
    let previous = vault.entries.clone();
    if !vault.disable_key(&alias) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": "Key not found"})),
        );
    }
    if vault.save().is_err() {
        vault.entries = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": "Could not persist the key change"})),
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// 6. PUT /api/keys/:alias/enable
// ---------------------------------------------------------------------------

pub async fn enable_key(
    State(state): State<AppState>,
    Path(alias): Path<String>,
) -> impl IntoResponse {
    let mut vault = match state.vault.write() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "vault lock poisoned"})),
            )
        }
    };
    let previous = vault.entries.clone();
    if !vault.enable_key(&alias) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": "Key not found"})),
        );
    }
    if vault.save().is_err() {
        vault.entries = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": "Could not persist the key change"})),
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// 7. GET /api/config
// ---------------------------------------------------------------------------

pub async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = match state.config.read() {
        Ok(value) => value,
        Err(_) => return Json(serde_json::json!({})),
    };
    let mut visible = config.clone();
    visible.server.admin_token_hash = visible
        .server
        .admin_token_hash
        .as_ref()
        .map(|_| "********".to_string());
    visible.server.inference_token_hash = visible
        .server
        .inference_token_hash
        .as_ref()
        .map(|_| "********".to_string());
    Json(serde_json::to_value(visible).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// 8. PUT /api/config
// ---------------------------------------------------------------------------

pub async fn update_config(
    State(state): State<AppState>,
    Json(mut new_config): Json<crate::config::SkyportConfig>,
) -> impl IntoResponse {
    let mut config = match state.config.write() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "config lock poisoned"})),
            )
        }
    };
    new_config.server.admin_token_hash = config.server.admin_token_hash.clone();
    new_config.server.inference_token_hash = config.server.inference_token_hash.clone();
    new_config.disk_fingerprint = config.disk_fingerprint.clone();
    if new_config.server.port < 1024 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": "Server port must be 1024 or higher"})),
        );
    }
    for (provider, provider_config) in &new_config.providers {
        if let Err(error) = validate_provider_config(provider, provider_config) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": error})),
            );
        }
        let credentialed = !crate::vault::Vault::is_keyless_provider(provider);
        if let Err(error) = crate::security::validate_provider_url(
            provider,
            &provider_config.base_url,
            credentialed,
        ) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": error})),
            );
        }
    }
    let previous = config.clone();
    *config = new_config;
    if save_config(&config).is_err() {
        *config = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": "Could not persist configuration"})),
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// 9. GET /api/logs
// ---------------------------------------------------------------------------

pub async fn get_logs_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let filter = match log_filter_from_params(&params) {
        Ok(filter) => filter,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error})),
            )
        }
    };
    let conn = match state.db.lock() {
        Ok(conn) => conn,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database lock poisoned"})),
            )
        }
    };
    match db::query_logs(&conn, &filter, limit, offset) {
        Ok((logs, total)) => (
            StatusCode::OK,
            Json(serde_json::json!({"logs": logs, "total": total})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// GET /api/traffic — filtered totals, a grouping breakdown, and a time series.
pub async fn get_traffic_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let filter = match log_filter_from_params(&params) {
        Ok(filter) => filter,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error})),
            )
        }
    };
    let group_by = params
        .get("group_by")
        .map(String::as_str)
        .unwrap_or("model");
    let conn = match state.db.lock() {
        Ok(conn) => conn,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database lock poisoned"})),
            )
        }
    };
    match db::traffic_report(&conn, &filter, group_by) {
        Ok(report) => (StatusCode::OK, Json(serde_json::json!(report))),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid telemetry query"})),
        ),
    }
}

fn log_filter_from_params(params: &HashMap<String, String>) -> Result<db::LogFilter, String> {
    fn text(params: &HashMap<String, String>, name: &str) -> Option<String> {
        params
            .get(name)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }
    fn number<T: std::str::FromStr>(
        params: &HashMap<String, String>,
        name: &str,
    ) -> Result<Option<T>, String> {
        params
            .get(name)
            .map(|value| value.parse().map_err(|_| format!("Invalid {name}")))
            .transpose()
    }
    Ok(db::LogFilter {
        provider: text(params, "provider"),
        model: text(params, "model"),
        key_alias: text(params, "key"),
        status: text(params, "status"),
        min_cost: number(params, "min_cost")?,
        max_cost: number(params, "max_cost")?,
        min_latency: number(params, "min_latency")?,
        max_latency: number(params, "max_latency")?,
        min_tokens: number(params, "min_tokens")?,
        max_tokens: number(params, "max_tokens")?,
        // `since` remains supported for existing dashboard callers.
        from_ms: number(params, "from")?.or(number(params, "since")?),
        to_ms: number(params, "to")?,
        query: text(params, "q"),
    })
}

// ---------------------------------------------------------------------------
// 10. GET /api/logs/stream  (SSE placeholder)
// ---------------------------------------------------------------------------

pub async fn get_log_stream(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream_state = state.clone();
    let stream =
        tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(Duration::from_secs(2)))
            .map(move |_| {
                let data = stream_state
                    .db
                    .lock()
                    .ok()
                    .and_then(|db| db::get_logs(&db, 1, 0).ok())
                    .and_then(|mut logs| logs.pop())
                    .and_then(|entry| serde_json::to_string(&entry).ok())
                    .unwrap_or_else(|| "ping".to_string());
                Ok(Event::default().event("request").data(data))
            });

    Sse::new(stream)
}

// ---------------------------------------------------------------------------
// Activity Endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AddActivityRequest {
    pub session_id: Option<String>,
    pub event_type: Option<String>,
    pub title: String,
    pub detail: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// GET /api/activity — query activity logs for the current session or overall.
pub async fn get_activity_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let filter = db::ActivityFilter {
        session_id: params.get("session_id").cloned(),
        event_type: params
            .get("type")
            .or_else(|| params.get("event_type"))
            .cloned(),
        from_ms: params
            .get("from")
            .or_else(|| params.get("since"))
            .and_then(|v| v.parse().ok()),
        to_ms: params.get("to").and_then(|v| v.parse().ok()),
        query: params.get("q").cloned(),
    };

    let conn = match state.db.lock() {
        Ok(conn) => conn,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database lock poisoned"})),
            )
        }
    };

    match db::query_activities(&conn, &filter, limit, offset) {
        Ok((activities, total)) => (
            StatusCode::OK,
            Json(serde_json::json!({"activities": activities, "total": total})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// POST /api/activity — record an activity event (e.g. from an external tool or hook).
pub async fn add_activity_handler(
    State(state): State<AppState>,
    Json(body): Json<AddActivityRequest>,
) -> impl IntoResponse {
    if body.title.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": "Title cannot be empty"})),
        );
    }

    let entry = db::ActivityEntry {
        id: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: body.session_id.unwrap_or_else(|| "default".to_string()),
        event_type: body.event_type.unwrap_or_else(|| "tool".to_string()),
        title: body.title.trim().to_string(),
        detail: body.detail,
        metadata_json: body.metadata.map(|m| m.to_string()),
    };

    let conn = match state.db.lock() {
        Ok(conn) => conn,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "database lock poisoned"})),
            )
        }
    };

    match db::log_activity(&conn, &entry) {
        Ok(id) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "id": id})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": e.to_string()})),
        ),
    }
}

/// DELETE /api/activity — clear session activity.
pub async fn clear_activity_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let session_id = params.get("session_id").map(String::as_str);

    let conn = match state.db.lock() {
        Ok(conn) => conn,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "database lock poisoned"})),
            )
        }
    };

    match db::clear_activities(&conn, session_id) {
        Ok(deleted) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "deleted": deleted})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": e.to_string()})),
        ),
    }
}

/// GET /api/activity/stream — SSE stream for real-time session activities.
pub async fn get_activity_stream(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream_state = state.clone();
    let stream = tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(
        Duration::from_millis(1500),
    ))
    .map(move |_| {
        let data = stream_state
            .db
            .lock()
            .ok()
            .and_then(|db| db::query_activities(&db, &db::ActivityFilter::default(), 5, 0).ok())
            .and_then(|(activities, _)| serde_json::to_string(&activities).ok())
            .unwrap_or_else(|| "[]".to_string());
        Ok(Event::default().event("activity").data(data))
    });

    Sse::new(stream)
}

/// GET /api/providers
pub async fn get_providers(State(state): State<AppState>) -> impl IntoResponse {
    let config = match state.config.read() {
        Ok(value) => value,
        Err(_) => return Json(serde_json::json!({})),
    };
    Json(serde_json::json!(config.providers))
}

/// Classify a discovered model's cost tier. Verified August 2026:
/// - NVIDIA NIM hosts its catalog free for prototyping (~40 RPM, no
///   per-token price) — developer.nvidia.com/nim
/// - Groq keeps a genuine free tier (no card, ~30 RPM + daily quotas) —
///   console.groq.com/docs/rate-limits
/// - Gemini retains free-tier access for Flash/Flash-Lite only; Pro models
///   are paid-only — ai.google.dev/gemini-api/docs/rate-limits
/// - OpenRouter prices per model: free variants carry a ":free" suffix and
///   a zero prompt price in the discovery payload
fn model_tier(provider: &str, model_id: &str, pricing: Option<&serde_json::Value>) -> &'static str {
    if crate::vault::Vault::is_keyless_provider(provider) {
        return "local";
    }
    if matches!(provider, "nvidia" | "groq") {
        return "free";
    }
    if provider == "gemini" {
        let id = model_id.to_lowercase();
        if id.contains("flash") {
            return "free";
        }
    }
    if model_id.ends_with(":free") {
        return "free";
    }
    if let Some(prompt_price) = pricing
        .and_then(|value| value.get("prompt"))
        .and_then(|value| value.as_str())
        .and_then(|text| text.parse::<f64>().ok())
    {
        if prompt_price == 0.0 {
            return "free";
        }
    }
    "paid"
}

/// Fetch a provider's model-id list in its native wire format. Returns None
/// when the request fails or returns a non-success status.
async fn fetch_model_catalog(
    state: &AppState,
    provider_id: &str,
    base_url: &str,
    format: &str,
    api_key: &str,
) -> Option<Vec<String>> {
    let credentialed = !api_key.is_empty();
    let mut base =
        crate::security::validate_provider_url(provider_id, base_url, credentialed).ok()?;
    let native_shape = format == "gemini" || base.path().trim_end_matches('/').ends_with("/openai");
    if base.path().trim_end_matches('/').ends_with("/openai") {
        base.path_segments_mut().ok()?.pop_if_empty().pop();
    }
    let url = match format {
        "anthropic" => crate::security::append_url_path(&base, "v1/models").ok()?,
        "gemini" => crate::security::append_url_path(&base, "v1beta/models").ok()?,
        _ => crate::security::append_url_path(&base, "models").ok()?,
    };
    crate::security::validate_resolved_destination(provider_id, &url, credentialed)
        .await
        .ok()?;
    let mut request = state.http_client.get(url).timeout(Duration::from_secs(10));
    if !api_key.is_empty() {
        request = match format {
            "anthropic" => request
                .header("x-api-key", api_key)
                .header("anthropic-version", "2023-06-01"),
            "gemini" => request.header("x-goog-api-key", api_key),
            _ if native_shape => request.header("x-goog-api-key", api_key),
            _ => request.bearer_auth(api_key),
        };
    }
    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let payload: serde_json::Value =
        serde_json::from_slice(&crate::security::read_upstream_body(response).await.ok()?).ok()?;
    let ids: Vec<String> = if native_shape {
        payload
            .get("models")
            .and_then(|value| value.as_array())
            .into_iter()
            .flatten()
            .filter_map(|model| model.get("name").and_then(|value| value.as_str()))
            .map(|name| name.strip_prefix("models/").unwrap_or(name).to_owned())
            .collect()
    } else {
        payload
            .get("data")
            .and_then(|value| value.as_array())
            .into_iter()
            .flatten()
            .filter_map(|model| model.get("id").and_then(|value| value.as_str()))
            .map(str::to_owned)
            .collect()
    };
    Some(ids)
}

/// POST /api/models/refresh — re-discover the model catalog from every
/// enabled provider. Also runs quietly at boot so /v1/models is useful
/// without a manual step.
pub async fn refresh_catalog(State(state): State<AppState>) -> impl IntoResponse {
    let providers: Vec<(String, String)> = match state.config.read() {
        Ok(config) => config
            .providers
            .iter()
            .filter(|(_, provider)| provider.enabled)
            .map(|(id, provider)| (id.clone(), provider.base_url.clone()))
            .collect(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "config lock poisoned"})),
            )
        }
    };

    let mut discovered: Vec<(String, usize)> = Vec::new();
    for (provider_id, base_url) in providers {
        let Ok(decision) = state.router.select_key(&provider_id) else {
            continue;
        };
        // With a large bundled catalog most providers have no key yet; a
        // keyless non-local upstream cannot list models, so skip the call.
        if decision.api_key.is_empty() && !crate::vault::Vault::is_keyless_provider(&provider_id) {
            continue;
        }
        let api_key = decision.api_key.clone();
        let format = decision.format.clone();
        let Some(ids) =
            fetch_model_catalog(&state, &provider_id, &base_url, &format, &api_key).await
        else {
            continue;
        };
        let entries: Vec<crate::api::CatalogModel> = ids
            .into_iter()
            .map(|id| crate::api::CatalogModel {
                tier: model_tier(&provider_id, &id, None).to_string(),
                id,
            })
            .collect();
        let count = entries.len();
        if count > 0 {
            if let Ok(mut catalog) = state.catalog.write() {
                catalog.insert(provider_id.clone(), entries);
            }
            discovered.push((provider_id, count));
        }
    }

    let total: usize = discovered.iter().map(|(_, count)| count).sum();
    let providers: serde_json::Map<String, serde_json::Value> = discovered
        .into_iter()
        .map(|(id, count)| (id, serde_json::json!(count)))
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "total_models": total, "providers": providers})),
    )
}

/// GET /api/models/catalog — the discovered catalog with paid/free tiers for
/// the dashboard's model browser.
pub async fn get_catalog(State(state): State<AppState>) -> impl IntoResponse {
    let (catalog, config) = match (state.catalog.read(), state.config.read()) {
        (Ok(catalog), Ok(config)) => (catalog, config),
        _ => return Json(serde_json::json!([])),
    };
    let entries: Vec<serde_json::Value> = catalog
        .iter()
        .filter(|(provider, _)| {
            config
                .providers
                .get(*provider)
                .is_some_and(|provider| provider.enabled)
        })
        .flat_map(|(provider, models)| {
            models.iter().map(move |model| {
                serde_json::json!({
                    "provider": provider,
                    "id": model.id,
                    "tier": model.tier,
                })
            })
        })
        .collect::<Vec<serde_json::Value>>();
    Json(serde_json::json!(entries))
}

/// POST /api/providers
pub async fn update_provider(
    State(state): State<AppState>,
    Json(body): Json<ProviderUpdateRequest>,
) -> impl IntoResponse {
    let credentialed = !crate::vault::Vault::is_keyless_provider(&body.id);
    if let Err(error) = validate_provider_config(&body.id, &body.config) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": error})),
        );
    }
    if let Err(error) =
        crate::security::validate_provider_url(&body.id, &body.config.base_url, credentialed)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": error})),
        );
    }
    let mut config = match state.config.write() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "config lock poisoned"})),
            )
        }
    };
    // Reject providers that would duplicate an existing upstream URL: same
    // endpoint behind two ids only causes confusing routing and catalog noise.
    let new_url = body.config.base_url.trim_end_matches('/').to_lowercase();
    if let Some((existing_id, existing)) = config.providers.iter().find(|(id, provider)| {
        *id != &body.id && provider.base_url.trim_end_matches('/').to_lowercase() == new_url
    }) {
        return (
            StatusCode::CONFLICT,
            Json(
                serde_json::json!({"ok": false, "error": format!("a provider with this url already exists: {} ({})", existing.name, existing_id)}),
            ),
        );
    }
    let previous = config.clone();
    config.providers.insert(body.id, body.config);
    match save_config(&config) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(_) => {
            *config = previous;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({"ok": false, "error": "Could not persist provider configuration"}),
                ),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// 11. GET /api/stats
// ---------------------------------------------------------------------------

pub async fn get_stats_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let range = params
        .get("range")
        .cloned()
        .unwrap_or_else(|| "24h".to_string());
    if !["1h", "6h", "24h", "7d", "30d", "90d"].contains(&range.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid range: {range}")})),
        );
    }

    let conn = match state.db.lock() {
        Ok(conn) => conn,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database lock poisoned"})),
            )
        }
    };
    match db::get_stats(&conn, &range) {
        Ok(stats) => (StatusCode::OK, Json(serde_json::json!(stats))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// ---------------------------------------------------------------------------
// 12. GET /api/budgets
// ---------------------------------------------------------------------------

pub async fn get_budgets(State(state): State<AppState>) -> impl IntoResponse {
    let config = match state.config.read() {
        Ok(value) => value,
        Err(_) => return Json(serde_json::json!({})),
    };
    Json(serde_json::to_value(&config.budgets).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// 13. PUT /api/budgets
// ---------------------------------------------------------------------------

pub async fn update_budgets(
    State(state): State<AppState>,
    Json(budgets): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut config = match state.config.write() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "config lock poisoned"})),
            )
        }
    };
    let previous = config.clone();
    match serde_json::from_value::<HashMap<String, crate::config::BudgetConfig>>(budgets) {
        Ok(b)
            if b.iter().all(|(scope, budget)| {
                !scope.is_empty()
                    && scope.len() <= 129
                    && budget
                        .monthly_cap_usd
                        .is_none_or(|cap| cap.is_finite() && cap > 0.0)
                    && budget
                        .daily_cap_usd
                        .is_none_or(|cap| cap.is_finite() && cap > 0.0)
                    && budget.max_rpm.is_none_or(|rpm| rpm > 0)
            }) =>
        {
            config.budgets = b
        }
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"ok": false, "error": "Budget scopes, caps, or rate limits are invalid"}),
                ),
            );
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": e.to_string()})),
            );
        }
    }
    if save_config(&config).is_err() {
        *config = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": "Could not persist budgets"})),
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// GET /api/rate-limit
// ---------------------------------------------------------------------------

pub async fn get_rate_limit(State(state): State<AppState>) -> impl IntoResponse {
    let config = match state.config.read() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "config lock poisoned"})),
            )
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::to_value(&config.rate_limit).unwrap_or_default()),
    )
}

// ---------------------------------------------------------------------------
// PUT /api/rate-limit
// ---------------------------------------------------------------------------

pub async fn update_rate_limit(
    State(state): State<AppState>,
    Json(body): Json<crate::config::RateLimitConfig>,
) -> impl IntoResponse {
    if body.max_rpm.is_some_and(|rpm| rpm == 0) || body.max_rps.is_some_and(|rps| rps == 0) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": "Rate limits must be greater than 0"})),
        );
    }
    let mut config = match state.config.write() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "config lock poisoned"})),
            )
        }
    };
    let previous = config.clone();
    config.rate_limit = body;
    if save_config(&config).is_err() {
        *config = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok": false, "error": "Could not persist rate limits"})),
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// 14. POST /api/providers/test
// ---------------------------------------------------------------------------

pub async fn test_provider(
    State(state): State<AppState>,
    Json(body): Json<TestProviderRequest>,
) -> impl IntoResponse {
    let (base_url, format) = {
        let config = match state.config.read() {
            Ok(value) => value,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"ok": false, "error": "config lock poisoned"})),
                )
            }
        };
        match config.providers.get(&body.provider) {
            Some(provider) if provider.enabled => (
                provider.base_url.clone(),
                provider.wire_format().to_string(),
            ),
            Some(_) => {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"ok": false, "error": "Provider is disabled"})),
                )
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(
                        serde_json::json!({"ok": false, "error": format!("provider '{}' not found in config", body.provider)}),
                    ),
                )
            }
        }
    };

    let credential = {
        let vault = match state.vault.read() {
            Ok(value) => value,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"ok": false, "error": "vault lock poisoned"})),
                )
            }
        };
        vault
            .get_keys_for_provider(&body.provider)
            .into_iter()
            .find(|key| {
                key.enabled
                    && key
                        .cooldown_until
                        .is_none_or(|until| until < chrono::Utc::now())
            })
            .map(|key| (key.key_alias.clone(), key.api_key.clone()))
    };

    // Native-wire-format providers (Anthropic, Gemini) require the key for the
    // models endpoint itself, so a successful catalog fetch proves access and
    // no probe request is needed.
    let native_format = matches!(format.as_str(), "anthropic" | "gemini");
    if native_format {
        let start = std::time::Instant::now();
        let api_key = credential
            .as_ref()
            .map(|(_, key)| key.as_str())
            .unwrap_or("");
        return match fetch_model_catalog(&state, &body.provider, &base_url, &format, api_key).await
        {
            Some(models) => {
                let latency_ms = start.elapsed().as_millis();
                let entries: Vec<crate::api::CatalogModel> = models
                    .iter()
                    .map(|id| crate::api::CatalogModel {
                        tier: model_tier(&body.provider, id, None).to_string(),
                        id: id.clone(),
                    })
                    .collect();
                if let Ok(mut catalog) = state.catalog.write() {
                    catalog.insert(body.provider.clone(), entries);
                }
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "ok": true,
                        "latency_ms": latency_ms,
                        "authenticated": true,
                        "key_alias": credential.as_ref().map(|(alias, _)| alias.as_str()),
                        "models": models
                    })),
                )
            }
            None => {
                if credential.is_none() && !crate::vault::Vault::is_keyless_provider(&body.provider)
                {
                    ok_json(
                        start.elapsed().as_millis(),
                        None,
                        vec![],
                        "provider is reachable, but no enabled API key is configured to validate access",
                    )
                } else {
                    err_json(
                        "model catalog request failed (check base URL and API key)".to_string(),
                    )
                }
            }
        };
    }

    // 1. Reachability + optional catalog fetch. Many providers (e.g. NVIDIA NIM)
    //    serve /models without authentication, so a 200 here proves reachability
    //    but says nothing about the credential. Google Gemini's OpenAI-compatible
    //    endpoint exposes no /models route at all (404), so its native REST
    //    catalog is used instead (403 without a key, i.e. reachable-but-unauthed).
    let credentialed = credential.is_some();
    let provider_base =
        match crate::security::validate_provider_url(&body.provider, &base_url, credentialed) {
            Ok(url) => url,
            Err(error) => return err_json(error),
        };
    let use_native_models = provider_base
        .path()
        .trim_end_matches('/')
        .ends_with("/openai");
    let mut base = provider_base.clone();
    if use_native_models {
        let _ = base.path_segments_mut().map(|mut segments| {
            segments.pop_if_empty().pop();
        });
    }
    let url = match crate::security::append_url_path(&base, "models") {
        Ok(url) => url,
        Err(error) => return err_json(error),
    };
    if let Err(error) =
        crate::security::validate_resolved_destination(&body.provider, &url, credentialed).await
    {
        return err_json(error);
    }
    let start = std::time::Instant::now();
    let mut models_request = state.http_client.get(url).timeout(Duration::from_secs(10));
    match &credential {
        Some((_, api_key)) if use_native_models => {
            models_request = models_request.header("x-goog-api-key", api_key);
        }
        Some((_, api_key)) => {
            models_request = models_request.bearer_auth(api_key);
        }
        None => {}
    }

    let (latency_ms, model_ids) = match models_request.send().await {
        Ok(resp) if resp.status().is_success() => {
            let payload = match crate::security::read_upstream_body(resp).await {
                Ok(body) => serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default(),
                Err(error) => return err_json(error),
            };
            let ids: Vec<String> = if use_native_models {
                payload
                    .get("models")
                    .and_then(|value| value.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|model| model.get("name").and_then(|value| value.as_str()))
                    .map(|name| name.strip_prefix("models/").unwrap_or(name).to_owned())
                    .collect()
            } else {
                payload
                    .get("data")
                    .and_then(|value| value.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|model| model.get("id").and_then(|value| value.as_str()))
                    .map(str::to_owned)
                    .collect()
            };
            (start.elapsed().as_millis(), ids)
        }
        Ok(resp) => {
            let status = resp.status();
            // Without a key, a 401/403 on /models still proves reachability but
            // not access: report it honestly and never leak the model catalog.
            if credential.is_none()
                && !crate::vault::Vault::is_keyless_provider(&body.provider)
                && matches!(
                    status,
                    reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
                )
            {
                return ok_json(
                    start.elapsed().as_millis(),
                    None,
                    vec![],
                    "provider is reachable, but no enabled API key is configured to validate access",
                );
            }
            return err_json(format!("Upstream returned status {}", status.as_u16()));
        }
        Err(error) => return err_json(crate::security::safe_network_error(&error).to_string()),
    };

    // 2. Validate the credential. /models may be public, so only credentials
    //    that survive a real authenticated request count as valid; models are
    //    only reported once access is proven.
    let keyless = crate::vault::Vault::is_keyless_provider(&body.provider);
    let (authenticated, key_alias) =
        match &credential {
            Some((alias, api_key)) => {
                let first_model = model_ids
                    .first()
                    .map(String::as_str)
                    .unwrap_or("gpt-3.5-turbo");
                let probe = serde_json::json!({
                    "model": first_model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1
                });
                let probe_url =
                    match crate::security::append_url_path(&provider_base, "chat/completions") {
                        Ok(url) => url,
                        Err(error) => return err_json(error),
                    };
                let probe_resp = state
                    .http_client
                    .post(probe_url)
                    .bearer_auth(api_key)
                    .json(&probe)
                    .timeout(Duration::from_secs(15))
                    .send()
                    .await;
                match probe_resp {
                    Ok(resp) if resp.status().is_success() => (true, Some(alias.as_str())),
                    Ok(resp)
                        if matches!(
                            resp.status(),
                            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
                        ) =>
                    {
                        return err_json("API key rejected by provider".to_string());
                    }
                    Ok(_resp) => {
                        // Not an auth failure (e.g. 400/429/5xx): the key is accepted.
                        (true, Some(alias.as_str()))
                    }
                    Err(error) => {
                        return err_json(crate::security::safe_network_error(&error).to_string())
                    }
                }
            }
            None if keyless => (true, Some("local")),
            None => return ok_json(
                latency_ms,
                None,
                vec![],
                "provider is reachable, but no enabled API key is configured to validate access",
            ),
        };

    // Feed the aggregated /v1/models catalog with what this discovery found.
    if authenticated {
        let entries: Vec<crate::api::CatalogModel> = model_ids
            .iter()
            .map(|id| crate::api::CatalogModel {
                tier: model_tier(&body.provider, id, None).to_string(),
                id: id.clone(),
            })
            .collect();
        if let Ok(mut catalog) = state.catalog.write() {
            catalog.insert(body.provider.clone(), entries);
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "latency_ms": latency_ms,
            "authenticated": authenticated,
            "key_alias": key_alias,
            "models": if authenticated { model_ids } else { Vec::<String>::new() }
        })),
    )
}

fn ok_json(
    latency_ms: u128,
    key_alias: Option<&str>,
    models: Vec<&str>,
    warning: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "latency_ms": latency_ms,
            "authenticated": false,
            "key_alias": key_alias,
            "models": models,
            "warning": warning
        })),
    )
}

fn err_json(error: String) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": false, "error": error})),
    )
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_provider_config(
    id: &str,
    config: &crate::config::ProviderConfig,
) -> Result<(), &'static str> {
    if !valid_identifier(id) {
        return Err("Invalid provider id");
    }
    if config.name.trim().is_empty() || config.name.len() > 128 {
        return Err("Provider name is empty or too long");
    }
    if !matches!(
        config.format.as_deref(),
        None | Some("openai" | "anthropic" | "gemini" | "responses")
    ) {
        return Err("Unsupported provider format");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{default_config, ProviderConfig},
        router::Router,
        vault::{Vault, VaultEntry},
    };
    use axum::response::IntoResponse;
    use serde_json::Value;
    use std::sync::{Arc, Mutex, RwLock};

    #[test]
    fn model_tier_matches_provider_free_tiers() {
        let free_pricing = serde_json::json!({"prompt": "0"});
        let paid_pricing = serde_json::json!({"prompt": "0.27"});

        assert_eq!(
            model_tier("nvidia", "nvidia/nemotron-3-ultra-550b-a55b", None),
            "free"
        );
        assert_eq!(model_tier("groq", "llama-3.3-70b-versatile", None), "free");
        assert_eq!(model_tier("gemini", "gemini-3.5-flash", None), "free");
        assert_eq!(model_tier("gemini", "gemini-3-pro", None), "paid");
        assert_eq!(model_tier("lmstudio", "google/gemma-4-e4b", None), "local");
        assert_eq!(model_tier("ollama", "llama3.2", None), "local");
        assert_eq!(model_tier("openrouter", "openai/gpt-5:free", None), "free");
        assert_eq!(
            model_tier("openrouter", "openai/gpt-5", Some(&paid_pricing)),
            "paid"
        );
        assert_eq!(
            model_tier("openrouter", "meta/llama-x", Some(&free_pricing)),
            "free"
        );
        assert_eq!(model_tier("openai", "gpt-4o", None), "paid");
    }

    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn provider_test_authenticates_and_returns_models() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer provider-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "data": [{"id": "model-a"}, {"id": "model-b"}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer provider-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": "pong"}}]
            })))
            .mount(&server)
            .await;

        let mut config = default_config();
        config.providers.clear();
        config.providers.insert(
            "mock".to_string(),
            ProviderConfig {
                name: "Mock".to_string(),
                base_url: format!("{}/v1", server.uri()),
                enabled: true,
                round_robin: false,
                format: None,
            },
        );
        let vault = Arc::new(RwLock::new(Vault {
            entries: vec![VaultEntry {
                key_alias: "primary".to_string(),
                provider: "mock".to_string(),
                api_key: "provider-key".to_string(),
                priority: 1,
                enabled: true,
                ..Default::default()
            }],
            master_key: vec![0; 32],
        }));
        let config = Arc::new(RwLock::new(config));
        let state = AppState {
            router: Arc::new(Router::new(vault.clone(), config.clone())),
            config,
            vault,
            db: Arc::new(Mutex::new(rusqlite::Connection::open_in_memory().unwrap())),
            http_client: reqwest::Client::new(),
            start_time: std::time::Instant::now(),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rate_limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
            catalog: Arc::new(RwLock::new(std::collections::HashMap::new())),
            auth_sessions: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        };

        let response = test_provider(
            State(state),
            Json(TestProviderRequest {
                provider: "mock".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["key_alias"], "primary");
        assert_eq!(payload["authenticated"], true);
        assert_eq!(payload["models"], serde_json::json!(["model-a", "model-b"]));
    }

    #[tokio::test]
    async fn provider_test_reports_reachable_without_a_key() {
        // NVIDIA NIM serves /models publicly (200 + catalog) even with no key.
        // The test must prove reachability but must NOT surface the catalog.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "data": [{"id": "model-a"}, {"id": "model-b"}, {"id": "model-c"}]
            })))
            .mount(&server)
            .await;

        let mut config = default_config();
        config.providers.clear();
        config.providers.insert(
            "mock".to_string(),
            ProviderConfig {
                name: "Mock".to_string(),
                base_url: format!("{}/v1", server.uri()),
                enabled: true,
                round_robin: false,
                format: None,
            },
        );
        let vault = Arc::new(RwLock::new(Vault {
            entries: vec![],
            master_key: vec![0; 32],
        }));
        let config = Arc::new(RwLock::new(config));
        let state = AppState {
            router: Arc::new(Router::new(vault.clone(), config.clone())),
            config,
            vault,
            db: Arc::new(Mutex::new(rusqlite::Connection::open_in_memory().unwrap())),
            http_client: reqwest::Client::new(),
            start_time: std::time::Instant::now(),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rate_limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
            catalog: Arc::new(RwLock::new(std::collections::HashMap::new())),
            auth_sessions: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        };

        let response = test_provider(
            State(state),
            Json(TestProviderRequest {
                provider: "mock".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["authenticated"], false);
        assert_eq!(payload["models"], serde_json::json!([]));
        assert!(payload["warning"].as_str().unwrap().contains("reachable"));
    }

    #[tokio::test]
    async fn provider_test_rejects_a_bad_key() {
        // A public catalog + a rejected credential must fail the test, not pass
        // as "reachable" with 100+ unusable models.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "data": [{"id": "model-a"}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer wrong-key"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {"message": "invalid_api_key"}
            })))
            .mount(&server)
            .await;

        let mut config = default_config();
        config.providers.clear();
        config.providers.insert(
            "mock".to_string(),
            ProviderConfig {
                name: "Mock".to_string(),
                base_url: format!("{}/v1", server.uri()),
                enabled: true,
                round_robin: false,
                format: None,
            },
        );
        let vault = Arc::new(RwLock::new(Vault {
            entries: vec![VaultEntry {
                key_alias: "primary".to_string(),
                provider: "mock".to_string(),
                api_key: "wrong-key".to_string(),
                priority: 1,
                enabled: true,
                ..Default::default()
            }],
            master_key: vec![0; 32],
        }));
        let config = Arc::new(RwLock::new(config));
        let state = AppState {
            router: Arc::new(Router::new(vault.clone(), config.clone())),
            config,
            vault,
            db: Arc::new(Mutex::new(rusqlite::Connection::open_in_memory().unwrap())),
            http_client: reqwest::Client::new(),
            start_time: std::time::Instant::now(),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rate_limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
            catalog: Arc::new(RwLock::new(std::collections::HashMap::new())),
            auth_sessions: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        };

        let response = test_provider(
            State(state),
            Json(TestProviderRequest {
                provider: "mock".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["ok"], false);
        assert!(payload["error"].as_str().unwrap().contains("rejected"));
    }

    #[tokio::test]
    async fn provider_test_uses_native_catalog_for_openai_style_provider() {
        // Google Gemini's OpenAI-compatible endpoint has no /models route, so the
        // test must fall back to the native REST catalog and strip the
        // "models/" prefix from model names.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .and(header("x-goog-api-key", "provider-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [
                    {"name": "models/gemini-2.5-flash"},
                    {"name": "models/gemini-2.5-pro"}
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1beta/openai/chat/completions"))
            .and(header("authorization", "Bearer provider-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": "pong"}}]
            })))
            .mount(&server)
            .await;

        let mut config = default_config();
        config.providers.clear();
        config.providers.insert(
            "mock".to_string(),
            ProviderConfig {
                name: "Mock".to_string(),
                base_url: format!("{}/v1beta/openai", server.uri()),
                enabled: true,
                round_robin: false,
                format: None,
            },
        );
        let vault = Arc::new(RwLock::new(Vault {
            entries: vec![VaultEntry {
                key_alias: "primary".to_string(),
                provider: "mock".to_string(),
                api_key: "provider-key".to_string(),
                priority: 1,
                enabled: true,
                ..Default::default()
            }],
            master_key: vec![0; 32],
        }));
        let config = Arc::new(RwLock::new(config));
        let state = AppState {
            router: Arc::new(Router::new(vault.clone(), config.clone())),
            config,
            vault,
            db: Arc::new(Mutex::new(rusqlite::Connection::open_in_memory().unwrap())),
            http_client: reqwest::Client::new(),
            start_time: std::time::Instant::now(),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rate_limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
            catalog: Arc::new(RwLock::new(std::collections::HashMap::new())),
            auth_sessions: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        };

        let response = test_provider(
            State(state),
            Json(TestProviderRequest {
                provider: "mock".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["authenticated"], true);
        assert_eq!(
            payload["models"],
            serde_json::json!(["gemini-2.5-flash", "gemini-2.5-pro"])
        );
    }
}
