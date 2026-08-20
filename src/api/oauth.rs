use axum::{
    extract::{Query, State},
    http::{header, HeaderName, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::AppState;
use crate::auth::{
    self, account_label, find_provider, parse_tokens, pkce_pair, token_expiry, AuthFlow,
    AuthTokens, BodyFormat, BrowserOutcome, PendingKind, PendingSession, SubscriptionProvider,
};
use crate::config::ProviderConfig;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuthRequest {
    pub provider: String,
}

#[derive(Deserialize)]
pub struct AuthPollRequest {
    pub provider: String,
    pub flow_id: String,
}

#[derive(Deserialize)]
pub struct AuthPasteRequest {
    pub provider: String,
    pub api_key: String,
    #[serde(default)]
    pub alias: Option<String>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// GET /api/auth — linked status for every subscription provider
// ---------------------------------------------------------------------------

pub async fn get_auth_status(State(state): State<AppState>) -> impl IntoResponse {
    let vault = match state.vault.read() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "vault lock poisoned"})),
            )
        }
    };
    let config = match state.config.read() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "config lock poisoned"})),
            )
        }
    };
    let mut providers = serde_json::Map::new();
    for provider in auth::subscription_providers() {
        let linked = vault.oauth_entry(provider.provider_id);
        let enabled = config
            .providers
            .get(provider.provider_id)
            .is_some_and(|p| p.enabled);
        providers.insert(
            provider.id.to_string(),
            serde_json::json!({
                "label": provider.label,
                "copy": provider.copy,
                "model_hint": provider.model_hint,
                "flow": provider.flow,
                "verify_url": provider.verify_url,
                "linked": linked.is_some(),
                "account": linked.and_then(|entry| entry.oauth_extra.as_ref())
                    .and_then(|extra| extra.get("account"))
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
                "expires_at": linked.and_then(|entry| entry.expires_at),
                "config_enabled": enabled,
                "provider_id": provider.provider_id,
            }),
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"providers": providers})),
    )
}

// ---------------------------------------------------------------------------
// POST /api/auth/connect — start a sign-in flow
// ---------------------------------------------------------------------------

pub async fn connect(
    State(state): State<AppState>,
    Json(body): Json<AuthRequest>,
) -> impl IntoResponse {
    let Some(provider) = find_provider(&body.provider) else {
        return err("unknown subscription provider").into_response();
    };
    match provider.flow {
        AuthFlow::Paste => (
            StatusCode::OK,
            Json(serde_json::json!({"mode": "paste", "help": provider.help, "verify_url": provider.verify_url})),
        )
            .into_response(),
        AuthFlow::Unavailable => (
            StatusCode::OK,
            Json(serde_json::json!({"mode": "unavailable", "help": provider.help, "verify_url": provider.verify_url})),
        )
            .into_response(),
        AuthFlow::Device => device_connect(&state, provider).await.into_response(),
        AuthFlow::Browser => browser_connect(&state, provider).into_response(),
    }
}

async fn device_connect(
    state: &AppState,
    provider: &'static SubscriptionProvider,
) -> (StatusCode, Json<serde_json::Value>) {
    let device = provider.device.as_ref().expect("device flow endpoints");
    let request = state
        .http_client
        .post(device.device_code_url)
        .header("accept", "application/json");
    let response = if device.form == BodyFormat::Json {
        request
            .json(&serde_json::json!({"client_id": provider.client_id, "scope": device.scope}))
            .send()
            .await
    } else {
        request
            .form(&[("client_id", provider.client_id), ("scope", device.scope)])
            .send()
            .await
    };
    match response {
        Ok(response) if response.status().is_success() => {
            let value = match auth::read_oauth_json(response).await {
                Ok(value) => value,
                Err(()) => return err("device code response was invalid"),
            };
            let Some(user_code) = value["user_code"].as_str().or(value["usercode"].as_str()) else {
                return err("device code response missing user_code");
            };
            // OpenAI calls it device_auth_id; RFC 8628 calls it device_code.
            let device_code = value["device_code"]
                .as_str()
                .or(value["device_auth_id"].as_str())
                .unwrap_or_default();
            if device_code.is_empty() {
                return err("device code response missing device_code");
            }
            let interval = value["interval"].as_u64().unwrap_or(5).max(1);
            let expires_in = value["expires_in"].as_u64().unwrap_or(900);
            let flow_id = uuid::Uuid::new_v4().simple().to_string();
            let session = PendingSession {
                provider: provider.id.to_string(),
                started_secs: now_secs(),
                kind: PendingKind::Device {
                    device_auth_id: device_code.to_string(),
                    user_code: user_code.to_string(),
                    interval,
                    expires_in_secs: expires_in,
                },
            };
            insert_session(state, flow_id.clone(), session);
            let verification_uri = value["verification_uri_complete"]
                .as_str()
                .or(value["verification_uri"].as_str())
                .unwrap_or(device.verification_uri)
                .to_string();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "mode": "device",
                    "flow_id": flow_id,
                    "verification_uri": verification_uri,
                    "user_code": user_code,
                    "interval": interval,
                    "expires_in": expires_in,
                    "help": provider.help,
                    "verify_url": provider.verify_url,
                })),
            )
        }
        Ok(response) => {
            // ChatGPT returns 404 when the Codex device-auth setting is off.
            let status = response.status();
            let mut message = format!("device code request rejected (HTTP {})", status.as_u16());
            if provider.id == "chatgpt" {
                message = format!(
                    "{message}; enable device code authentication for Codex in ChatGPT settings"
                );
            }
            err(&message)
        }
        Err(_) => err("device code request failed"),
    }
}

fn browser_connect(
    state: &AppState,
    provider: &'static SubscriptionProvider,
) -> (StatusCode, Json<serde_json::Value>) {
    let browser = provider.browser.as_ref().expect("browser flow endpoints");
    let (verifier, challenge) = pkce_pair();
    let flow_id = uuid::Uuid::new_v4().simple().to_string();
    let params: Vec<(String, String)> = vec![
        ("response_type".into(), "code".into()),
        ("client_id".into(), provider.client_id.into()),
        ("redirect_uri".into(), browser.redirect_uri.to_string()),
        ("scope".into(), browser.scope.to_string()),
        ("state".into(), flow_id.clone()),
        ("code_challenge".into(), challenge),
        ("code_challenge_method".into(), "S256".into()),
    ];
    let authorize_url = format!(
        "{}?{}",
        browser.authorize_url,
        params
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    );
    let session = PendingSession {
        provider: provider.id.to_string(),
        started_secs: now_secs(),
        kind: PendingKind::Browser {
            verifier: Some(verifier),
            outcome: None,
        },
    };
    insert_session(state, flow_id.clone(), session);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "mode": "browser",
            "flow_id": flow_id,
            "authorize_url": authorize_url,
            "redirect_uri": browser.redirect_uri,
            "help": provider.help,
        })),
    )
}

fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// POST /api/auth/poll — advance a pending flow one step
// ---------------------------------------------------------------------------

pub async fn poll(
    State(state): State<AppState>,
    Json(body): Json<AuthPollRequest>,
) -> impl IntoResponse {
    let Some(provider) = find_provider(&body.provider) else {
        return err("unknown subscription provider");
    };
    let session = {
        let sessions = match state.auth_sessions.read() {
            Ok(value) => value,
            Err(_) => return err("auth session lock poisoned"),
        };
        sessions.get(&body.flow_id).cloned()
    };
    let Some(session) = session else {
        return err("auth flow expired — start a new sign-in");
    };
    if session.provider != body.provider {
        return err("flow/provider mismatch");
    }
    let alive = match &session.kind {
        PendingKind::Device {
            expires_in_secs, ..
        } => now_secs().saturating_sub(session.started_secs) < *expires_in_secs,
        PendingKind::Browser { .. } => now_secs().saturating_sub(session.started_secs) < 900,
    };
    if !alive {
        drop_session(&state, &body.flow_id);
        return (
            StatusCode::OK,
            Json(
                serde_json::json!({"status": "expired", "message": "authorization window expired — start again"}),
            ),
        );
    }
    match session.kind {
        PendingKind::Device {
            device_auth_id,
            user_code,
            interval,
            ..
        } => match poll_device_step(&state, provider, &device_auth_id, &user_code).await {
            DeviceStep::Pending => (
                StatusCode::OK,
                Json(serde_json::json!({"status": "pending", "interval": interval})),
            ),
            DeviceStep::Failed(message) => {
                drop_session(&state, &body.flow_id);
                (
                    StatusCode::OK,
                    Json(serde_json::json!({"status": "failed", "message": message})),
                )
            }
            DeviceStep::Tokens(tokens) => {
                drop_session(&state, &body.flow_id);
                match finish_login(&state, provider, &tokens).await {
                    Ok(label) => (
                        StatusCode::OK,
                        Json(serde_json::json!({"status": "done", "account": label})),
                    ),
                    Err(message) => (
                        StatusCode::OK,
                        Json(serde_json::json!({"status": "failed", "message": message})),
                    ),
                }
            }
        },
        PendingKind::Browser { outcome, .. } => match outcome {
            Some(BrowserOutcome::Done(tokens)) => {
                drop_session(&state, &body.flow_id);
                match finish_login(&state, provider, &tokens).await {
                    Ok(label) => (
                        StatusCode::OK,
                        Json(serde_json::json!({"status": "done", "account": label})),
                    ),
                    Err(message) => (
                        StatusCode::OK,
                        Json(serde_json::json!({"status": "failed", "message": message})),
                    ),
                }
            }
            Some(BrowserOutcome::Failed(message)) => {
                drop_session(&state, &body.flow_id);
                (
                    StatusCode::OK,
                    Json(serde_json::json!({"status": "failed", "message": message})),
                )
            }
            None => (
                StatusCode::OK,
                Json(serde_json::json!({"status": "pending"})),
            ),
        },
    }
}

enum DeviceStep {
    Pending,
    Failed(String),
    Tokens(AuthTokens),
}

/// One poll attempt against the provider's device-flow token endpoint.
async fn poll_device_step(
    state: &AppState,
    provider: &'static SubscriptionProvider,
    device_auth_id: &str,
    user_code: &str,
) -> DeviceStep {
    let device = provider.device.as_ref().expect("device flow endpoints");
    match provider.id {
        // ChatGPT's flow: polling returns an authorization_code, which is then
        // exchanged at the standard token endpoint. 403/404 = still pending.
        "chatgpt" => {
            let response = state
                .http_client
                .post("https://auth.openai.com/api/accounts/deviceauth/token")
                .header("accept", "application/json")
                .json(&serde_json::json!({
                    "device_auth_id": device_auth_id,
                    "user_code": user_code,
                }))
                .send()
                .await;
            match response {
                Ok(response)
                    if response.status() == StatusCode::FORBIDDEN
                        || response.status() == StatusCode::NOT_FOUND =>
                {
                    DeviceStep::Pending
                }
                Ok(response) if response.status().is_success() => {
                    let value = match auth::read_oauth_json(response).await {
                        Ok(value) => value,
                        Err(()) => {
                            return DeviceStep::Failed("device poll response was invalid".into())
                        }
                    };
                    let Some(code) = value["authorization_code"].as_str() else {
                        return DeviceStep::Failed(
                            "poll response missing authorization_code".into(),
                        );
                    };
                    let verifier = value["code_verifier"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let exchange = state
                        .http_client
                        .post(device.token_url)
                        .form(&[
                            ("grant_type", "authorization_code"),
                            ("client_id", provider.client_id),
                            ("code", code),
                            ("code_verifier", verifier.as_str()),
                            (
                                "redirect_uri",
                                "https://auth.openai.com/deviceauth/callback",
                            ),
                        ])
                        .send()
                        .await;
                    match exchange {
                        Ok(response) if response.status().is_success() => {
                            let value = match auth::read_oauth_json(response).await {
                                Ok(value) => value,
                                Err(()) => {
                                    return DeviceStep::Failed(
                                        "token exchange response was invalid".into(),
                                    )
                                }
                            };
                            match parse_tokens(&value) {
                                Some(tokens) => DeviceStep::Tokens(tokens),
                                None => {
                                    DeviceStep::Failed("token exchange missing access_token".into())
                                }
                            }
                        }
                        Ok(response) => {
                            let status = response.status();
                            DeviceStep::Failed(format!(
                                "token exchange rejected (HTTP {})",
                                status.as_u16()
                            ))
                        }
                        Err(_) => DeviceStep::Failed("token exchange request failed".into()),
                    }
                }
                Ok(response) => {
                    let status = response.status();
                    DeviceStep::Failed(format!("device poll rejected (HTTP {})", status.as_u16()))
                }
                Err(_) => DeviceStep::Failed("device poll request failed".into()),
            }
        }
        // RFC 8628 (grok): poll the token endpoint directly.
        _ => {
            let response = state
                .http_client
                .post(device.token_url)
                .header("accept", "application/json")
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", provider.client_id),
                    ("device_code", device_auth_id),
                ])
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {
                    let value = match auth::read_oauth_json(response).await {
                        Ok(value) => value,
                        Err(()) => return DeviceStep::Failed("token response was invalid".into()),
                    };
                    match parse_tokens(&value) {
                        Some(tokens) => DeviceStep::Tokens(tokens),
                        None => DeviceStep::Failed("token response missing access_token".into()),
                    }
                }
                Ok(response) => {
                    let status = response.status();
                    let value = auth::read_oauth_json(response).await.unwrap_or_default();
                    match value["error"].as_str().unwrap_or("") {
                        "authorization_pending" | "slow_down" => DeviceStep::Pending,
                        "access_denied" => DeviceStep::Failed("authorization was denied".into()),
                        "expired_token" => {
                            DeviceStep::Failed("authorization window expired".into())
                        }
                        "invalid_grant" => DeviceStep::Failed("authorization failed".into()),
                        _ => DeviceStep::Failed(format!(
                            "device poll rejected (HTTP {})",
                            status.as_u16()
                        )),
                    }
                }
                Err(_) => DeviceStep::Failed("device poll request failed".into()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/auth/paste — store a pasted credential
// ---------------------------------------------------------------------------

pub async fn paste(
    State(state): State<AppState>,
    Json(body): Json<AuthPasteRequest>,
) -> impl IntoResponse {
    let Some(provider) = find_provider(&body.provider) else {
        return err("unknown subscription provider");
    };
    if body.api_key.trim().is_empty() {
        return err("API key cannot be empty");
    }
    let alias = body
        .alias
        .unwrap_or_else(|| auth::subscription_alias(provider.id));
    let mut vault = match state.vault.write() {
        Ok(value) => value,
        Err(_) => return err("vault lock poisoned"),
    };
    if body.api_key.trim().is_empty() || body.api_key.len() > 16 * 1024 {
        return err("credential is empty or too long");
    }
    let previous_entries = vault.entries.clone();
    // Replace any previous subscription entry for this provider.
    vault.entries.retain(|entry| {
        !(entry.provider == provider.provider_id
            && (entry.key_alias == alias || entry.oauth_provider.as_deref() == Some(provider.id)))
    });
    match vault.add_key(provider.provider_id, &alias, body.api_key.trim(), 0) {
        Ok(()) => {}
        Err(_) => return err("failed to store key"),
    }
    if vault.save().is_err() {
        vault.entries = previous_entries;
        return err("failed to save vault");
    }
    let mut config = match state.config.write() {
        Ok(value) => value,
        Err(_) => return err("config lock poisoned"),
    };
    let previous = config.clone();
    let provider_id = provider.provider_id.to_string();
    if !config.providers.contains_key(&provider_id) {
        config.providers.insert(
            provider_id.clone(),
            ProviderConfig {
                name: provider.label.to_string(),
                base_url: provider.base_url.to_string(),
                enabled: true,
                round_robin: false,
                format: Some(provider.format.to_string()),
            },
        );
        if matches!(provider.id, "chatgpt" | "grok") {
            config
                .routing
                .model_map
                .entry(provider.model_hint.to_string())
                .or_insert_with(|| format!("{}/{}", provider.provider_id, provider.model_hint));
        }
        if crate::config::save_config(&config).is_err() {
            *config = previous;
            return err("failed to save config");
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "account": alias})),
    )
}

// ---------------------------------------------------------------------------
// POST /api/auth/disconnect — remove the linked subscription credential
// ---------------------------------------------------------------------------

pub async fn disconnect(
    State(state): State<AppState>,
    Json(body): Json<AuthRequest>,
) -> impl IntoResponse {
    let Some(provider) = find_provider(&body.provider) else {
        return err("unknown subscription provider");
    };
    let mut vault = match state.vault.write() {
        Ok(value) => value,
        Err(_) => return err("vault lock poisoned"),
    };
    let previous_entries = vault.entries.clone();
    let alias = auth::subscription_alias(provider.id);
    vault.entries.retain(|entry| {
        !(entry.provider == provider.provider_id
            && (entry.key_alias == alias || entry.oauth_provider.as_deref() == Some(provider.id)))
    });
    if vault.save().is_err() {
        vault.entries = previous_entries;
        return err("failed to save vault");
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

fn insert_session(state: &AppState, flow_id: String, session: PendingSession) {
    if let Ok(mut sessions) = state.auth_sessions.write() {
        // never let the map grow unbounded
        if sessions.len() > 64 {
            let oldest: Vec<String> = sessions.keys().take(16).cloned().collect();
            for key in oldest {
                sessions.remove(&key);
            }
        }
        sessions.insert(flow_id, session);
    }
}

fn drop_session(state: &AppState, flow_id: &str) {
    if let Ok(mut sessions) = state.auth_sessions.write() {
        sessions.remove(flow_id);
    }
}

/// Persist tokens + config entry for a successfully linked subscription.
pub async fn finish_login(
    state: &AppState,
    provider: &'static SubscriptionProvider,
    tokens: &AuthTokens,
) -> Result<String, String> {
    let provider_id = provider.provider_id.to_string();
    let needs_config_entry = !state
        .config
        .read()
        .map_err(|_| "config lock poisoned".to_string())?
        .providers
        .contains_key(&provider_id);
    if needs_config_entry {
        let mut config = state
            .config
            .write()
            .map_err(|_| "config lock poisoned".to_string())?;
        let previous = config.clone();
        config.providers.insert(
            provider_id,
            ProviderConfig {
                name: provider.label.to_string(),
                base_url: provider.base_url.to_string(),
                enabled: true,
                round_robin: false,
                format: Some(provider.format.to_string()),
            },
        );
        // Responses-format providers have no model catalog to discover, so
        // register the advertised model id as a routeable alias.
        if matches!(provider.id, "chatgpt" | "grok") {
            config
                .routing
                .model_map
                .entry(provider.model_hint.to_string())
                .or_insert_with(|| format!("{}/{}", provider.provider_id, provider.model_hint));
        }
        if crate::config::save_config(&config).is_err() {
            *config = previous;
            return Err("failed to save config".to_string());
        }
    }

    let label = account_label(tokens);
    let extra = oauth_extra(provider, tokens, &label);
    let alias = auth::subscription_alias(provider.id);
    let mut vault = state
        .vault
        .write()
        .map_err(|_| "vault lock poisoned".to_string())?;
    let previous_entries = vault.entries.clone();
    vault.upsert_oauth_key(crate::vault::OAuthCredential {
        provider: provider.provider_id,
        alias: &alias,
        access_token: &tokens.access_token,
        refresh_token: tokens.refresh_token.as_deref(),
        expires_at: token_expiry(tokens, chrono::Utc::now()),
        oauth_provider: provider.id,
        extra: Some(extra),
    });
    if vault.save().is_err() {
        vault.entries = previous_entries;
        return Err("failed to save vault".to_string());
    }
    Ok(label)
}

/// Request-side metadata for the subscription provider: account label plus
/// the identity/version headers the upstream expects.
pub fn oauth_extra(
    provider: &'static SubscriptionProvider,
    tokens: &AuthTokens,
    account: &str,
) -> serde_json::Value {
    let mut headers = serde_json::Map::new();
    match provider.id {
        "grok" => {
            // Grok CLI chat proxy identity headers; without them the proxy
            // answers as an unentitled API client.
            headers.insert("x-xai-token-auth".into(), "xai-grok-cli".into());
            headers.insert("x-grok-client-identifier".into(), "grok-shell".into());
            headers.insert("x-grok-client-version".into(), "0.2.93".into());
            headers.insert("account".into(), account.into());
        }
        "chatgpt" => {
            headers.insert("OpenAI-Beta".into(), "responses=v1".into());
            headers.insert("originator".into(), "skyport".into());
            headers.insert("version".into(), "skyport/0.1.0".into());
            // Prefer the id_token claim, then explicit token-response metadata.
            let account_id = tokens
                .id_token
                .as_deref()
                .and_then(|token| {
                    let Ok(claims) = auth::decode_jwt_payload(token) else {
                        return None;
                    };
                    claims
                        .get("https://api.openai.com/auth")
                        .and_then(|entry| entry.get("chatgpt_account_id"))
                        .or_else(|| claims.get("chatgpt_account_id"))
                        .and_then(|value| value.as_str())
                        .map(str::to_string)
                })
                .or_else(|| tokens.chatgpt_account_id.clone())
                .or_else(|| tokens.account_id.clone());
            if let Some(account_id) = account_id {
                headers.insert("ChatGPT-Account-ID".into(), account_id.into());
            }
            headers.insert("account".into(), account.into());
        }
        "claude" => {
            // OAuth access tokens are only honored with the beta header, and
            // are passed as a bearer credential instead of x-api-key.
            headers.insert("anthropic-beta".into(), "oauth-2025-04-20".into());
            headers.insert("account".into(), account.into());
        }
        _ => {}
    }
    serde_json::Value::Object(headers)
}

/// The `oauth_extra` headers a request should carry for a linked account.
pub fn headers_from_extra(extra: &Option<serde_json::Value>) -> Vec<(String, String)> {
    let Some(extra) = extra.as_ref() else {
        return Vec::new();
    };
    let Ok(headers) = serde_json::from_value::<HashMap<String, String>>(extra.clone()) else {
        return Vec::new();
    };
    headers
        .into_iter()
        .filter(|(key, _)| key != "account")
        .collect()
}

fn err(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"ok": false, "error": message})),
    )
}

/// Browser OAuth redirect target served by the loopback listener. Exchanges
/// the authorization code and records the outcome on the pending session so
/// the dashboard's poll step completes the login.
pub async fn callback_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(flow_id) = params.get("state").cloned() else {
        return callback_page(false);
    };
    let (provider_id, verifier) = {
        let mut sessions = match state.auth_sessions.write() {
            Ok(value) => value,
            Err(_) => return callback_page(false),
        };
        match take_browser_callback(&mut sessions, &flow_id, now_secs()) {
            Some(values) => values,
            None => return callback_page(false),
        }
    };
    let Some(code) = params.get("code") else {
        record_browser_outcome(
            &state,
            &flow_id,
            BrowserOutcome::Failed("authorization callback did not include a code".into()),
        );
        return callback_page(false);
    };
    let Some(provider) = find_provider(&provider_id) else {
        record_browser_outcome(
            &state,
            &flow_id,
            BrowserOutcome::Failed("authorization provider was unavailable".into()),
        );
        return callback_page(false);
    };
    match exchange_authorization_code(&state, provider, code, &verifier).await {
        Ok(tokens) => {
            if record_browser_outcome(&state, &flow_id, BrowserOutcome::Done(tokens)) {
                callback_page(true)
            } else {
                callback_page(false)
            }
        }
        Err(message) => {
            record_browser_outcome(&state, &flow_id, BrowserOutcome::Failed(message));
            callback_page(false)
        }
    }
}

fn take_browser_callback(
    sessions: &mut HashMap<String, PendingSession>,
    flow_id: &str,
    current_secs: u64,
) -> Option<(String, String)> {
    let expired = sessions
        .get(flow_id)
        .is_some_and(|session| current_secs.saturating_sub(session.started_secs) >= 900);
    if expired {
        sessions.remove(flow_id);
        return None;
    }

    let session = sessions.get_mut(flow_id)?;
    let PendingKind::Browser { verifier, outcome } = &mut session.kind else {
        return None;
    };
    if outcome.is_some() {
        return None;
    }
    verifier
        .take()
        .map(|verifier| (session.provider.clone(), verifier))
}

fn record_browser_outcome(state: &AppState, flow_id: &str, new_outcome: BrowserOutcome) -> bool {
    let Ok(mut sessions) = state.auth_sessions.write() else {
        return false;
    };
    store_browser_outcome(&mut sessions, flow_id, new_outcome)
}

fn store_browser_outcome(
    sessions: &mut HashMap<String, PendingSession>,
    flow_id: &str,
    new_outcome: BrowserOutcome,
) -> bool {
    let Some(session) = sessions.get_mut(flow_id) else {
        return false;
    };
    let PendingKind::Browser { verifier, outcome } = &mut session.kind else {
        return false;
    };
    if verifier.is_some() || outcome.is_some() {
        return false;
    }
    *outcome = Some(new_outcome);
    true
}

const CALLBACK_SUCCESS_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Signed in</title></head><body><h2>Signed in</h2><p>You can close this tab.</p></body></html>";
const CALLBACK_FAILURE_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in problem</title></head><body><h2>Sign-in problem</h2><p>Return to Skyport and start the sign-in again.</p></body></html>";

fn callback_page(ok: bool) -> Response {
    let (status, html) = if ok {
        (StatusCode::OK, CALLBACK_SUCCESS_HTML)
    } else {
        (StatusCode::BAD_REQUEST, CALLBACK_FAILURE_HTML)
    };
    let mut response = (status, Html(html)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Bind marker used by the callback listener to look up sessions by flow id.
/// The `Arc` keeps `AppState` clonable (shared across the main and callback
/// listeners) while the inner lock stays process-local.
pub type SessionMap =
    std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, PendingSession>>>;

/// The loopback port where browser-flow callbacks arrive (the Anthropic CLI's
/// registered redirect URI).
pub const CALLBACK_PORT: u16 = 8080;

/// Small helper the callback handler uses to exchange an authorization code.
pub async fn exchange_authorization_code(
    state: &AppState,
    provider: &'static SubscriptionProvider,
    code: &str,
    verifier: &str,
) -> Result<AuthTokens, String> {
    let browser = provider.browser.as_ref().expect("browser flow endpoints");
    let response = state
        .http_client
        .post(browser.token_url)
        .header("accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", provider.client_id),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", browser.redirect_uri),
        ])
        .send()
        .await
        .map_err(|_| "code exchange request failed".to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("code exchange rejected (HTTP {})", status.as_u16()));
    }
    let value = auth::read_oauth_json(response)
        .await
        .map_err(|_| "code exchange response was invalid".to_string())?;
    parse_tokens(&value).ok_or_else(|| "code exchange missing access_token".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt_with(payload: serde_json::Value) -> String {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("{header}.{body}.signature")
    }

    #[test]
    fn url_encode_escapes_reserved_characters_only() {
        assert_eq!(url_encode("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(url_encode("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(url_encode(""), "");
    }

    #[test]
    fn headers_from_extra_skips_the_account_label() {
        let extra = Some(serde_json::json!({
            "account": "me@example.com",
            "OpenAI-Beta": "responses=v1",
            "ChatGPT-Account-ID": "acct_1"
        }));
        let headers = headers_from_extra(&extra);
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&("OpenAI-Beta".to_string(), "responses=v1".to_string())));
        assert!(!headers.iter().any(|(key, _)| key == "account"));
        assert_eq!(headers_from_extra(&None), Vec::<(String, String)>::new());
    }

    #[test]
    fn oauth_extra_carries_grok_identity_headers() {
        let provider = find_provider("grok").unwrap();
        let extra = oauth_extra(
            provider,
            &crate::auth::AuthTokens {
                access_token: "at".into(),
                refresh_token: None,
                expires_in: None,
                id_token: None,
                account_id: None,
                chatgpt_account_id: None,
                user_id: None,
            },
            "grok-account",
        );
        assert_eq!(extra["x-xai-token-auth"], "xai-grok-cli");
        assert_eq!(extra["x-grok-client-identifier"], "grok-shell");
        assert_eq!(extra["x-grok-client-version"], "0.2.93");
        assert_eq!(extra["account"], "grok-account");
    }

    #[test]
    fn oauth_extra_derives_chatgpt_account_id_from_id_token() {
        let provider = find_provider("chatgpt").unwrap();
        let extra = oauth_extra(
            provider,
            &crate::auth::AuthTokens {
                access_token: "at".into(),
                refresh_token: None,
                expires_in: None,
                id_token: Some(jwt_with(serde_json::json!({
                    "https://api.openai.com/auth": {"chatgpt_account_id": "acct_1234567890"}
                }))),
                account_id: None,
                chatgpt_account_id: None,
                user_id: None,
            },
            "account abc…",
        );
        assert_eq!(extra["ChatGPT-Account-ID"], "acct_1234567890");
        assert_eq!(extra["OpenAI-Beta"], "responses=v1");
        assert_eq!(extra["originator"], "skyport");
        assert_eq!(extra["version"], "skyport/0.1.0");
        assert_eq!(extra["account"], "account abc…");
    }

    #[test]
    fn oauth_extra_for_claude_carries_the_oauth_beta_header() {
        let provider = find_provider("claude").unwrap();
        let extra = oauth_extra(
            provider,
            &crate::auth::AuthTokens {
                access_token: "at".into(),
                refresh_token: None,
                expires_in: None,
                id_token: None,
                account_id: None,
                chatgpt_account_id: None,
                user_id: None,
            },
            "claude-account",
        );
        assert_eq!(extra["anthropic-beta"], "oauth-2025-04-20");
        assert_eq!(extra["account"], "claude-account");
    }

    #[test]
    fn browser_callback_state_is_consumed_once_and_retained_for_polling() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "flow".into(),
            PendingSession {
                provider: "claude".into(),
                started_secs: 100,
                kind: PendingKind::Browser {
                    verifier: Some("pkce-secret".into()),
                    outcome: None,
                },
            },
        );

        assert_eq!(
            take_browser_callback(&mut sessions, "flow", 101),
            Some(("claude".into(), "pkce-secret".into()))
        );
        assert!(take_browser_callback(&mut sessions, "flow", 101).is_none());
        assert!(sessions.contains_key("flow"));
        assert!(store_browser_outcome(
            &mut sessions,
            "flow",
            BrowserOutcome::Failed("fixed failure".into())
        ));
        assert!(!store_browser_outcome(
            &mut sessions,
            "flow",
            BrowserOutcome::Failed("replay".into())
        ));
        assert!(matches!(
            sessions.get("flow").map(|session| &session.kind),
            Some(PendingKind::Browser {
                verifier: None,
                outcome: Some(BrowserOutcome::Failed(_))
            })
        ));
    }

    #[test]
    fn expired_browser_callback_state_is_removed() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "expired".into(),
            PendingSession {
                provider: "claude".into(),
                started_secs: 100,
                kind: PendingKind::Browser {
                    verifier: Some("pkce-secret".into()),
                    outcome: None,
                },
            },
        );

        assert!(take_browser_callback(&mut sessions, "expired", 1_000).is_none());
        assert!(!sessions.contains_key("expired"));
    }

    #[tokio::test]
    async fn callback_pages_are_static_and_hardened() {
        let response = callback_page(false);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[HeaderName::from_static("x-frame-options")],
            "DENY"
        );
        assert_eq!(
            response.headers()[HeaderName::from_static("referrer-policy")],
            "no-referrer"
        );
        assert_eq!(
            response.headers()[HeaderName::from_static("x-content-type-options")],
            "nosniff"
        );
        assert!(response
            .headers()
            .get(HeaderName::from_static("content-security-policy"))
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), CALLBACK_FAILURE_HTML.as_bytes());
        assert!(!CALLBACK_FAILURE_HTML.contains("<script"));
        assert!(!CALLBACK_SUCCESS_HTML.contains("<script"));
    }
}
