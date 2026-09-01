use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use futures::StreamExt;
use serde_json::{json, Value};
use std::{collections::HashSet, time::Instant};

static UPSTREAM_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(64);
static BUDGET_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

struct InFlightGuard {
    counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl InFlightGuard {
    fn new(counter: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self { counter }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

struct StreamLease {
    _permit: tokio::sync::SemaphorePermit<'static>,
    _in_flight: InFlightGuard,
}

use crate::{
    api::AppState,
    db::{self, RequestLogEntry},
    providers::{default_prices, ChatRequest, EmbeddingRequest},
    router::RouteDecision,
};

fn openai_error(status: StatusCode, message: impl Into<String>, code: &str) -> Response {
    (status, Json(json!({"error": {"message": message.into(), "type": "api_error", "param": null, "code": code}}))).into_response()
}

fn budget_for<'a>(
    config: &'a crate::config::SkyportConfig,
    provider: &str,
    alias: &str,
) -> Option<(&'a crate::config::BudgetConfig, bool)> {
    config
        .budgets
        .get(&format!("{provider}:{alias}"))
        .map(|budget| (budget, true))
        .or_else(|| config.budgets.get(provider).map(|budget| (budget, false)))
}

async fn proxy(
    state: &AppState,
    model: &str,
    mut body: Value,
    path: &str,
    stream: bool,
) -> Response {
    // 1. Global rate limit check
    let (global_rpm, global_rps) = match state.config.read() {
        Ok(config) => (config.rate_limit.max_rpm, config.rate_limit.max_rps),
        Err(_) => (None, None),
    };
    if let Err(exceeded) = state.rate_limiter.check_global(global_rpm, global_rps) {
        let msg = if exceeded.is_burst {
            format!(
                "Global burst rate limit exceeded (max {} requests/sec). Please retry after {}s.",
                exceeded.limit_rps.unwrap_or(0),
                exceeded.retry_after_secs
            )
        } else {
            format!(
                "Global rate limit exceeded (max {} requests/min). Please retry after {}s.",
                exceeded.limit_rpm.unwrap_or(0),
                exceeded.retry_after_secs
            )
        };
        let mut response = openai_error(StatusCode::TOO_MANY_REQUESTS, msg, "rate_limit_exceeded");
        if let Ok(retry_hdr) =
            axum::http::HeaderValue::from_str(&exceeded.retry_after_secs.to_string())
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, retry_hdr);
        }
        return response;
    }

    let permit = match UPSTREAM_SLOTS.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return openai_error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many concurrent upstream requests",
                "concurrency_limit",
            )
        }
    };
    if model.is_empty() || model.len() > 512 || model.chars().any(char::is_control) {
        return openai_error(
            StatusCode::BAD_REQUEST,
            "Invalid model identifier",
            "invalid_model",
        );
    }
    for field in ["max_tokens", "max_output_tokens"] {
        if body
            .get(field)
            .and_then(Value::as_u64)
            .is_some_and(|tokens| tokens > 32_768)
        {
            return openai_error(
                StatusCode::BAD_REQUEST,
                "Requested token limit exceeds 32768",
                "token_limit_exceeded",
            );
        }
    }
    let (provider, actual_model) = match state.router.resolve_model(model) {
        Ok(value) => value,
        Err(error) => {
            return openai_error(
                StatusCode::BAD_REQUEST,
                error.to_string(),
                "model_not_found",
            )
        }
    };
    let has_usd_budget = match state.config.read() {
        Ok(config) => config.budgets.iter().any(|(scope, b)| {
            (scope == &provider || scope.starts_with(&format!("{provider}:")))
                && (b.monthly_cap_usd.is_some() || b.daily_cap_usd.is_some())
        }),
        Err(_) => {
            return openai_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Configuration lock poisoned",
                "internal_error",
            )
        }
    };
    if has_usd_budget && stream {
        return openai_error(
            StatusCode::CONFLICT,
            "Streaming is disabled for budgeted providers so caps cannot be overshot",
            "budget_streaming_disabled",
        );
    }
    if has_usd_budget
        && path != "embeddings"
        && body.get("max_tokens").and_then(Value::as_u64).is_none()
    {
        body["max_tokens"] = json!(4096);
    }
    let _budget_guard = if has_usd_budget {
        Some(BUDGET_GATE.lock().await)
    } else {
        None
    };
    body["model"] = json!(actual_model);
    let start = Instant::now();
    let mut attempted = HashSet::new();
    let mut last_error = "No eligible API key".to_string();
    let mut last_status = StatusCode::SERVICE_UNAVAILABLE;

    loop {
        let mut decision = match state.router.select_key(&provider) {
            Ok(value) => value,
            Err(error) => break openai_error(last_status, format!("{error}"), "no_available_key"),
        };
        if !attempted.insert(decision.key_alias.clone()) && decision.key_alias != "local" {
            break openai_error(last_status, last_error, "upstream_error");
        }

        let (blocked, scoped_rpm) = {
            let config = match state.config.read() {
                Ok(value) => value,
                Err(_) => {
                    return openai_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Configuration lock poisoned",
                        "internal_error",
                    )
                }
            };
            let rpm = budget_for(&config, &provider, &decision.key_alias)
                .and_then(|(budget, key_scoped)| budget.max_rpm.map(|rpm| (rpm, key_scoped)));
            let blocked_by_budget = match budget_for(&config, &provider, &decision.key_alias) {
                Some((budget, _))
                    if (budget.monthly_cap_usd.is_some() || budget.daily_cap_usd.is_some())
                        && default_prices(&provider).is_none() =>
                {
                    return openai_error(
                        StatusCode::CONFLICT,
                        "A budget cannot be enforced because this provider has no trusted pricing data",
                        "pricing_unknown",
                    )
                }
                Some((budget, key_scoped))
                    if budget.monthly_cap_usd.is_some() || budget.daily_cap_usd.is_some() =>
                {
                    match state.db.lock() {
                        Ok(db) => {
                            let projected_cost = default_prices(&provider)
                                .map(|prices| {
                                    let prompt_bound = serde_json::to_vec(&body)
                                        .map(|body| body.len() as u64)
                                        .unwrap_or(u64::MAX);
                                    let completion_bound = body
                                        .get("max_tokens")
                                        .or_else(|| body.get("max_output_tokens"))
                                        .and_then(Value::as_u64)
                                        .unwrap_or(0);
                                    prices.estimate_cost(prompt_bound, completion_bound)
                                })
                                .unwrap_or(f64::INFINITY);
                            match db::check_budget(
                                &db,
                                &provider,
                                key_scoped.then_some(decision.key_alias.as_str()),
                                budget,
                                projected_cost,
                            ) {
                                Ok(within_budget) => !within_budget,
                                Err(_) => {
                                    return openai_error(
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        "Could not verify the configured budget",
                                        "budget_check_failed",
                                    )
                                }
                            }
                        }
                        Err(_) => {
                            return openai_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Database lock poisoned",
                                "internal_error",
                            )
                        }
                    }
                }
                _ => false,
            };
            (blocked_by_budget, rpm)
        };
        if blocked {
            return openai_error(
                StatusCode::TOO_MANY_REQUESTS,
                format!("Budget cap reached for {provider}"),
                "budget_exceeded",
            );
        }
        if let Some((rpm, key_scoped)) = scoped_rpm {
            let scope_key = if key_scoped {
                format!("{}:{}", provider, decision.key_alias)
            } else {
                provider.clone()
            };
            if let Err(exceeded) = state.rate_limiter.check_scoped(&scope_key, Some(rpm)) {
                let mut response = openai_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    format!(
                        "Rate limit exceeded for {} (max {} requests/min). Please retry after {}s.",
                        provider, rpm, exceeded.retry_after_secs
                    ),
                    "rate_limit_exceeded",
                );
                if let Ok(retry_hdr) =
                    axum::http::HeaderValue::from_str(&exceeded.retry_after_secs.to_string())
                {
                    response
                        .headers_mut()
                        .insert(axum::http::header::RETRY_AFTER, retry_hdr);
                }
                return response;
            }
        }

        // Subscription access tokens are short-lived; refresh in place before
        // the request goes out (cheap no-op when the token is still fresh).
        if let Err(error) = ensure_fresh_oauth(state, &mut decision).await {
            return openai_error(
                StatusCode::SERVICE_UNAVAILABLE,
                error,
                "oauth_refresh_failed",
            );
        }

        let credentialed = !decision.api_key.is_empty();
        let base_url = match crate::security::validate_provider_url(
            &provider,
            &decision.base_url,
            credentialed,
        ) {
            Ok(url) => url,
            Err(error) => {
                return openai_error(StatusCode::BAD_GATEWAY, error, "unsafe_provider_url")
            }
        };
        if let Err(error) =
            crate::security::validate_resolved_destination(&provider, &base_url, credentialed).await
        {
            return openai_error(StatusCode::BAD_GATEWAY, error, "unsafe_provider_url");
        }

        // Translate the request to the upstream's wire protocol and pick the
        // matching endpoint and authentication scheme.
        let (upstream_url, upstream_body, bearer_auth) = match decision.format.as_str() {
            "anthropic" => match crate::security::append_url_path(&base_url, "v1/messages") {
                Ok(url) => (url, crate::providers::translate::to_anthropic(&body), false),
                Err(error) => {
                    return openai_error(StatusCode::BAD_GATEWAY, error, "invalid_provider_url")
                }
            },
            "gemini" => {
                if !crate::security::valid_model_path_segment(&actual_model) {
                    return openai_error(
                        StatusCode::BAD_REQUEST,
                        "Invalid Gemini model identifier",
                        "invalid_model",
                    );
                }
                let action = if stream {
                    "streamGenerateContent"
                } else {
                    "generateContent"
                };
                let path = format!("v1beta/models/{actual_model}:{action}");
                match crate::security::append_url_path(&base_url, &path) {
                    Ok(mut url) => {
                        if stream {
                            url.query_pairs_mut().append_pair("alt", "sse");
                        }
                        (url, crate::providers::translate::to_gemini(&body), false)
                    }
                    Err(error) => {
                        return openai_error(StatusCode::BAD_GATEWAY, error, "invalid_provider_url")
                    }
                }
            }
            "responses" => match crate::security::append_url_path(&base_url, "responses") {
                Ok(url) => (url, crate::providers::translate::to_responses(&body), true),
                Err(error) => {
                    return openai_error(StatusCode::BAD_GATEWAY, error, "invalid_provider_url")
                }
            },
            _ => match crate::security::append_url_path(&base_url, path) {
                Ok(url) => (url, body.clone(), true),
                Err(error) => {
                    return openai_error(StatusCode::BAD_GATEWAY, error, "invalid_provider_url")
                }
            },
        };

        let oauth_headers = crate::api::oauth::headers_from_extra(&decision.oauth_extra);
        let mut request = state.http_client.post(upstream_url).json(&upstream_body);
        if oauth_headers.is_empty() {
            if !decision.api_key.is_empty() {
                request = match decision.format.as_str() {
                    "anthropic" => request
                        .header("x-api-key", &decision.api_key)
                        .header("anthropic-version", "2023-06-01"),
                    "gemini" => request.header("x-goog-api-key", &decision.api_key),
                    _ => {
                        if bearer_auth {
                            request.bearer_auth(&decision.api_key)
                        } else {
                            request
                        }
                    }
                };
            }
        } else if !decision.api_key.is_empty() {
            // Subscription credential: bearer access token plus the
            // identity/version headers the upstream expects (the ChatGPT
            // account id, Grok CLI identity, Anthropic OAuth beta...).
            if decision.format.as_str() == "anthropic" {
                request = request.header("anthropic-version", "2023-06-01");
            }
            request = request.bearer_auth(&decision.api_key);
            for (name, value) in oauth_headers {
                request = request.header(name, value);
            }
        }
        let in_flight = InFlightGuard::new(state.in_flight.clone());
        let send_result = request.send().await;
        match send_result {
            Ok(upstream) if upstream.status().is_success() => {
                state.router.mark_key_success(&decision.key_alias);
                if stream {
                    let lease = StreamLease {
                        _permit: permit,
                        _in_flight: in_flight,
                    };
                    return match decision.format.as_str() {
                        "anthropic" | "gemini" => translate_native_stream(
                            upstream
                                .bytes_stream()
                                .map(|result| result.map_err(axum::Error::new)),
                            decision.format.clone(),
                            state.clone(),
                            provider.clone(),
                            decision.key_alias.clone(),
                            actual_model.clone(),
                            start,
                            Some(body.clone()),
                            lease,
                        ),
                        "responses" => translate_responses_stream(
                            upstream
                                .bytes_stream()
                                .map(|result| result.map_err(axum::Error::new)),
                            state.clone(),
                            provider.clone(),
                            decision.key_alias.clone(),
                            actual_model.clone(),
                            start,
                            Some(body.clone()),
                            lease,
                        ),
                        _ => logged_passthrough_stream(
                            upstream
                                .bytes_stream()
                                .map(|result| result.map_err(axum::Error::new)),
                            state.clone(),
                            provider.clone(),
                            decision.key_alias.clone(),
                            actual_model.clone(),
                            start,
                            Some(body.clone()),
                            lease,
                        ),
                    };
                }
                let status = upstream.status();
                let bytes = match crate::security::read_upstream_body(upstream).await {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        return openai_error(
                            StatusCode::BAD_GATEWAY,
                            error,
                            "upstream_response_too_large",
                        )
                    }
                };
                let payload: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({"error": {"message": "Upstream returned invalid JSON", "type": "api_error"}}));
                let payload = match decision.format.as_str() {
                    "anthropic" => crate::providers::translate::from_anthropic(&payload),
                    "gemini" => crate::providers::translate::from_gemini(&payload),
                    "responses" => crate::providers::translate::from_responses(&payload),
                    _ => payload,
                };
                log_response(
                    state,
                    &provider,
                    &decision.key_alias,
                    &actual_model,
                    status.as_u16(),
                    start.elapsed().as_millis() as i64,
                    Some(&body),
                    &payload,
                );
                return (StatusCode::OK, Json(payload)).into_response();
            }
            Ok(upstream) => {
                let status = upstream.status();
                let retry_after = upstream
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse().ok());
                if status.as_u16() == 401 || status.as_u16() == 429 || status.is_server_error() {
                    log_response(
                        state,
                        &provider,
                        &decision.key_alias,
                        &actual_model,
                        status.as_u16(),
                        start.elapsed().as_millis() as i64,
                        Some(&body),
                        &json!({}),
                    );
                    state
                        .router
                        .mark_key_failed(&decision.key_alias, status.as_u16(), retry_after);
                    last_status =
                        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                    last_error = format!("Upstream returned status {}", status.as_u16());
                    continue;
                }
                let payload = json!({"error": {"message": format!("Upstream returned status {}", status.as_u16()), "type": "api_error"}});
                log_response(
                    state,
                    &provider,
                    &decision.key_alias,
                    &actual_model,
                    status.as_u16(),
                    start.elapsed().as_millis() as i64,
                    Some(&body),
                    &payload,
                );
                return (status, Json(payload)).into_response();
            }
            Err(error) => {
                log_tokens(
                    state,
                    TokenLog {
                        provider: &provider,
                        alias: &decision.key_alias,
                        model: &actual_model,
                        status: 502,
                        latency_ms: start.elapsed().as_millis() as i64,
                        prompt: 0,
                        completion: 0,
                        request_body: Some(&body),
                    },
                );
                state.router.mark_key_failed(&decision.key_alias, 502, None);
                last_status = StatusCode::BAD_GATEWAY;
                last_error = crate::security::safe_network_error(&error).to_string();
                if decision.key_alias == "local" {
                    break openai_error(last_status, last_error, "connection_error");
                }
            }
        }
    }
}

/// Convert an SSE stream in a native upstream format (Anthropic Messages or
/// Gemini) into OpenAI chat-completion chunks for gateway clients.
fn translate_native_stream<S>(
    source: S,
    format: String,
    state: AppState,
    provider: String,
    alias: String,
    model: String,
    start: Instant,
    request_body: Option<Value>,
    lease: StreamLease,
) -> Response
where
    S: futures::Stream<Item = Result<Bytes, axum::Error>> + Send + 'static,
{
    let stream = async_stream::stream! {
        let _lease = lease;
        let mut pending = String::new();
        let mut source = std::pin::pin!(source);
        let mut done = false;
        let mut prompt_tokens = 0;
        let mut completion_tokens = 0;
        let mut failed = false;
        while let Some(chunk) = source.next().await {
            match chunk {
                Ok(chunk) => {
                    pending.push_str(&String::from_utf8_lossy(&chunk));
                    if pending.len() > MAX_SSE_EVENT_BYTES {
                        failed = true;
                        break;
                    }
                    pending = pending.replace("\r\n", "\n");
                    while let Some(end) = pending.find("\n\n") {
                        let event = pending[..end].to_string();
                        pending = pending[end + 2..].to_string();
                        for line in event.lines() {
                            let Some(data) = line.strip_prefix("data: ") else { continue };
                            let (prompt, completion) = stream_usage(data);
                            prompt_tokens = prompt_tokens.max(prompt);
                            completion_tokens = completion_tokens.max(completion);
                            let translated = match format.as_str() {
                                "anthropic" => crate::providers::translate::anthropic_stream_event(data, &mut done),
                                _ => crate::providers::translate::gemini_stream_event(data, &mut done),
                            };
                            if let Some(chunk) = translated {
                                yield Ok(Bytes::from(format!("data: {chunk}\n\n")));
                            }
                        }
                        if done { break; }
                    }
                    if done { break; }
                }
                Err(error) => { failed = true; yield Err(error); break; }
            }
        }
        log_tokens(&state, TokenLog { provider: &provider, alias: &alias, model: &model, status: if failed { 502 } else { 200 }, latency_ms: start.elapsed().as_millis() as i64, prompt: prompt_tokens, completion: completion_tokens, request_body: request_body.as_ref() });
        yield Ok(Bytes::from("data: [DONE]\n\n"));
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(axum::body::Body::from_stream(stream))
        .unwrap_or_else(|_| {
            openai_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not create translated stream",
                "internal_error",
            )
        })
}

/// Convert a Responses-API SSE stream (ChatGPT Codex backend, Grok CLI proxy)
/// into OpenAI chat-completion chunks for gateway clients.
fn translate_responses_stream<S>(
    source: S,
    state: AppState,
    provider: String,
    alias: String,
    model: String,
    start: Instant,
    request_body: Option<Value>,
    lease: StreamLease,
) -> Response
where
    S: futures::Stream<Item = Result<Bytes, axum::Error>> + Send + 'static,
{
    let stream = async_stream::stream! {
        let _lease = lease;
        let mut pending = String::new();
        let mut source = std::pin::pin!(source);
        let mut done = false;
        let mut prompt_tokens = 0;
        let mut completion_tokens = 0;
        let mut failed = false;
        while let Some(chunk) = source.next().await {
            match chunk {
                Ok(chunk) => {
                    pending.push_str(&String::from_utf8_lossy(&chunk));
                    if pending.len() > MAX_SSE_EVENT_BYTES {
                        failed = true;
                        break;
                    }
                    pending = pending.replace("\r\n", "\n");
                    while let Some(end) = pending.find("\n\n") {
                        let event = pending[..end].to_string();
                        pending = pending[end + 2..].to_string();
                        for line in event.lines() {
                            let Some(data) = line.strip_prefix("data: ") else { continue };
                            let (prompt, completion) = stream_usage(data);
                            prompt_tokens = prompt_tokens.max(prompt);
                            completion_tokens = completion_tokens.max(completion);
                            if let Some(chunk) =
                                crate::providers::translate::responses_stream_event(data, &mut done)
                            {
                                yield Ok(Bytes::from(format!("data: {chunk}\n\n")));
                            }
                        }
                        if done { break; }
                    }
                    if done { break; }
                }
                Err(error) => { failed = true; yield Err(error); break; }
            }
        }
        log_tokens(&state, TokenLog { provider: &provider, alias: &alias, model: &model, status: if failed { 502 } else { 200 }, latency_ms: start.elapsed().as_millis() as i64, prompt: prompt_tokens, completion: completion_tokens, request_body: request_body.as_ref() });
        yield Ok(Bytes::from("data: [DONE]\n\n"));
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(axum::body::Body::from_stream(stream))
        .unwrap_or_else(|_| {
            openai_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not create translated stream",
                "internal_error",
            )
        })
}

/// Relay OpenAI-compatible SSE unchanged while recording final usage.
fn logged_passthrough_stream<S>(
    source: S,
    state: AppState,
    provider: String,
    alias: String,
    model: String,
    start: Instant,
    request_body: Option<Value>,
    lease: StreamLease,
) -> Response
where
    S: futures::Stream<Item = Result<Bytes, axum::Error>> + Send + 'static,
{
    let stream = async_stream::stream! {
        let _lease = lease;
        let mut source = std::pin::pin!(source);
        let mut pending = String::new();
        let mut prompt_tokens = 0;
        let mut completion_tokens = 0;
        let mut failed = false;
        while let Some(chunk) = source.next().await {
            match chunk {
                Ok(chunk) => {
                    pending.push_str(&String::from_utf8_lossy(&chunk));
                    if pending.len() > MAX_SSE_EVENT_BYTES {
                        failed = true;
                        break;
                    }
                    pending = pending.replace("\r\n", "\n");
                    while let Some(end) = pending.find("\n\n") {
                        let event = pending[..end].to_string();
                        pending = pending[end + 2..].to_string();
                        for line in event.lines() {
                            if let Some(data) = line.strip_prefix("data: ") {
                                let (prompt, completion) = stream_usage(data);
                                prompt_tokens = prompt_tokens.max(prompt);
                                completion_tokens = completion_tokens.max(completion);
                            }
                        }
                    }
                    yield Ok(chunk);
                }
                Err(error) => { failed = true; yield Err(error); break; }
            }
        }
        log_tokens(&state, TokenLog { provider: &provider, alias: &alias, model: &model, status: if failed { 502 } else { 200 }, latency_ms: start.elapsed().as_millis() as i64, prompt: prompt_tokens, completion: completion_tokens, request_body: request_body.as_ref() });
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(axum::body::Body::from_stream(stream))
        .unwrap_or_else(|_| {
            openai_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not create stream",
                "internal_error",
            )
        })
}

/// Refresh an expired subscription access token in place, so requests keep
/// flowing without the user re-signing in. Fail closed rather than sending an
/// expired token and disabling an otherwise recoverable subscription.
async fn ensure_fresh_oauth(state: &AppState, decision: &mut RouteDecision) -> Result<(), String> {
    if decision.oauth_extra.is_none() {
        return Ok(());
    }
    let (provider_id, refresh_token, expires_at) = {
        let vault = match state.vault.read() {
            Ok(value) => value,
            Err(_) => return Err("Credential vault is unavailable".to_string()),
        };
        match vault
            .entries
            .iter()
            .find(|e| e.key_alias == decision.key_alias)
        {
            Some(entry) => (
                entry.oauth_provider.clone().unwrap_or_default(),
                entry.refresh_token.clone(),
                entry.expires_at,
            ),
            None => return Err("Subscription credential is unavailable".to_string()),
        }
    };
    let Some(refresh_token) = refresh_token else {
        return Ok(());
    };
    let still_fresh = expires_at
        .map(|at| at > chrono::Utc::now() + chrono::Duration::minutes(2))
        .unwrap_or(false);
    if still_fresh {
        return Ok(());
    }
    let Some(provider) = crate::auth::find_provider(&provider_id) else {
        return Err("Subscription provider is unavailable".to_string());
    };
    let tokens =
        match crate::auth::refresh_access_token(&state.http_client, provider, &refresh_token).await
        {
            Ok(tokens) => tokens,
            Err(_) => {
                tracing::warn!(provider = %provider_id, "subscription token refresh failed");
                return Err("Subscription token refresh failed; reconnect the account".to_string());
            }
        };
    let next_refresh_token = tokens
        .refresh_token
        .clone()
        .unwrap_or_else(|| refresh_token.clone());
    let extra =
        crate::api::oauth::oauth_extra(provider, &tokens, &crate::auth::account_label(&tokens));
    let mut vault = state
        .vault
        .write()
        .map_err(|_| "Credential vault is unavailable".to_string())?;
    let previous = vault.entries.clone();
    let entry = vault
        .entries
        .iter_mut()
        .find(|entry| entry.key_alias == decision.key_alias)
        .ok_or_else(|| "Subscription credential is unavailable".to_string())?;
    use zeroize::Zeroize;
    entry.api_key.zeroize();
    entry.api_key.push_str(&tokens.access_token);
    entry.refresh_token.zeroize();
    entry.refresh_token = Some(next_refresh_token);
    entry.expires_at = crate::auth::token_expiry(&tokens, chrono::Utc::now());
    entry.oauth_extra = Some(extra.clone());
    if vault.save().is_err() {
        vault.entries = previous;
        return Err("Could not persist refreshed subscription credentials".to_string());
    }
    decision.api_key = tokens.access_token.clone();
    decision.oauth_extra = Some(extra);
    Ok(())
}

fn log_response(
    state: &AppState,
    provider: &str,
    alias: &str,
    model: &str,
    status: u16,
    latency_ms: i64,
    request_body: Option<&Value>,
    payload: &Value,
) {
    let (prompt, completion) = usage_from_payload(payload);
    log_tokens(
        state,
        TokenLog {
            provider,
            alias,
            model,
            status,
            latency_ms,
            prompt,
            completion,
            request_body,
        },
    );
}

struct TokenLog<'a> {
    provider: &'a str,
    alias: &'a str,
    model: &'a str,
    status: u16,
    latency_ms: i64,
    prompt: i64,
    completion: i64,
    request_body: Option<&'a Value>,
}

fn log_tokens(state: &AppState, log: TokenLog<'_>) {
    let cost = default_prices(log.provider)
        .map(|prices| prices.estimate_cost(log.prompt.max(0) as u64, log.completion.max(0) as u64))
        .unwrap_or(0.0);
    let entry = RequestLogEntry {
        id: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
        provider: log.provider.into(),
        key_alias: log.alias.into(),
        model: log.model.into(),
        status: log.status as i32,
        latency_ms: log.latency_ms,
        prompt_tokens: log.prompt,
        completion_tokens: log.completion,
        est_cost_usd: cost,
    };
    if let Ok(mut db) = state.db.lock() {
        let now = chrono::Utc::now();
        let write_result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let transaction = db.transaction()?;
            db::log_request(&transaction, &entry)?;
            db::update_budget_usage(
                &transaction,
                log.provider,
                log.alias,
                &now.format("%Y-%m").to_string(),
                cost,
            )?;
            db::update_budget_usage(
                &transaction,
                log.provider,
                log.alias,
                &now.format("%Y-%m-%d").to_string(),
                cost,
            )?;
            transaction.commit()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            tracing::error!(%error, "failed to atomically persist telemetry and budget usage");
        }
    }
    let empty_body = serde_json::json!({});
    let body = log.request_body.unwrap_or(&empty_body);
    crate::activity::record_request_activity(
        state,
        "default",
        body,
        log.provider,
        log.model,
        log.latency_ms,
        log.prompt,
        log.completion,
        log.status,
        cost,
    );
}

fn usage_from_payload(payload: &Value) -> (i64, i64) {
    let usage = payload
        .get("usage")
        .or_else(|| payload.get("usageMetadata"))
        .or_else(|| {
            payload
                .get("response")
                .and_then(|response| response.get("usage"))
        })
        .unwrap_or(payload);
    let prompt = usage["prompt_tokens"]
        .as_i64()
        .or_else(|| usage["input_tokens"].as_i64())
        .or_else(|| usage["promptTokenCount"].as_i64())
        .unwrap_or(0);
    let completion = usage["completion_tokens"]
        .as_i64()
        .or_else(|| usage["output_tokens"].as_i64())
        .or_else(|| usage["candidatesTokenCount"].as_i64())
        .unwrap_or(0);
    (prompt, completion)
}

fn stream_usage(data: &str) -> (i64, i64) {
    serde_json::from_str::<Value>(data)
        .map(|payload| usage_from_payload(&payload))
        .unwrap_or_default()
}

pub async fn chat_completions(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Response {
    let stream = request.stream.unwrap_or(false);
    let model = request.model.clone();
    let body = serde_json::to_value(request).unwrap_or_default();
    proxy(&state, &model, body, "chat/completions", stream).await
}

pub async fn embeddings(
    State(state): State<AppState>,
    Json(request): Json<EmbeddingRequest>,
) -> Response {
    let model = request.model.clone();
    let body = serde_json::to_value(request).unwrap_or_default();
    proxy(&state, &model, body, "embeddings", false).await
}

pub async fn list_models(State(state): State<AppState>) -> impl IntoResponse {
    let config = match state.config.read() {
        Ok(value) => value,
        Err(_) => return Json(json!({"object":"list", "data": []})),
    };

    let mut data: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Discovered upstream models, exposed as unambiguous provider/model ids.
    if let Ok(catalog) = state.catalog.read() {
        for (provider, models) in catalog.iter() {
            let enabled = config.providers.get(provider).is_some_and(|p| p.enabled);
            if !enabled {
                continue;
            }
            let owned_by = config.providers[provider].name.clone();
            for model in models {
                let id = format!("{provider}/{}", model.id);
                if seen.insert(id.clone()) {
                    data.push(
                        json!({"id": id, "object": "model", "created": 0, "owned_by": owned_by}),
                    );
                }
            }
        }
    }

    // User-defined aliases from the model map are first-class ids too.
    for alias in config.routing.model_map.keys() {
        if seen.insert(alias.clone()) {
            data.push(json!({"id": alias, "object": "model", "created": 0, "owned_by": "skyport"}));
        }
    }

    // Nothing discovered yet: at least advertise the enabled providers so
    // picky harnesses have a valid id to pin.
    if data.is_empty() {
        for (id, provider) in config.providers.iter().filter(|(_, p)| p.enabled) {
            data.push(
                json!({"id": id, "object": "model", "created": 0, "owned_by": provider.name}),
            );
        }
    }

    Json(json!({"object": "list", "data": data}))
}

pub async fn responses(State(state): State<AppState>, Json(body): Json<Value>) -> Response {
    let model = body["model"].as_str().unwrap_or("gpt-4o").to_string();
    let stream = body["stream"].as_bool().unwrap_or(false);
    let messages = match &body["input"] {
        Value::String(text) => vec![json!({"role": "user", "content": text})],
        Value::Array(items) => items
            .iter()
            .map(|item| {
                if item.is_string() {
                    json!({"role": "user", "content": item})
                } else {
                    item.clone()
                }
            })
            .collect(),
        value => vec![json!({"role": "user", "content": value.to_string()})],
    };
    let chat_body = json!({"model": model, "messages": messages, "stream": stream, "temperature": body["temperature"], "max_tokens": body["max_output_tokens"]});
    let response = proxy(&state, &model, chat_body, "chat/completions", stream).await;
    if stream {
        return translate_response_stream(response, model);
    }
    let (parts, body) = response.into_parts();
    if !parts.status.is_success() {
        return Response::from_parts(parts, body);
    }
    let bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return openai_error(
                StatusCode::BAD_GATEWAY,
                "Unable to read upstream response",
                "upstream_error",
            )
        }
    };
    let chat: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    let text = chat["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("");
    (StatusCode::OK, Json(json!({"id": format!("resp_{}", uuid::Uuid::new_v4().simple()), "object": "response", "created_at": chrono::Utc::now().timestamp(), "status": "completed", "model": chat["model"].as_str().unwrap_or(&model), "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}], "usage": chat["usage"]}))).into_response()
}

/// Convert OpenAI chat-completions SSE chunks into the Responses API event names
/// expected by clients configured with `wire_api = responses`.
fn translate_response_stream(response: Response, model: String) -> Response {
    let (parts, body) = response.into_parts();
    if !parts.status.is_success() {
        return Response::from_parts(parts, body);
    }
    let response_id = format!("resp_{}", uuid::Uuid::new_v4().simple());
    let stream = async_stream::stream! {
        let created = json!({
            "type": "response.created",
            "response": {"id": response_id, "object": "response", "status": "in_progress", "model": model}
        });
        yield Ok::<Bytes, axum::Error>(Bytes::from(format!("event: response.created\ndata: {created}\n\n")));

        let mut pending = String::new();
        let mut source = body.into_data_stream();
        while let Some(chunk) = source.next().await {
            match chunk {
                Ok(chunk) => {
                    pending.push_str(&String::from_utf8_lossy(&chunk));
                    if pending.len() > MAX_SSE_EVENT_BYTES {
                        break;
                    }
                    while let Some(end) = pending.find("\n\n") {
                        let event = pending[..end].to_string();
                        pending = pending[end + 2..].to_string();
                        for line in event.lines() {
                            let Some(data) = line.strip_prefix("data: ") else { continue };
                            if data == "[DONE]" {
                                let completed = json!({"type": "response.completed", "response": {"id": response_id, "object": "response", "status": "completed", "model": model}});
                                yield Ok(Bytes::from(format!("event: response.completed\ndata: {completed}\n\n")));
                            } else if let Ok(chunk) = serde_json::from_str::<Value>(data) {
                                if let Some(delta) = chunk["choices"][0]["delta"]["content"].as_str() {
                                    let output = json!({"type": "response.output_text.delta", "delta": delta});
                                    yield Ok(Bytes::from(format!("event: response.output_text.delta\ndata: {output}\n\n")));
                                }
                            }
                        }
                    }
                }
                Err(error) => { yield Err(error); break; }
            }
        }
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(axum::body::Body::from_stream(stream))
        .unwrap_or_else(|_| {
            openai_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not create response stream",
                "internal_error",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{default_config, ProviderConfig},
        router::Router,
        vault::{Vault, VaultEntry},
    };
    use std::sync::{Arc, Mutex, RwLock};
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[test]
    fn stream_usage_reads_openai_gemini_and_responses_shapes() {
        assert_eq!(
            stream_usage(r#"{"usage":{"prompt_tokens":3,"completion_tokens":5}}"#),
            (3, 5)
        );
        assert_eq!(
            stream_usage(r#"{"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":11}}"#),
            (7, 11)
        );
        assert_eq!(
            stream_usage(r#"{"response":{"usage":{"input_tokens":13,"output_tokens":17}}}"#),
            (13, 17)
        );
    }

    fn state(server: &MockServer) -> AppState {
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
        config.routing.default_provider = Some("mock".to_string());
        let vault = Arc::new(RwLock::new(Vault {
            entries: vec![
                VaultEntry {
                    key_alias: "bad".to_string(),
                    provider: "mock".to_string(),
                    api_key: "bad-key".to_string(),
                    priority: 1,
                    enabled: true,
                    ..Default::default()
                },
                VaultEntry {
                    key_alias: "good".to_string(),
                    provider: "mock".to_string(),
                    api_key: "good-key".to_string(),
                    priority: 2,
                    enabled: true,
                    ..Default::default()
                },
            ],
            master_key: vec![0; 32],
        }));
        let config = Arc::new(RwLock::new(config));
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                provider TEXT NOT NULL, key_alias TEXT NOT NULL, model TEXT NOT NULL,
                status INTEGER NOT NULL, latency_ms INTEGER NOT NULL,
                prompt_tokens INTEGER NOT NULL, completion_tokens INTEGER NOT NULL,
                est_cost_usd REAL NOT NULL
            );
            CREATE TABLE budget_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL,
                key_alias TEXT NOT NULL, period TEXT NOT NULL,
                total_cost_usd REAL NOT NULL DEFAULT 0.0,
                UNIQUE(provider, key_alias, period)
            );",
        )
        .unwrap();
        AppState {
            router: Arc::new(Router::new(vault.clone(), config.clone())),
            config,
            vault,
            db: Arc::new(Mutex::new(db)),
            http_client: reqwest::Client::new(),
            start_time: Instant::now(),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rate_limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
            catalog: Arc::new(RwLock::new(std::collections::HashMap::new())),
            auth_sessions: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    #[tokio::test]
    async fn forwards_system_message_and_extra_params_to_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chat_mock", "model": "test-model",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let state = state(&server);
        let response = chat_completions(
            State(state),
            Json(ChatRequest {
                model: "mock/test-model".to_string(),
                messages: vec![
                    crate::providers::Message {
                        role: "system".to_string(),
                        content: Some(json!("be terse")),
                        extra: serde_json::Map::new(),
                    },
                    crate::providers::Message {
                        role: "user".to_string(),
                        content: Some(json!("hi")),
                        extra: serde_json::Map::new(),
                    },
                ],
                stream: None,
                temperature: Some(0.5),
                max_tokens: Some(64),
                top_p: None,
                extra: {
                    let mut map = serde_json::Map::new();
                    map.insert("reasoning_effort".to_string(), json!("high"));
                    map
                },
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let forwarded: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(forwarded["model"], "test-model");
        assert_eq!(forwarded["messages"][0]["role"], "system");
        assert_eq!(forwarded["messages"][0]["content"], "be terse");
        assert_eq!(forwarded["messages"][1]["content"], "hi");
        assert_eq!(forwarded["reasoning_effort"], "high");
        assert_eq!(forwarded["temperature"], 0.5);
    }

    #[tokio::test]
    async fn rate_limited_key_fails_over_to_the_next_key() {
        let server = MockServer::start().await;
        // priority-1 key is rate limited; the request must be retried on the
        // next eligible key within the same gateway call.
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer bad-key"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer good-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chat_mock", "model": "test-model",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2}
            })))
            .mount(&server)
            .await;

        let state = state(&server);
        let response = chat_completions(
            State(state.clone()),
            Json(ChatRequest {
                model: "test-model".to_string(),
                messages: vec![],
                stream: None,
                temperature: None,
                max_tokens: None,
                top_p: None,
                extra: serde_json::Map::new(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["choices"][0]["message"]["content"],
            "ok"
        );
        // the rate-limited key is cooling down, not disabled
        let vault = state.vault.read().unwrap();
        let limited = &vault.entries[0];
        assert_eq!(limited.key_alias, "bad");
        assert!(limited.enabled, "a 429 must disable nothing");
        assert!(
            limited
                .cooldown_until
                .is_some_and(|until| until > chrono::Utc::now()),
            "a 429 must put the key on cooldown"
        );
        let logs = db::get_logs(&state.db.lock().unwrap(), 10, 0).unwrap();
        assert_eq!(
            logs.len(),
            2,
            "both the failed attempt and retry should be visible"
        );
        assert!(logs.iter().any(|entry| entry.status == 429));
        assert!(logs.iter().any(|entry| entry.status == 200));
    }

    fn add_native_provider(state: &AppState, server_uri: String, format: &str) {
        state.config.write().unwrap().providers.insert(
            "native".to_string(),
            crate::config::ProviderConfig {
                name: "Native".to_string(),
                base_url: server_uri,
                enabled: true,
                round_robin: false,
                format: Some(format.to_string()),
            },
        );
        state
            .vault
            .write()
            .unwrap()
            .entries
            .push(crate::vault::VaultEntry {
                key_alias: "native-key".to_string(),
                provider: "native".to_string(),
                api_key: "good-key".to_string(),
                priority: 1,
                enabled: true,
                ..Default::default()
            });
    }

    fn user_messages() -> Vec<crate::providers::Message> {
        vec![
            crate::providers::Message {
                role: "system".to_string(),
                content: Some(json!("be terse")),
                extra: serde_json::Map::new(),
            },
            crate::providers::Message {
                role: "user".to_string(),
                content: Some(json!("hi")),
                extra: serde_json::Map::new(),
            },
        ]
    }

    #[tokio::test]
    async fn anthropic_format_translates_requests_and_responses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "good-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_1", "model": "claude-sonnet-5",
                "content": [
                    {"type": "thinking", "thinking": "pondering"},
                    {"type": "text", "text": "bonjour"}
                ],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 4, "output_tokens": 2}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let state = state(&server);
        add_native_provider(&state, server.uri(), "anthropic");
        let response = chat_completions(
            State(state.clone()),
            Json(ChatRequest {
                model: "native/claude-sonnet-5".to_string(),
                messages: user_messages(),
                stream: None,
                temperature: None,
                max_tokens: Some(64),
                top_p: None,
                extra: serde_json::Map::new(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["choices"][0]["message"]["content"], "bonjour");
        assert_eq!(
            payload["choices"][0]["message"]["reasoning_content"],
            "pondering"
        );
        assert_eq!(payload["usage"]["prompt_tokens"], 4);
        assert_eq!(payload["usage"]["completion_tokens"], 2);

        let requests = server.received_requests().await.unwrap();
        let upstream: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(upstream["model"], "claude-sonnet-5");
        assert_eq!(upstream["system"], "be terse");
        assert_eq!(upstream["messages"].as_array().unwrap().len(), 1);
        assert_eq!(upstream["max_tokens"], 64);
    }

    #[tokio::test]
    async fn gemini_format_translates_requests_and_responses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-3-flash:generateContent"))
            .and(header("x-goog-api-key", "good-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "candidates": [{"content": {"parts": [{"text": "salut"}]}, "finishReason": "STOP"}],
                "usageMetadata": {"promptTokenCount": 6, "candidatesTokenCount": 2, "totalTokenCount": 8},
                "modelVersion": "gemini-3-flash"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let state = state(&server);
        add_native_provider(&state, server.uri(), "gemini");
        let response = chat_completions(
            State(state),
            Json(ChatRequest {
                model: "native/gemini-3-flash".to_string(),
                messages: user_messages(),
                stream: None,
                temperature: None,
                max_tokens: None,
                top_p: None,
                extra: serde_json::Map::new(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["choices"][0]["message"]["content"], "salut");
        assert_eq!(payload["usage"]["prompt_tokens"], 6);
        assert_eq!(payload["choices"][0]["finish_reason"], "stop");

        let requests = server.received_requests().await.unwrap();
        let upstream: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(
            upstream["systemInstruction"]["parts"][0]["text"],
            "be terse"
        );
        assert_eq!(upstream["contents"][0]["role"], "user");
        assert_eq!(upstream["contents"][0]["parts"][0]["text"], "hi");
    }

    #[tokio::test]
    async fn anthropic_format_translates_streams() {
        let server = MockServer::start().await;
        let body = "event: content_block_delta
data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"he\"}}

 event: content_block_delta
data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"llo\"}}

event: message_stop
data: {}

"
        .replace(" event:", "event:");
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
            .mount(&server)
            .await;

        let state = state(&server);
        add_native_provider(&state, server.uri(), "anthropic");
        let response = chat_completions(
            State(state),
            Json(ChatRequest {
                model: "native/claude".to_string(),
                messages: user_messages(),
                stream: Some(true),
                temperature: None,
                max_tokens: None,
                top_p: None,
                extra: serde_json::Map::new(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let events = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(events.contains("\"delta\":{\"content\":\"he\"}"));
        assert!(events.contains("\"delta\":{\"content\":\"llo\"}"));
        assert!(events.trim_end().ends_with("data: [DONE]"));
    }

    #[tokio::test]
    async fn models_endpoint_aggregates_catalog_and_aliases() {
        let server = MockServer::start().await;
        let state = state(&server);
        state.catalog.write().unwrap().insert(
            "mock".to_string(),
            vec![
                crate::api::CatalogModel {
                    id: "model-a".to_string(),
                    tier: "free".to_string(),
                },
                crate::api::CatalogModel {
                    id: "model-b".to_string(),
                    tier: "paid".to_string(),
                },
            ],
        );
        state
            .config
            .write()
            .unwrap()
            .routing
            .model_map
            .insert("fast".to_string(), "mock/model-a".to_string());

        let response = list_models(State(state)).await.into_response();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();
        let ids: Vec<&str> = payload["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|model| model["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"mock/model-a"));
        assert!(ids.contains(&"mock/model-b"));
        assert!(ids.contains(&"fast"));
    }

    #[tokio::test]
    async fn gitcommit_tool_uses_the_configured_utility_model() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chat_mock", "model": "test-model",
                "choices": [{"message": {"content": "Add encrypted key vault\n\n- AES-256-GCM at rest\n- keyring-backed master key"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 8}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let state = state(&server);

        let dir = std::env::temp_dir().join(format!("skyport-gitcommit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut config = state.config.write().unwrap();
            config.utility.model = Some("mock/test-model".to_string());
            config.utility.workspace = Some(dir.to_string_lossy().into_owned());
            config.utility.allow_cloud = true;
        }
        let result = crate::tools::gitcommit::run(
            &state,
            Some("diff --git a/src/vault.rs b/src/vault.rs\n+ encrypt everything".to_string()),
            dir.to_str().unwrap(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            result.commit_message.lines().next().unwrap(),
            "Add encrypted key vault"
        );
        assert_eq!(result.model, "test-model");
        std::fs::remove_dir_all(&dir).ok();

        let requests = server.received_requests().await.unwrap();
        let forwarded: Value = serde_json::from_slice(&requests[0].body).unwrap();
        // the utility call must run with conservative sampling and no coding-model tokens
        assert_eq!(forwarded["model"], "test-model");
        assert_eq!(forwarded["temperature"], 0.2);
        assert_eq!(forwarded["messages"][0]["role"], "system");
    }

    #[tokio::test]
    async fn retries_an_unauthorized_key_and_logs_the_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer bad-key"))
            .respond_with(
                ResponseTemplate::new(401).set_body_json(json!({"error": {"message": "bad key"}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer good-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chat_mock", "model": "test-model", "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2}
            })))
            .mount(&server)
            .await;

        let state = state(&server);
        let response = chat_completions(
            State(state.clone()),
            Json(ChatRequest {
                model: "test-model".to_string(),
                messages: vec![],
                stream: Some(false),
                temperature: None,
                max_tokens: None,
                top_p: None,
                extra: serde_json::Map::new(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["choices"][0]["message"]["content"],
            "ok"
        );
        assert!(!state.vault.read().unwrap().entries[0].enabled);
    }

    #[tokio::test]
    async fn translates_chat_sse_to_responses_events() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer bad-key"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n",
                "text/event-stream",
            ))
            .mount(&server)
            .await;
        let state = state(&server);
        let response = responses(
            State(state),
            Json(json!({"model": "test-model", "input": "hi", "stream": true})),
        )
        .await;
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let events = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(events.contains("event: response.created"));
        assert!(events.contains("event: response.output_text.delta"));
        assert!(events.contains("hello"));
        assert!(events.contains("event: response.completed"));
    }

    fn make_responses_provider(state: &AppState, uri: String, oauth: bool) {
        state
            .config
            .write()
            .unwrap()
            .providers
            .get_mut("mock")
            .unwrap()
            .base_url = format!("{uri}/v1");
        state
            .config
            .write()
            .unwrap()
            .providers
            .get_mut("mock")
            .unwrap()
            .format = Some("responses".to_string());
        let mut vault = state.vault.write().unwrap();
        // The router prefers the "bad" key (lower priority); tests pin the
        // selected credential to the entry the mock server expects.
        if let Some(entry) = vault.entries.iter_mut().find(|e| e.key_alias == "bad") {
            entry.enabled = false;
        }
        if let Some(entry) = vault.entries.iter_mut().find(|e| e.key_alias == "good") {
            if oauth {
                entry.oauth_provider = Some("grok".to_string());
                entry.oauth_extra = Some(json!({
                    "x-xai-token-auth": "xai-grok-cli",
                    "x-grok-client-identifier": "grok-shell",
                    "account": "sub-account"
                }));
            }
        }
    }

    #[tokio::test]
    async fn responses_format_upstream_round_trips_with_oauth_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .and(header("authorization", "Bearer good-key"))
            .and(header("x-xai-token-auth", "xai-grok-cli"))
            .and(header("x-grok-client-identifier", "grok-shell"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "resp_1", "object": "response", "status": "completed",
                "model": "test-model", "created_at": 123,
                "output": [{"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "okay"}
                ]}],
                "usage": {"input_tokens": 4, "output_tokens": 2, "total_tokens": 6}
            })))
            .mount(&server)
            .await;

        let state = state(&server);
        make_responses_provider(&state, server.uri(), true);
        let response = chat_completions(
            State(state),
            Json(ChatRequest {
                model: "mock/test-model".to_string(),
                messages: vec![crate::providers::Message {
                    role: "user".to_string(),
                    content: Some(json!("hi")),
                    extra: serde_json::Map::new(),
                }],
                stream: None,
                temperature: None,
                max_tokens: Some(64),
                top_p: None,
                extra: serde_json::Map::new(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["choices"][0]["message"]["content"], "okay");
        assert_eq!(payload["usage"]["prompt_tokens"], 4);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let forwarded: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(forwarded["input"][0]["role"], "user");
        assert_eq!(forwarded["input"][0]["content"][0]["type"], "input_text");
        assert_eq!(forwarded["max_output_tokens"], 64);
    }

    #[tokio::test]
    async fn responses_format_stream_translates_to_chat_chunks() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n\
                 data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"output_tokens\":7}}}\n\n",
                "text/event-stream",
            ))
            .mount(&server)
            .await;
        let state = state(&server);
        make_responses_provider(&state, server.uri(), false);
        let response = chat_completions(
            State(state.clone()),
            Json(ChatRequest {
                model: "mock/test-model".to_string(),
                messages: vec![],
                stream: Some(true),
                temperature: None,
                max_tokens: None,
                top_p: None,
                extra: serde_json::Map::new(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            state.in_flight.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a streaming request must stay in flight until its body is consumed"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(
            state.in_flight.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "consuming the stream must release its in-flight lease"
        );
        let events = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(events.contains(r#""content":"hi""#));
        assert!(events.contains(r#""finish_reason":"stop""#));
        assert!(events.contains("data: [DONE]"));
    }

    #[tokio::test]
    async fn global_rate_limit_blocks_excessive_requests_and_sets_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chat_mock", "model": "test-model",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}
            })))
            .mount(&server)
            .await;

        let state = state(&server);
        {
            let mut cfg = state.config.write().unwrap();
            cfg.rate_limit.max_rpm = Some(2);
        }

        let make_req = || {
            let s = state.clone();
            async move {
                chat_completions(
                    State(s),
                    Json(ChatRequest {
                        model: "mock/test-model".to_string(),
                        messages: vec![],
                        stream: None,
                        temperature: None,
                        max_tokens: None,
                        top_p: None,
                        extra: serde_json::Map::new(),
                    }),
                )
                .await
            }
        };

        let res1 = make_req().await;
        assert_eq!(res1.status(), StatusCode::OK);

        let res2 = make_req().await;
        assert_eq!(res2.status(), StatusCode::OK);

        let res3 = make_req().await;
        assert_eq!(res3.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(res3.headers().contains_key(axum::http::header::RETRY_AFTER));

        let bytes = axum::body::to_bytes(res3.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["error"]["code"], "rate_limit_exceeded");
    }

    #[tokio::test]
    async fn scoped_budget_rate_limit_blocks_excessive_requests() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chat_mock", "model": "test-model",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}
            })))
            .mount(&server)
            .await;

        let state = state(&server);
        {
            let mut cfg = state.config.write().unwrap();
            cfg.budgets.insert(
                "mock".to_string(),
                crate::config::BudgetConfig {
                    monthly_cap_usd: None,
                    daily_cap_usd: None,
                    max_rpm: Some(1),
                },
            );
        }

        let make_req = || {
            let s = state.clone();
            async move {
                chat_completions(
                    State(s),
                    Json(ChatRequest {
                        model: "mock/test-model".to_string(),
                        messages: vec![],
                        stream: None,
                        temperature: None,
                        max_tokens: None,
                        top_p: None,
                        extra: serde_json::Map::new(),
                    }),
                )
                .await
            }
        };

        let res1 = make_req().await;
        assert_eq!(res1.status(), StatusCode::OK);

        let res2 = make_req().await;
        assert_eq!(res2.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(res2.headers().contains_key(axum::http::header::RETRY_AFTER));

        let bytes = axum::body::to_bytes(res2.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["error"]["code"], "rate_limit_exceeded");
    }
}
