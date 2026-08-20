//! HTTP surface for harness-independent tools.

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::AppState;

#[derive(Deserialize)]
pub struct UtilityConfigRequest {
    pub model: Option<String>,
    pub workspace: Option<String>,
    pub allow_cloud: Option<bool>,
}

#[derive(Deserialize)]
pub struct GitcommitRequest {
    pub diff: Option<String>,
    pub workspace: Option<String>,
    pub instructions: Option<String>,
}

#[derive(Deserialize)]
pub struct BtwRequest {
    pub question: String,
    pub workspace: Option<String>,
}

/// GET /api/tools/config
pub async fn get_utility_config(State(state): State<AppState>) -> Json<Value> {
    let config = state
        .config
        .read()
        .map(|config| config.utility.clone())
        .unwrap_or_default();
    Json(json!({
        "model": config.model,
        "workspace": config.workspace,
        "allow_cloud": config.allow_cloud,
    }))
}

/// POST /api/tools/config
pub async fn set_utility_config(
    State(state): State<AppState>,
    Json(body): Json<UtilityConfigRequest>,
) -> (StatusCode, Json<Value>) {
    let mut config = match state.config.write() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "Configuration is unavailable"})),
            )
        }
    };
    let previous = config.clone();
    config.utility.model = body.model.filter(|value| !value.trim().is_empty());
    config.utility.workspace = body.workspace.filter(|value| !value.trim().is_empty());
    if let Some(allow_cloud) = body.allow_cloud {
        config.utility.allow_cloud = allow_cloud;
    }
    let snapshot = config.clone();
    drop(config);
    match crate::config::save_config(&snapshot) {
        Ok(()) => (StatusCode::OK, Json(json!({"ok": true}))),
        Err(_) => {
            if let Ok(mut config) = state.config.write() {
                *config = previous;
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "Could not save utility configuration"})),
            )
        }
    }
}

/// POST /api/tools/gitcommit
pub async fn gitcommit(
    State(state): State<AppState>,
    Json(body): Json<GitcommitRequest>,
) -> (StatusCode, Json<Value>) {
    let workspace = body
        .workspace
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_default();

    match crate::tools::gitcommit::run(&state, body.diff, &workspace, body.instructions.as_deref())
        .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(crate::tools::gitcommit::to_json(&result)),
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": error})),
        ),
    }
}

/// POST /api/tools/btw
pub async fn btw(
    State(state): State<AppState>,
    Json(body): Json<BtwRequest>,
) -> (StatusCode, Json<Value>) {
    if body.question.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "Ask a question first"})),
        );
    }
    match crate::tools::btw::run(&state, body.question.trim(), body.workspace.as_deref()).await {
        Ok(result) => (StatusCode::OK, Json(crate::tools::btw::to_json(&result))),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": error})),
        ),
    }
}
