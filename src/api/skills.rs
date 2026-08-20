use std::collections::{HashMap, HashSet};
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{api::AppState, db};

const CATALOG_URL: &str = "https://raw.githubusercontent.com/NVIDIA/skills/main/.github/scripts/marketplace/metadata.json";
const SOURCE_URL: &str = "https://github.com/NVIDIA/skills";
const CC_LICENSE_URL: &str = "https://github.com/NVIDIA/skills/blob/main/LICENSE-CC-BY-4.0";
const APACHE_LICENSE_URL: &str = "https://github.com/NVIDIA/skills/blob/main/LICENSE-APACHE";
const MAX_CATALOG_BYTES: usize = 2 * 1024 * 1024;
const MAX_SKILLS: usize = 1_000;
const SKILLS_CLI_PACKAGE: &str = "skills@1.5.23";
static SKILL_OPERATION: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[derive(Deserialize)]
struct RemoteCatalog {
    skills: Vec<RemoteSkill>,
}

#[derive(Deserialize)]
struct RemoteSkill {
    path: String,
    name: String,
    description: String,
    #[serde(default)]
    metadata: HashMap<String, Value>,
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({"ok": false, "error": message.into()}))).into_response()
}

fn catalog_payload(skills: Vec<db::SkillRecord>) -> Value {
    let available = skills.iter().filter(|skill| skill.available).count();
    let enabled = skills.iter().filter(|skill| skill.enabled).count();
    let downloaded = skills
        .iter()
        .filter(|skill| skill.installed_at.is_some())
        .count();
    json!({
        "ok": true,
        "skills": skills,
        "total": available,
        "enabled": enabled,
        "downloaded": downloaded,
        "source": SOURCE_URL,
        "license": {
            "summary": "NVIDIA skill content is CC BY 4.0; source code is Apache 2.0.",
            "cc_by_4_0": CC_LICENSE_URL,
            "apache_2_0": APACHE_LICENSE_URL
        }
    })
}

fn valid_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn metadata_text(metadata: &HashMap<String, Value>, key: &str) -> String {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .chars()
        .take(512)
        .collect()
}

fn parse_catalog(bytes: &[u8], fetched_at: &str) -> Result<Vec<db::SkillRecord>, String> {
    let remote: RemoteCatalog =
        serde_json::from_slice(bytes).map_err(|_| "NVIDIA returned invalid catalog JSON")?;
    if remote.skills.is_empty() || remote.skills.len() > MAX_SKILLS {
        return Err("NVIDIA returned an invalid skill count".to_string());
    }

    let mut names = HashSet::with_capacity(remote.skills.len());
    let mut skills = Vec::with_capacity(remote.skills.len());
    for remote in remote.skills {
        let expected_path = format!("skills/{}", remote.name);
        if !valid_skill_name(&remote.name)
            || remote.path != expected_path
            || !names.insert(remote.name.clone())
            || remote.description.trim().is_empty()
            || remote.description.len() > 16 * 1024
        {
            return Err("NVIDIA returned invalid skill metadata".to_string());
        }
        skills.push(db::SkillRecord {
            name: remote.name,
            path: remote.path,
            description: remote.description.trim().to_string(),
            product: metadata_text(&remote.metadata, "product.primary"),
            category: metadata_text(&remote.metadata, "classification.category.primary"),
            subdomain: metadata_text(&remote.metadata, "catalog.subdomain"),
            audience: metadata_text(&remote.metadata, "audience"),
            activity_tags: metadata_text(&remote.metadata, "discovery.activity_tags"),
            enabled: false,
            available: true,
            catalog_updated_at: fetched_at.to_string(),
            installed_at: None,
        });
    }
    skills.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(skills)
}

fn read_catalog(state: &AppState) -> Result<Vec<db::SkillRecord>, String> {
    let connection = state
        .db
        .lock()
        .map_err(|_| "Database lock poisoned".to_string())?;
    db::list_skills(&connection).map_err(|_| "Could not read the skills catalog".to_string())
}

pub async fn list_skills(State(state): State<AppState>) -> Response {
    match read_catalog(&state) {
        Ok(skills) => (StatusCode::OK, Json(catalog_payload(skills))).into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}

pub async fn refresh_skills(State(state): State<AppState>) -> Response {
    let response = match state
        .http_client
        .get(CATALOG_URL)
        .timeout(Duration::from_secs(20))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            return error(
                StatusCode::BAD_GATEWAY,
                format!(
                    "NVIDIA catalog returned HTTP {}",
                    response.status().as_u16()
                ),
            )
        }
        Err(network_error) => {
            return error(
                StatusCode::BAD_GATEWAY,
                crate::security::safe_network_error(&network_error),
            )
        }
    };
    let bytes = match crate::security::read_limited_body(response, MAX_CATALOG_BYTES).await {
        Ok(bytes) => bytes,
        Err(message) => return error(StatusCode::BAD_GATEWAY, message),
    };
    let fetched_at = chrono::Utc::now().to_rfc3339();
    let catalog = match parse_catalog(&bytes, &fetched_at) {
        Ok(catalog) => catalog,
        Err(message) => return error(StatusCode::BAD_GATEWAY, message),
    };
    let mut connection = match state.db.lock() {
        Ok(connection) => connection,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned"),
    };
    if db::upsert_skill_catalog(&mut connection, &catalog).is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not store the skills catalog",
        );
    }
    drop(connection);
    match read_catalog(&state) {
        Ok(skills) => (StatusCode::OK, Json(catalog_payload(skills))).into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}

#[cfg(windows)]
fn npx_program() -> &'static str {
    "npx.cmd"
}

#[cfg(not(windows))]
fn npx_program() -> &'static str {
    "npx"
}

fn cli_args(name: &str, enable: bool) -> Vec<String> {
    let mut args = vec!["--yes".to_string(), SKILLS_CLI_PACKAGE.to_string()];
    if enable {
        args.extend(
            [
                "add",
                "NVIDIA/skills",
                "--skill",
                name,
                "--agent",
                "*",
                "--global",
                "--yes",
            ]
            .into_iter()
            .map(str::to_string),
        );
    } else {
        args.extend(
            ["remove", "--global", "--yes", name]
                .into_iter()
                .map(str::to_string),
        );
    }
    args
}

fn safe_cli_message(output: &[u8]) -> String {
    let text = String::from_utf8_lossy(output);
    let clean: String = text
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .collect();
    let clean = clean.trim();
    if clean.is_empty() {
        "The skills CLI did not report a reason".to_string()
    } else {
        clean.chars().take(600).collect()
    }
}

async fn run_skills_cli(name: &str, enable: bool) -> Result<(), String> {
    let mut command = tokio::process::Command::new(npx_program());
    command
        .args(cli_args(name, enable))
        .env("DISABLE_TELEMETRY", "1")
        .env("DO_NOT_TRACK", "1")
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(300), command.output())
        .await
        .map_err(|_| "The skills CLI timed out after five minutes".to_string())?
        .map_err(|_| "Node.js and npx are required to manage global skills".to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let details = if output.stderr.is_empty() {
            safe_cli_message(&output.stdout)
        } else {
            safe_cli_message(&output.stderr)
        };
        Err(format!("Global skill update failed: {details}"))
    }
}

async fn set_enabled(state: AppState, name: String, enabled: bool) -> Response {
    if !valid_skill_name(&name) && !valid_custom_skill_name(&name) {
        return error(StatusCode::BAD_REQUEST, "Invalid skill name");
    }
    let skill = {
        let connection = match state.db.lock() {
            Ok(connection) => connection,
            Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned"),
        };
        match db::get_skill(&connection, &name) {
            Ok(Some(skill)) => skill,
            Ok(None) => return error(StatusCode::NOT_FOUND, "Skill not found in the catalog"),
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not read skill state",
                )
            }
        }
    };
    if enabled && !skill.available && skill.installed_at.is_none() {
        return error(
            StatusCode::CONFLICT,
            "This skill is no longer available upstream",
        );
    }
    if skill.enabled == enabled {
        return (StatusCode::OK, Json(json!({"ok": true, "skill": skill}))).into_response();
    }

    if enabled && skill.installed_at.is_none() {
        let _permit = match SKILL_OPERATION.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Skill installer unavailable",
                )
            }
        };
        if let Err(message) = run_skills_cli(&name, true).await {
            return error(StatusCode::BAD_GATEWAY, message);
        }
    }

    let updated = {
        let connection = match state.db.lock() {
            Ok(connection) => connection,
            Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned"),
        };
        match db::set_skill_enabled(&connection, &name, enabled) {
            Ok(true) => db::get_skill(&connection, &name).ok().flatten(),
            _ => None,
        }
    };
    match updated {
        Some(skill) => (StatusCode::OK, Json(json!({"ok": true, "skill": skill}))).into_response(),
        None => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not persist skill state",
        ),
    }
}

pub async fn enable_skill(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    set_enabled(state, name, true).await
}

pub async fn disable_skill(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    set_enabled(state, name, false).await
}

#[derive(Deserialize)]
pub struct ImportSkillRequest {
    pub source: String,
    pub skill: Option<String>,
    pub product: Option<String>,
    pub category: Option<String>,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct InspectSkillRequest {
    pub source: String,
}

pub fn valid_skill_source(source: &str) -> bool {
    let s = source.trim();
    if s.is_empty() || s.len() > 256 {
        return false;
    }
    if s.starts_with('-') || s.starts_with('/') || s.starts_with('.') || s.contains("..") {
        return false;
    }
    if let Some(rest) = s.strip_prefix('@') {
        if !rest.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            return false;
        }
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':' | b'@'))
}

pub fn valid_custom_skill_name(name: &str) -> bool {
    let n = name.trim();
    if n.is_empty() || n.len() > 128 {
        return false;
    }
    if !n.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return false;
    }
    if n.contains("..") {
        return false;
    }
    n.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub async fn import_custom_skill(
    State(state): State<AppState>,
    Json(payload): Json<ImportSkillRequest>,
) -> Response {
    let source = payload.source.trim();
    if !valid_skill_source(source) {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid skill source package or URL",
        );
    }
    let skill_param = payload
        .skill
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(skill_name) = skill_param {
        if !valid_custom_skill_name(skill_name) {
            return error(StatusCode::BAD_REQUEST, "Invalid skill name");
        }
    }

    let _permit = match SKILL_OPERATION.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Skill installer unavailable",
            )
        }
    };

    let mut args = vec![
        "--yes".to_string(),
        SKILLS_CLI_PACKAGE.to_string(),
        "add".to_string(),
        source.to_string(),
    ];
    if let Some(skill_name) = skill_param {
        args.extend(["--skill".to_string(), skill_name.to_string()]);
    }
    args.extend([
        "--agent".to_string(),
        "*".to_string(),
        "--global".to_string(),
        "--yes".to_string(),
    ]);

    let mut command = tokio::process::Command::new(npx_program());
    command
        .args(args)
        .env("DISABLE_TELEMETRY", "1")
        .env("DO_NOT_TRACK", "1")
        .kill_on_drop(true);

    let output = match tokio::time::timeout(Duration::from_secs(300), command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(_)) => {
            return error(
                StatusCode::BAD_GATEWAY,
                "Node.js and npx are required to install custom skills",
            )
        }
        Err(_) => {
            return error(
                StatusCode::GATEWAY_TIMEOUT,
                "The skills CLI timed out after 5 minutes",
            )
        }
    };

    if !output.status.success() {
        let details = if output.stderr.is_empty() {
            safe_cli_message(&output.stdout)
        } else {
            safe_cli_message(&output.stderr)
        };
        return error(
            StatusCode::BAD_GATEWAY,
            format!("Custom skill import failed: {details}"),
        );
    }

    let derived_name = if let Some(skill_name) = skill_param {
        skill_name.to_string()
    } else {
        source
            .split('/')
            .last()
            .unwrap_or(source)
            .trim_end_matches(".git")
            .to_string()
    };

    let now = chrono::Utc::now().to_rfc3339();
    let record = db::SkillRecord {
        name: derived_name.clone(),
        path: format!("custom/{source}"),
        description: payload
            .description
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| format!("Custom skill imported from {source}")),
        product: payload
            .product
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| source.to_string()),
        category: payload
            .category
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| "custom".to_string()),
        subdomain: "custom".to_string(),
        audience: "developer".to_string(),
        activity_tags: "custom,imported".to_string(),
        enabled: true,
        available: true,
        catalog_updated_at: now.clone(),
        installed_at: Some(now),
    };

    let connection = match state.db.lock() {
        Ok(connection) => connection,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned"),
    };

    if let Err(e) = db::insert_custom_skill(&connection, &record) {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Could not store custom skill: {e}"),
        );
    }

    (StatusCode::OK, Json(json!({"ok": true, "skill": record}))).into_response()
}

pub async fn inspect_custom_skill(
    State(_state): State<AppState>,
    Json(payload): Json<InspectSkillRequest>,
) -> Response {
    let source = payload.source.trim();
    if !valid_skill_source(source) {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid skill source package or URL",
        );
    }

    let _permit = match SKILL_OPERATION.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Skill inspector unavailable",
            )
        }
    };

    let args = vec![
        "--yes".to_string(),
        SKILLS_CLI_PACKAGE.to_string(),
        "add".to_string(),
        source.to_string(),
        "--list".to_string(),
    ];

    let mut command = tokio::process::Command::new(npx_program());
    command
        .args(args)
        .env("DISABLE_TELEMETRY", "1")
        .env("DO_NOT_TRACK", "1")
        .kill_on_drop(true);

    let output = match tokio::time::timeout(Duration::from_secs(120), command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(_)) => {
            return error(
                StatusCode::BAD_GATEWAY,
                "Node.js and npx are required to inspect skills",
            )
        }
        Err(_) => return error(StatusCode::GATEWAY_TIMEOUT, "Skills inspection timed out"),
    };

    if !output.status.success() {
        let details = if output.stderr.is_empty() {
            safe_cli_message(&output.stdout)
        } else {
            safe_cli_message(&output.stderr)
        };
        return error(
            StatusCode::BAD_GATEWAY,
            format!("Could not inspect package: {details}"),
        );
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let skills = parse_inspect_output(&text);

    (StatusCode::OK, Json(json!({"ok": true, "skills": skills}))).into_response()
}

pub fn parse_inspect_output(output: &str) -> Vec<Value> {
    let mut skills = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_desc = String::new();

    for raw_line in output.lines() {
        let line =
            raw_line.trim_matches(|c: char| c.is_whitespace() || c == '|' || c == '•' || c == 'o');
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("Available Skills")
            || line.starts_with("Source:")
            || line.starts_with("Found ")
            || line.starts_with("Use --skill")
            || line.starts_with("Done")
            || line.contains("Agent detected")
        {
            continue;
        }

        let candidate = line.trim_start_matches('-').trim();
        if candidate.is_empty() {
            continue;
        }

        if !candidate.contains(' ') && valid_custom_skill_name(candidate) {
            if let Some(name) = current_name.take() {
                skills.push(json!({
                    "name": name,
                    "description": current_desc.trim()
                }));
                current_desc.clear();
            }
            current_name = Some(candidate.to_string());
        } else if current_name.is_some() {
            if !current_desc.is_empty() {
                current_desc.push(' ');
            }
            current_desc.push_str(line);
        }
    }

    if let Some(name) = current_name {
        skills.push(json!({
            "name": name,
            "description": current_desc.trim()
        }));
    }

    skills
}

pub async fn delete_custom_skill(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if !valid_custom_skill_name(&name) && !valid_skill_name(&name) {
        return error(StatusCode::BAD_REQUEST, "Invalid skill name");
    }

    let _permit = match SKILL_OPERATION.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Skill uninstaller unavailable",
            )
        }
    };

    let _ = run_skills_cli(&name, false).await;

    let connection = match state.db.lock() {
        Ok(connection) => connection,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned"),
    };

    match db::uninstall_skill(&connection, &name) {
        Ok(true) => (StatusCode::OK, Json(json!({"ok": true, "deleted": name}))).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "Skill not found in catalog"),
        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Could not uninstall skill: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_official_metadata_shape() {
        let payload = br#"{
            "skills": [{
                "path": "skills/skill-card-generator",
                "name": "skill-card-generator",
                "description": "Generate a governance card.",
                "metadata": {
                    "product.primary": "Skill Card Generator",
                    "classification.category.primary": "developer_tools",
                    "catalog.subdomain": "agentic-ai",
                    "audience": "developer",
                    "discovery.activity_tags": "generate,validate"
                }
            }]
        }"#;
        let skills = parse_catalog(payload, "2026-08-19T00:00:00Z").unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].product, "Skill Card Generator");
        assert!(!skills[0].enabled);
    }

    #[test]
    fn rejects_catalog_path_traversal() {
        let payload = br#"{
            "skills": [{
                "path": "skills/../bad",
                "name": "bad",
                "description": "Bad path",
                "metadata": {}
            }]
        }"#;
        assert!(parse_catalog(payload, "now").is_err());
    }

    #[test]
    fn installer_is_global_and_all_agent() {
        let install = cli_args("skill-card-generator", true);
        assert!(install.windows(2).any(|pair| pair == ["--agent", "*"]));
        assert!(install.iter().any(|argument| argument == "--global"));
        assert!(install
            .windows(2)
            .any(|pair| pair == ["--skill", "skill-card-generator"]));

        let remove = cli_args("skill-card-generator", false);
        assert!(!remove.windows(2).any(|pair| pair == ["--agent", "*"]));
        assert!(remove.iter().any(|argument| argument == "--global"));
        assert!(remove
            .iter()
            .any(|argument| argument == "skill-card-generator"));
    }

    #[test]
    fn valid_source_and_name_rules() {
        assert!(valid_skill_source("vercel-labs/agent-skills"));
        assert!(valid_skill_source("https://github.com/owner/repo.git"));
        assert!(valid_skill_source("@scope/package-name"));
        assert!(!valid_skill_source("bad source with spaces"));
        assert!(!valid_skill_source("bad;command"));
        assert!(!valid_skill_source("--extra-flag"));
        assert!(!valid_skill_source("-f"));
        assert!(!valid_skill_source("../relative/path"));
        assert!(!valid_skill_source("/absolute/path"));
        assert!(!valid_skill_source("@/bad-scope"));

        assert!(valid_custom_skill_name("vercel-optimize"));
        assert!(valid_custom_skill_name("my_custom_skill.v2"));
        assert!(!valid_custom_skill_name("bad name with spaces"));
        assert!(!valid_custom_skill_name("--flag-name"));
        assert!(!valid_custom_skill_name("-name"));
        assert!(!valid_custom_skill_name(".hidden"));
        assert!(!valid_custom_skill_name("_private"));
    }

    #[test]
    fn parses_inspect_cli_output() {
        let output = r#"
|  Fetching skills…
|  Found 2 skills
|
|  Available Skills
|
|    vercel-optimize
|      React and Next.js optimization guidelines.
|
|    deploy-to-vercel
|      Deploy applications to Vercel.
|
— Done!
"#;
        let skills = parse_inspect_output(output);
        assert_eq!(skills.len(), 2);
        assert_eq!(skills[0]["name"], "vercel-optimize");
        assert_eq!(skills[1]["name"], "deploy-to-vercel");
    }
}
