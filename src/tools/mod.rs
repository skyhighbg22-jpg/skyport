//! Harness-independent tools.
//!
//! Utility commands (/gitcommit, /btw) are features of the gateway runtime,
//! not of any coding harness. They observe Skyport's own telemetry and the
//! workspace repository, and they run on a cheap or local "utility model"
//! configured in `utility.model` instead of the developer's coding model.

pub mod btw;
pub mod gitcommit;

use crate::api::AppState;
use crate::providers::ChatRequest;
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_GIT_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_GIT_OUTPUT_CHARS: usize = 256_000;
const MAX_REPO_FACT_CHARS: usize = 8_000;
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const TRUNCATION_MARKER: &str = "\n... [truncated]";

#[derive(Debug)]
pub(crate) struct Workspace {
    root: PathBuf,
    path: PathBuf,
}

impl Workspace {
    fn resolve(configured_root: Option<&str>, requested: Option<&str>) -> Result<Self, String> {
        let configured_root = configured_root
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "No workspace is configured. Set utility.workspace before using workspace tools."
                    .to_string()
            })?;
        let root = std::fs::canonicalize(configured_root)
            .ok()
            .filter(|path| path.is_dir())
            .ok_or_else(|| "The configured workspace is unavailable.".to_string())?;

        let requested = requested.map(str::trim).filter(|value| !value.is_empty());
        let candidate = match requested {
            None => root.clone(),
            Some(value) if value == configured_root => root.clone(),
            Some(value) if Path::new(value).is_absolute() => PathBuf::from(value),
            Some(value) => root.join(value),
        };
        let path = std::fs::canonicalize(candidate)
            .ok()
            .filter(|path| path.is_dir() && path.starts_with(&root))
            .ok_or_else(|| {
                "The requested workspace is unavailable or outside the configured workspace."
                    .to_string()
            })?;
        Ok(Self { root, path })
    }

    fn verified_path(&self) -> Result<PathBuf, String> {
        let root = std::fs::canonicalize(&self.root)
            .ok()
            .filter(|path| path.is_dir())
            .ok_or_else(|| "The configured workspace is unavailable.".to_string())?;
        std::fs::canonicalize(&self.path)
            .ok()
            .filter(|path| path.is_dir() && path.starts_with(&root))
            .ok_or_else(|| {
                "The requested workspace is unavailable or outside the configured workspace."
                    .to_string()
            })
    }
}

pub(crate) fn resolve_workspace(
    state: &AppState,
    requested: Option<&str>,
) -> Result<Workspace, String> {
    let configured_root = state
        .config
        .read()
        .map_err(|_| "Configuration is unavailable.".to_string())?
        .utility
        .workspace
        .clone();
    Workspace::resolve(configured_root.as_deref(), requested)
}

pub(crate) fn utility_allows_cloud(config: &crate::config::UtilityConfig) -> bool {
    config.allow_cloud
}

fn ensure_cloud_consent(model: &str, allow_cloud: bool) -> Result<(), String> {
    let explicit_local = model
        .split_once('/')
        .map(|(provider, model_id)| {
            !model_id.trim().is_empty() && matches!(provider, "ollama" | "lmstudio")
        })
        .unwrap_or(false);
    if explicit_local || allow_cloud {
        Ok(())
    } else {
        Err("Cloud utility model access is disabled. Set utility.allow_cloud=true to consent, or select an explicit ollama/... or lmstudio/... model.".to_string())
    }
}

pub(crate) fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let marker_chars = TRUNCATION_MARKER.chars().count();
    if max_chars <= marker_chars {
        return input.chars().take(max_chars).collect();
    }
    let mut output: String = input.chars().take(max_chars - marker_chars).collect();
    output.push_str(TRUNCATION_MARKER);
    output
}

fn has_secret_assignment(line: &str) -> bool {
    const LABELS: &[&str] = &[
        "authorization",
        "api_key",
        "api-key",
        "api key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "auth_token",
        "secret_token",
        "client_secret",
        "aws_secret_access_key",
        "secret",
        "password",
        "passwd",
    ];

    let normalized = line
        .trim_start_matches([' ', '\t', '+', '-'])
        .to_ascii_lowercase();
    LABELS.iter().any(|label| {
        normalized.match_indices(label).any(|(index, _)| {
            normalized[index + label.len()..]
                .trim_start_matches([' ', '\t', '"', '\''])
                .starts_with([':', '='])
        })
    })
}

fn redact_prefixed_tokens(line: &str) -> String {
    const PREFIXES: &[&str] = &[
        "sk-proj-",
        "sk-ant-",
        "sk-",
        "sk_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "github_pat_",
        "glpat-",
        "hf_",
        "npm_",
        "pypi-",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "akia",
        "aiza",
        "ya29.",
    ];

    let lower = line.to_ascii_lowercase();
    let mut output = String::with_capacity(line.len());
    let mut cursor = 0;
    while cursor < line.len() {
        let found = PREFIXES
            .iter()
            .filter_map(|prefix| {
                lower[cursor..]
                    .find(prefix)
                    .map(|offset| (cursor + offset, prefix.len()))
            })
            .min_by_key(|(index, _)| *index);
        let Some((start, prefix_len)) = found else {
            output.push_str(&line[cursor..]);
            break;
        };
        output.push_str(&line[cursor..start]);
        let bytes = line.as_bytes();
        let mut end = start + prefix_len;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric()
                || matches!(bytes[end], b'_' | b'-' | b'.' | b'/' | b'+' | b'='))
        {
            end += 1;
        }
        output.push_str("[REDACTED]");
        cursor = end;
    }
    output
}

fn redact_bearer_token(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let Some(start) = lower.find("bearer ") else {
        return line.to_string();
    };
    let token_start = start + "bearer ".len();
    let token_len = line[token_start..]
        .find(|character: char| character.is_whitespace() || "\"'`,;)]}".contains(character))
        .unwrap_or(line.len() - token_start);
    if token_len == 0 {
        return line.to_string();
    }
    format!(
        "{}Bearer [REDACTED]{}",
        &line[..start],
        &line[token_start + token_len..]
    )
}

pub(crate) fn redact_secrets(input: &str) -> String {
    let mut output = Vec::new();
    let mut in_private_key = false;
    for line in input.lines() {
        let lower = line.to_ascii_lowercase();
        if !in_private_key && lower.contains("-----begin ") && lower.contains("private key-----") {
            output.push("[REDACTED private key]".to_string());
            in_private_key = true;
            continue;
        }
        if in_private_key {
            if lower.contains("-----end ") && lower.contains("private key-----") {
                in_private_key = false;
            }
            continue;
        }
        if has_secret_assignment(line) {
            output.push("[REDACTED likely secret]".to_string());
        } else {
            output.push(redact_prefixed_tokens(&redact_bearer_token(line)));
        }
    }
    output.join("\n")
}

fn redact_absolute_paths(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    let mut index = 0;
    while index < bytes.len() {
        let at_boundary = index == 0
            || bytes[index - 1].is_ascii_whitespace()
            || matches!(bytes[index - 1], b'\'' | b'"' | b'(' | b'[' | b'{' | b'=');
        let windows_path = index + 2 < bytes.len()
            && bytes[index].is_ascii_alphabetic()
            && bytes[index + 1] == b':'
            && matches!(bytes[index + 2], b'/' | b'\\');
        let network_path = index + 1 < bytes.len()
            && ((bytes[index] == b'\\' && bytes[index + 1] == b'\\')
                || (bytes[index] == b'/' && bytes[index + 1] == b'/'));
        let unix_path = bytes[index] == b'/'
            && index + 1 < bytes.len()
            && bytes[index + 1] != b'/'
            && at_boundary;
        if windows_path || (at_boundary && (network_path || unix_path)) {
            output.push_str(&input[cursor..index]);
            let mut end = index
                + if windows_path {
                    3
                } else if network_path {
                    2
                } else {
                    1
                };
            while end < bytes.len()
                && !bytes[end].is_ascii_whitespace()
                && !matches!(
                    bytes[end],
                    b'\'' | b'"' | b'`' | b',' | b';' | b')' | b']' | b'}' | b'<' | b'>'
                )
            {
                end += 1;
            }
            output.push_str("[absolute path]");
            cursor = end;
            index = end;
        } else {
            index += 1;
        }
    }
    output.push_str(&input[cursor..]);
    output
}

pub(crate) fn sanitize_for_model(
    input: &str,
    workspace: Option<&Workspace>,
    max_chars: usize,
) -> String {
    let mut hidden = input.to_string();
    if let Some(workspace) = workspace {
        for path in [&workspace.root, &workspace.path] {
            if let Some(path) = path.to_str().filter(|path| !path.is_empty()) {
                hidden = hidden.replace(path, "[workspace]");
                hidden = hidden.replace(&path.replace('\\', "/"), "[workspace]");
            }
        }
    }
    truncate_chars(&redact_absolute_paths(&redact_secrets(&hidden)), max_chars)
}

/// Answer the user's message using the configured utility model. Returns the
/// assistant text and the route that served it. Reuses the full chat pipeline
/// (routing, keys, failover, budgets, telemetry) by calling the v1 handler
/// in-process.
pub async fn complete(
    state: &AppState,
    system: &str,
    user: &str,
) -> Result<(String, String), String> {
    let (model, allow_cloud) = {
        let config = state
            .config
            .read()
            .map_err(|_| "Configuration is unavailable.".to_string())?;
        let model = config.utility.model.clone().ok_or_else(|| {
            "No utility model configured. Set one on the Tools page or via the API.".to_string()
        })?;
        (model, utility_allows_cloud(&config.utility))
    };
    ensure_cloud_consent(&model, allow_cloud)?;

    let request = ChatRequest {
        model,
        messages: vec![
            crate::providers::Message {
                role: "system".to_string(),
                content: Some(Value::String(system.to_string())),
                extra: serde_json::Map::new(),
            },
            crate::providers::Message {
                role: "user".to_string(),
                content: Some(Value::String(user.to_string())),
                extra: serde_json::Map::new(),
            },
        ],
        stream: Some(false),
        temperature: Some(0.2),
        // Reasoning models spend this budget on thinking before the answer,
        // so keep headroom for both.
        max_tokens: Some(2000),
        top_p: None,
        extra: serde_json::Map::new(),
    };

    let response =
        crate::api::v1::chat_completions(axum::extract::State(state.clone()), axum::Json(request))
            .await;
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|_| "Could not read utility model response".to_string())?;
    let payload: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "Utility model returned invalid JSON".to_string())?;
    if !parts.status.is_success() {
        return Err("Utility model request failed".to_string());
    }
    let message = &payload["choices"][0]["message"];
    // Reasoning models can spend the whole budget thinking; if the final
    // content is empty, use whatever reasoning they produced.
    let content = message["content"]
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .or_else(|| message["reasoning_content"].as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if content.is_empty() {
        return Err("Utility model returned an empty response".to_string());
    }
    Ok((content, payload["model"].as_str().unwrap_or("").to_string()))
}

fn read_bounded(mut reader: impl Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..count.min(remaining)]);
        truncated |= count > remaining;
    }
    Ok((output, truncated))
}

/// Run one of the fixed read-only Git operations and capture bounded stdout.
pub(super) fn git(workspace: &Workspace, args: &[&str]) -> Result<String, String> {
    if !matches!(
        args.first().copied(),
        Some("rev-parse") | Some("status") | Some("diff") | Some("log")
    ) {
        return Err("Git operation is not permitted.".to_string());
    }
    let path = workspace.verified_path()?;
    let null_device = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device)
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_OPTIONAL_LOCKS", "0");
    for variable in [
        "PATH",
        "Path",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(variable) {
            command.env(variable, value);
        }
    }
    let mut child = command
        .arg("--no-pager")
        .arg("--literal-pathspecs")
        .arg("--no-optional-locks")
        .args(["-c", "color.ui=false"])
        .args(["-c", "credential.helper="])
        .args(["-c", "core.askPass="])
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", &format!("core.hooksPath={null_device}")])
        .args(["-c", "diff.external="])
        .args(["-c", "interactive.diffFilter="])
        .args(["-c", "log.showSignature=false"])
        .args(["-c", "protocol.allow=never"])
        .arg("-C")
        .arg(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "Git is unavailable.".to_string())?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Git output is unavailable.".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Git output is unavailable.".to_string())?;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout, MAX_GIT_OUTPUT_BYTES));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr, MAX_GIT_OUTPUT_BYTES));

    let start = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if start.elapsed() < GIT_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                break (child.wait().ok(), true);
            }
            Err(_) => break (None, false),
        }
    };
    let (stdout, was_truncated) = stdout_reader
        .join()
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| "Could not read Git output.".to_string())?;
    let _ = stderr_reader.join();
    if timed_out {
        return Err("Git operation timed out.".to_string());
    }
    if !status.map(|status| status.success()).unwrap_or(false) {
        return Err("Git operation failed.".to_string());
    }

    let mut output = String::from_utf8_lossy(&stdout).trim().to_string();
    if was_truncated {
        output.push_str(TRUNCATION_MARKER);
    }
    Ok(truncate_chars(&output, MAX_GIT_OUTPUT_CHARS))
}

/// Observable repository facts for /btw: working-tree state, diffstat, and
/// recent history. Read-only; never mutates the repository.
pub(crate) fn repo_facts(workspace: &Workspace) -> Vec<String> {
    let mut facts = vec!["Workspace: configured repository".to_string()];
    match git(workspace, &["rev-parse", "--is-inside-work-tree"]) {
        Ok(_) => {}
        Err(_) => {
            facts.push("Not a git repository.".to_string());
            return facts;
        }
    }
    if let Ok(status) = git(workspace, &["status", "--porcelain=v1"]) {
        if status.is_empty() {
            facts.push("git status: clean (no uncommitted changes)".to_string());
        } else {
            let changed: Vec<&str> = status.lines().collect();
            facts.push(sanitize_for_model(
                &format!(
                    "git status: {} changed path(s): {}",
                    changed.len(),
                    changed.join(", ")
                ),
                Some(workspace),
                MAX_REPO_FACT_CHARS,
            ));
        }
    }
    if let Ok(stat) = git(
        workspace,
        &["diff", "--no-ext-diff", "--no-textconv", "--stat", "HEAD"],
    ) {
        if !stat.is_empty() {
            facts.push(sanitize_for_model(
                &format!("Uncommitted diffstat: {stat}"),
                Some(workspace),
                MAX_REPO_FACT_CHARS,
            ));
        }
    }
    if let Ok(log) = git(
        workspace,
        &["log", "--no-show-signature", "-5", "--oneline"],
    ) {
        let commits: Vec<&str> = log.lines().collect();
        if !commits.is_empty() {
            facts.push(sanitize_for_model(
                &format!("Recent commits: {}", commits.join(" | ")),
                Some(workspace),
                MAX_REPO_FACT_CHARS,
            ));
        }
    } else {
        facts.push("No commits yet.".to_string());
    }
    facts
}

/// Observable gateway facts for /btw: recent requests, window aggregates, and
/// today's spend, all from the local telemetry database.
pub fn telemetry_facts(state: &AppState, recent_limit: i64) -> Vec<String> {
    let mut facts = Vec::new();
    let Ok(db) = state.db.lock() else {
        facts.push("Telemetry database unavailable.".to_string());
        return facts;
    };
    if let Ok(logs) = crate::db::get_logs(&db, recent_limit, 0) {
        if logs.is_empty() {
            facts.push("No requests recorded yet.".to_string());
        } else {
            facts.push(format!(
                "{} most recent gateway request(s), newest first:",
                logs.len()
            ));
            for log in &logs {
                let tokens = log.prompt_tokens + log.completion_tokens;
                facts.push(format!(
                    "  {} {}/{} status {} {} tok ${:.4} {} ms",
                    log.timestamp,
                    log.provider,
                    log.model,
                    log.status,
                    tokens,
                    log.est_cost_usd,
                    log.latency_ms
                ));
            }
        }
    }
    if let Ok(stats) = crate::db::get_stats(&db, "24h") {
        facts.push(format!(
            "Last 24h: {} requests, {} tokens, ${:.4} estimated spend, avg latency {:.0} ms, {} failed",
            stats.total_requests,
            stats.total_tokens,
            stats.total_cost_usd,
            stats.avg_latency_ms,
            stats.error_count
        ));
    }
    if let Ok(today) = crate::db::get_today_cost(&db) {
        facts.push(format!("Today's estimated spend: ${:.4}", today));
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("skyport-{label}-{}", uuid::Uuid::new_v4()))
    }

    fn setup_git(workspace: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn workspace_is_limited_to_the_canonical_configured_root() {
        let base = test_dir("workspace-boundary");
        let root = base.join("root");
        let child = root.join("child");
        let outside = base.join("outside");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        assert!(Workspace::resolve(None, None).is_err());
        let root_text = root.to_str().unwrap();
        let resolved = Workspace::resolve(Some(root_text), Some("child")).unwrap();
        assert_eq!(resolved.path, std::fs::canonicalize(&child).unwrap());
        let error = Workspace::resolve(Some(root_text), outside.to_str()).unwrap_err();
        assert!(!error.contains(root_text));
        assert!(!error.contains(outside.to_str().unwrap()));

        let escape = root.join("escape");
        #[cfg(unix)]
        let link_result = std::os::unix::fs::symlink(&outside, &escape);
        #[cfg(windows)]
        let link_result = std::os::windows::fs::symlink_dir(&outside, &escape);
        #[cfg(not(any(unix, windows)))]
        let link_result: std::io::Result<()> = Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlinks unsupported",
        ));
        if link_result.is_ok() {
            assert!(Workspace::resolve(Some(root_text), Some("escape")).is_err());
        }
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn unicode_truncation_uses_character_boundaries_and_honors_the_cap() {
        let value = "ab😀界cd";
        let truncated = truncate_chars(value, 5);
        assert_eq!(truncated.chars().count(), 5);
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
        assert_eq!(truncate_chars(value, value.chars().count()), value);
    }

    #[test]
    fn likely_secrets_are_redacted_before_model_use() {
        let input = "safe line\nAuthorization: Bearer top-secret\nAPI_KEY=sk-proj-abcdef123456\nraw ghp_abcdefghijklmnopqrstuvwxyz\n-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\nafter";
        let redacted = redact_secrets(input);
        for secret in [
            "top-secret",
            "sk-proj-abcdef123456",
            "ghp_abcdefghijklmnopqrstuvwxyz",
            "private-material",
        ] {
            assert!(!redacted.contains(secret));
        }
        assert!(redacted.contains("safe line"));
        assert!(redacted.contains("after"));
        assert!(redacted.contains("[REDACTED private key]"));
    }

    #[test]
    fn model_context_does_not_expose_absolute_paths() {
        let sanitized = sanitize_for_model(
            "changed C:\\Users\\person\\repo\\secret.rs and /home/person/repo/key.txt",
            None,
            1_000,
        );
        assert!(!sanitized.contains("C:\\Users"));
        assert!(!sanitized.contains("/home/person"));
        assert_eq!(sanitized.matches("[absolute path]").count(), 2);
    }

    #[test]
    fn cloud_models_require_explicit_consent() {
        assert!(ensure_cloud_consent("ollama/llama3.2", false).is_ok());
        assert!(ensure_cloud_consent("lmstudio/local-model", false).is_ok());
        assert!(ensure_cloud_consent("openai/gpt-5", false).is_err());
        assert!(ensure_cloud_consent("ollama-cloud/model", false).is_err());
        assert!(ensure_cloud_consent("bare-model", false).is_err());
        assert!(ensure_cloud_consent("openai/gpt-5", true).is_ok());
    }

    #[test]
    fn repo_facts_are_read_only_on_a_real_repository() {
        let dir = test_dir("tools-repository");
        std::fs::create_dir_all(&dir).unwrap();
        setup_git(&dir, &["init", "--quiet"]);
        std::fs::write(dir.join("README.md"), "hello\n").unwrap();
        setup_git(&dir, &["add", "."]);
        let workspace = Workspace::resolve(dir.to_str(), None).unwrap();
        let facts = repo_facts(&workspace);
        assert!(facts.iter().any(|f| f.contains("README.md")));
        assert!(facts.iter().any(|f| f.contains("No commits yet")));
        assert!(facts
            .iter()
            .all(|fact| !fact.contains(dir.to_str().unwrap())));
        // read-only: staging state must be untouched
        let status = git(&workspace, &["status", "--porcelain=v1"]).unwrap();
        assert_eq!(status, "A  README.md");
        std::fs::remove_dir_all(&dir).ok();
    }
}
