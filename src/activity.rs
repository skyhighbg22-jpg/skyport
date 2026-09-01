//! Current-session activity parsing and tracking engine.
//!
//! Extracts human-readable events from AI coding sessions:
//! - File reads ("Read src/router.ts")
//! - LLM completions ("→ Kimi", "→ Claude", "→ GPT-4o")
//! - File edits ("Modified router.ts", "Created src/activity.rs")
//! - Test executions ("Ran tests")
//! - Test results ("42/42 passed", "3 failed")
//! - Shell & git commands ("Ran cargo check", "Git commit")

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::AppState;
use crate::db::{self, ActivityEntry};

const MAX_ACTIONS_PER_REQUEST: usize = 32;
const MAX_TOOL_NAME_CHARS: usize = 128;
const MAX_PATH_CHARS: usize = 256;
const MAX_QUERY_CHARS: usize = 256;
const MAX_TITLE_CHARS: usize = 160;
const MAX_DETAIL_CHARS: usize = 2_048;
const MAX_METADATA_VALUE_CHARS: usize = 1_024;
const MAX_METADATA_JSON_CHARS: usize = 4_096;
const MAX_TOOL_OUTPUT_PARSE_CHARS: usize = 8_192;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ParsedAction {
    pub event_type: String, // "read", "modify", "create", "test_run", "test_result", "llm_call", "command", "search", "tool"
    pub title: String,
    pub detail: Option<String>,
    pub metadata: Option<Value>,
}

/// Format a provider / model into a concise label for the LLM invocation line
/// e.g. "→ Kimi", "→ Claude 3.7", "→ GPT-4o", "→ Gemini"
pub fn format_llm_title(provider: &str, model: &str) -> String {
    let lower_provider = provider.to_lowercase();
    let lower_model = model.to_lowercase();

    let display_name = if lower_provider == "kimi"
        || lower_model.contains("moonshot")
        || lower_model.contains("kimi")
    {
        "Kimi"
    } else if lower_provider == "openai" {
        if lower_model.contains("gpt-4o-mini") {
            "GPT-4o mini"
        } else if lower_model.contains("gpt-4o") {
            "GPT-4o"
        } else if lower_model.contains("o1") {
            "o1"
        } else if lower_model.contains("o3") {
            "o3"
        } else {
            "OpenAI"
        }
    } else if lower_provider == "anthropic" || lower_model.contains("claude") {
        if lower_model.contains("3-7") || lower_model.contains("3.7") {
            "Claude 3.7"
        } else if lower_model.contains("3-5-sonnet") || lower_model.contains("3.5-sonnet") {
            "Claude 3.5 Sonnet"
        } else if lower_model.contains("3-5-haiku") || lower_model.contains("3.5-haiku") {
            "Claude 3.5 Haiku"
        } else {
            "Claude"
        }
    } else if lower_provider == "gemini" || lower_model.contains("gemini") {
        if lower_model.contains("2.0-flash") || lower_model.contains("2-flash") {
            "Gemini 2.0 Flash"
        } else if lower_model.contains("flash") {
            "Gemini Flash"
        } else if lower_model.contains("pro") {
            "Gemini Pro"
        } else {
            "Gemini"
        }
    } else if lower_provider == "deepseek" || lower_model.contains("deepseek") {
        if lower_model.contains("r1") {
            "DeepSeek-R1"
        } else {
            "DeepSeek"
        }
    } else if lower_provider == "groq" {
        "Groq"
    } else if lower_provider == "nvidia" {
        "NVIDIA"
    } else if lower_provider == "openrouter" {
        "OpenRouter"
    } else if lower_provider == "ollama" {
        "Ollama"
    } else if lower_provider == "lmstudio" {
        "LM Studio"
    } else {
        provider
    };

    format!("→ {display_name}")
}

/// Simplify a file path for display (strip workspace prefix or absolute path if possible)
pub fn simplify_path(path: &str) -> String {
    let clean = path.trim().trim_matches(['"', '\'']);
    let normalized = clean.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    let simplified = if parts.len() <= 3 {
        normalized
    } else {
        // Return the last two segments (e.g. src/router.ts).
        parts[parts.len().saturating_sub(2)..].join("/")
    };
    sanitize_persisted_text(&simplified, MAX_PATH_CHARS)
}

/// Last-mile protection for everything copied from an inference request into
/// telemetry. Bound the work before redaction as well as the final value so a
/// large request cannot create another large temporary allocation here.
fn sanitize_persisted_text(input: &str, max_chars: usize) -> String {
    let scan_limit = max_chars.saturating_mul(4).max(max_chars);
    let bounded: String = input
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .take(scan_limit)
        .collect();
    crate::tools::truncate_chars(&crate::tools::redact_secrets(&bounded), max_chars)
}

fn sanitize_metadata_value(value: &mut Value, depth: usize) {
    if depth >= 8 {
        *value = Value::String("[truncated]".to_string());
        return;
    }
    match value {
        Value::String(text) => {
            *text = sanitize_persisted_text(text, MAX_METADATA_VALUE_CHARS);
        }
        Value::Array(values) => {
            values.truncate(MAX_ACTIONS_PER_REQUEST);
            for value in values {
                sanitize_metadata_value(value, depth + 1);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                sanitize_metadata_value(value, depth + 1);
            }
        }
        _ => {}
    }
}

fn sanitized_metadata_json(metadata: Option<Value>) -> Option<String> {
    let mut metadata = metadata?;
    sanitize_metadata_value(&mut metadata, 0);
    let serialized = serde_json::to_string(&metadata).ok()?;
    if serialized.chars().count() <= MAX_METADATA_JSON_CHARS {
        Some(serialized)
    } else {
        Some(serde_json::json!({"truncated": true}).to_string())
    }
}

/// Parse tool arguments JSON to find common file path fields
fn extract_path_arg(args: &Value) -> Option<String> {
    if let Value::String(s) = args {
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            return extract_path_arg(&parsed);
        }
    }
    for field in [
        "path",
        "file_path",
        "filePath",
        "file",
        "TargetFile",
        "target_file",
        "AbsolutePath",
        "absolute_path",
        "filename",
        "uri",
    ] {
        if let Some(val) = args.get(field).and_then(Value::as_str) {
            if !val.trim().is_empty() {
                return Some(simplify_path(val));
            }
        }
    }
    None
}

/// Parse tool arguments JSON to find common command fields
fn extract_command_arg(args: &Value) -> Option<String> {
    if let Value::String(s) = args {
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            return extract_command_arg(&parsed);
        }
    }
    for field in ["command", "cmd", "CommandLine", "command_line", "script"] {
        if let Some(val) = args.get(field).and_then(Value::as_str) {
            if !val.trim().is_empty() {
                return Some(sanitize_persisted_text(val.trim(), MAX_DETAIL_CHARS));
            }
        }
    }
    None
}

/// Parse tool arguments JSON to find search query fields
fn extract_query_arg(args: &Value) -> Option<String> {
    if let Value::String(s) = args {
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            return extract_query_arg(&parsed);
        }
    }
    for field in [
        "query",
        "pattern",
        "Query",
        "searchTerm",
        "search_term",
        "q",
    ] {
        if let Some(val) = args.get(field).and_then(Value::as_str) {
            if !val.trim().is_empty() {
                return Some(sanitize_persisted_text(val.trim(), MAX_QUERY_CHARS));
            }
        }
    }
    None
}

/// Parse a tool call by its function name and arguments
pub fn parse_tool_call(name: &str, args_val: &Value) -> Option<ParsedAction> {
    let name = sanitize_persisted_text(name, MAX_TOOL_NAME_CHARS);
    let lower_name = name.to_ascii_lowercase();

    // 1. File read operations
    if lower_name.contains("read")
        || lower_name.contains("view_file")
        || lower_name == "cat"
        || lower_name == "fetch_file"
    {
        let path = extract_path_arg(args_val).unwrap_or_else(|| "file".to_string());
        return Some(ParsedAction {
            event_type: "read".to_string(),
            title: format!("Read {path}"),
            detail: None,
            metadata: Some(serde_json::json!({ "tool": name, "path": path })),
        });
    }

    // 2. File write / edit / modification operations
    if lower_name.contains("edit")
        || lower_name.contains("replace")
        || lower_name.contains("write")
        || lower_name.contains("patch")
        || lower_name.contains("save")
        || lower_name.contains("create_file")
    {
        let path = extract_path_arg(args_val).unwrap_or_else(|| "file".to_string());
        let is_create = lower_name.contains("create") || lower_name.contains("write_to_file");
        return Some(ParsedAction {
            event_type: if is_create {
                "create".to_string()
            } else {
                "modify".to_string()
            },
            title: if is_create {
                format!("Created {path}")
            } else {
                format!("Modified {path}")
            },
            detail: None,
            metadata: Some(serde_json::json!({ "tool": name, "path": path })),
        });
    }

    // 3. Command / terminal execution
    if lower_name.contains("command")
        || lower_name == "bash"
        || lower_name == "exec"
        || lower_name == "terminal"
        || lower_name == "sh"
    {
        if let Some(cmd) = extract_command_arg(args_val) {
            let lower_cmd = cmd.to_lowercase();
            if lower_cmd.contains("test")
                || lower_cmd.contains("cargo t")
                || lower_cmd.contains("pytest")
                || lower_cmd.contains("vitest")
                || lower_cmd.contains("jest")
                || lower_cmd.contains("go test")
            {
                return Some(ParsedAction {
                    event_type: "test_run".to_string(),
                    title: "Ran tests".to_string(),
                    detail: Some(cmd.clone()),
                    metadata: Some(serde_json::json!({ "tool": name, "command": cmd })),
                });
            }
            if lower_cmd.starts_with("git commit") {
                return Some(ParsedAction {
                    event_type: "command".to_string(),
                    title: "Git commit".to_string(),
                    detail: Some(cmd.clone()),
                    metadata: Some(serde_json::json!({ "tool": name, "command": cmd })),
                });
            }
            if lower_cmd.starts_with("git diff") || lower_cmd.starts_with("git status") {
                return Some(ParsedAction {
                    event_type: "command".to_string(),
                    title: "Checked git status".to_string(),
                    detail: Some(cmd.clone()),
                    metadata: Some(serde_json::json!({ "tool": name, "command": cmd })),
                });
            }
            // General command
            let short_cmd = if cmd.chars().count() > 36 {
                format!("{}...", cmd.chars().take(33).collect::<String>())
            } else {
                cmd.clone()
            };
            return Some(ParsedAction {
                event_type: "command".to_string(),
                title: format!("Ran {short_cmd}"),
                detail: Some(cmd.clone()),
                metadata: Some(serde_json::json!({ "tool": name, "command": cmd })),
            });
        }
        return Some(ParsedAction {
            event_type: "command".to_string(),
            title: "Ran command".to_string(),
            detail: None,
            metadata: Some(serde_json::json!({ "tool": name })),
        });
    }

    // 4. Search / Grep operations
    if lower_name.contains("grep") || lower_name.contains("search") || lower_name == "find" {
        let query = extract_query_arg(args_val).unwrap_or_else(|| "codebase".to_string());
        return Some(ParsedAction {
            event_type: "search".to_string(),
            title: format!("Searched for {query}"),
            detail: None,
            metadata: Some(serde_json::json!({ "tool": name, "query": query })),
        });
    }

    // 5. Directory list operations
    if lower_name.contains("list_dir")
        || lower_name == "ls"
        || lower_name.contains("list_directory")
    {
        let path = extract_path_arg(args_val).unwrap_or_else(|| "workspace".to_string());
        return Some(ParsedAction {
            event_type: "read".to_string(),
            title: format!("Listed {path}"),
            detail: None,
            metadata: Some(serde_json::json!({ "tool": name, "path": path })),
        });
    }

    // Default tool
    Some(ParsedAction {
        event_type: "tool".to_string(),
        title: format!("Tool: {name}"),
        detail: None,
        metadata: Some(serde_json::json!({ "tool": name })),
    })
}

/// Parse tool output string (e.g. test results like "42/42 passed", "3 failed")
pub fn parse_tool_output(text: &str) -> Option<ParsedAction> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    let parse_text = crate::tools::truncate_chars(text, MAX_TOOL_OUTPUT_PARSE_CHARS);
    let safe_text = sanitize_persisted_text(text, MAX_DETAIL_CHARS);

    let lower = parse_text.to_ascii_lowercase();

    // Check for explicit failed counts: e.g. "3 failed", "3 failures", "failed: 3", "3 failed;"
    let mut failed_count = 0usize;
    let mut found_explicit_failure = false;

    let words: Vec<&str> = parse_text.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        let clean = word
            .trim_matches(['.', ',', ';', '(', ')', ':', '[', ']'])
            .to_ascii_lowercase();
        if clean == "failed" || clean == "failures" || clean == "failure" {
            // Check preceding word for number: e.g. "3 failed"
            if i > 0 {
                let prev_clean =
                    words[i - 1].trim_matches(['.', ',', ';', '(', ')', ':', '[', ']']);
                if let Ok(num) = prev_clean.parse::<usize>() {
                    if num > 0 {
                        failed_count = num;
                        found_explicit_failure = true;
                    }
                }
            }
            // Check succeeding word for number: e.g. "failed: 3"
            if !found_explicit_failure && i + 1 < words.len() {
                let next_clean =
                    words[i + 1].trim_matches(['.', ',', ';', '(', ')', ':', '[', ']']);
                if let Ok(num) = next_clean.parse::<usize>() {
                    if num > 0 {
                        failed_count = num;
                        found_explicit_failure = true;
                    }
                }
            }
        }
    }

    // Scan for passed counts: e.g. "42/42 passed", "42 passed"
    let mut passed_str = String::new();
    for (i, word) in words.iter().enumerate() {
        let clean = word
            .trim_matches(['.', ',', ';', '(', ')', ':', '[', ']'])
            .to_ascii_lowercase();
        if clean == "passed" || clean == "passing" {
            if i > 0 {
                let prev_clean =
                    words[i - 1].trim_matches(['.', ',', ';', '(', ')', ':', '[', ']']);
                if prev_clean.chars().all(|c| c.is_ascii_digit() || c == '/')
                    && !prev_clean.is_empty()
                {
                    if prev_clean.contains('/') {
                        passed_str = prev_clean.to_string();
                    } else if let Ok(num) = prev_clean.parse::<usize>() {
                        passed_str = format!("{num}/{num}");
                    }
                }
            }
        }
    }

    if found_explicit_failure {
        return Some(ParsedAction {
            event_type: "test_result".to_string(),
            title: format!("{failed_count} failed"),
            detail: Some(safe_text.lines().take(3).collect::<Vec<_>>().join(" ")),
            metadata: Some(serde_json::json!({ "output": safe_text })),
        });
    }

    if !passed_str.is_empty() {
        return Some(ParsedAction {
            event_type: "test_result".to_string(),
            title: format!("{passed_str} passed"),
            detail: Some(safe_text.lines().take(3).collect::<Vec<_>>().join(" ")),
            metadata: Some(serde_json::json!({ "output": safe_text })),
        });
    }

    if lower.contains("test result: ok")
        || lower.contains("tests passed")
        || lower.contains("all tests passed")
    {
        return Some(ParsedAction {
            event_type: "test_result".to_string(),
            title: "Tests passed".to_string(),
            detail: Some(safe_text.lines().take(2).collect::<Vec<_>>().join(" ")),
            metadata: Some(serde_json::json!({ "output": safe_text })),
        });
    }

    if lower.contains("test result: failed") || lower.contains("tests failed") {
        return Some(ParsedAction {
            event_type: "test_result".to_string(),
            title: "Tests failed".to_string(),
            detail: Some(safe_text.lines().take(2).collect::<Vec<_>>().join(" ")),
            metadata: Some(serde_json::json!({ "output": safe_text })),
        });
    }

    None
}

/// Extract actions from request messages
pub fn extract_actions_from_request_body(body: &Value) -> Vec<ParsedAction> {
    let mut actions = Vec::new();
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return actions;
    };

    let has_tool_call = |message: &Value| {
        message
            .get("tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|calls| !calls.is_empty())
            || message
                .get("content")
                .and_then(Value::as_array)
                .is_some_and(|parts| {
                    parts
                        .iter()
                        .any(|part| part.get("type").and_then(Value::as_str) == Some("tool_use"))
                })
    };

    // A chat request carries its complete history. Extract only the newest
    // active tool batch and its following tool results; otherwise every model
    // turn would persist the same historical actions again. If a later user or
    // non-tool assistant message exists, that batch is already historical.
    let Some(start_idx) = messages.iter().rposition(has_tool_call).or_else(|| {
        messages
            .last()
            .is_some_and(|message| {
                matches!(
                    message.get("role").and_then(Value::as_str),
                    Some("tool" | "function")
                )
            })
            .then(|| messages.len().saturating_sub(1))
    }) else {
        return actions;
    };
    if messages[start_idx + 1..].iter().any(|message| {
        matches!(
            message.get("role").and_then(Value::as_str),
            Some("user" | "assistant")
        )
    }) {
        return actions;
    }

    for message in &messages[start_idx..] {
        // Tool calls in assistant message
        if let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array) {
            for call in tool_calls {
                let name = call
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                    .or_else(|| call.get("name").and_then(Value::as_str))
                    .unwrap_or("");
                let args = call
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .unwrap_or(&Value::Null);
                if !name.is_empty() {
                    if let Some(action) = parse_tool_call(name, args) {
                        actions.push(action);
                        if actions.len() >= MAX_ACTIONS_PER_REQUEST {
                            return actions;
                        }
                    }
                }
            }
        }

        // Anthropic content array with type = "tool_use"
        if let Some(content_array) = message.get("content").and_then(Value::as_array) {
            for part in content_array {
                if part.get("type").and_then(Value::as_str) == Some("tool_use") {
                    let name = part.get("name").and_then(Value::as_str).unwrap_or("");
                    let input = part.get("input").unwrap_or(&Value::Null);
                    if !name.is_empty() {
                        if let Some(action) = parse_tool_call(name, input) {
                            actions.push(action);
                            if actions.len() >= MAX_ACTIONS_PER_REQUEST {
                                return actions;
                            }
                        }
                    }
                }
            }
        }

        // Tool output messages
        let role = message.get("role").and_then(Value::as_str).unwrap_or("");
        if role == "tool" || role == "function" {
            let content = message.get("content").and_then(Value::as_str).unwrap_or("");
            if let Some(action) = parse_tool_output(content) {
                actions.push(action);
                if actions.len() >= MAX_ACTIONS_PER_REQUEST {
                    return actions;
                }
            }
        }
    }

    actions
}

/// Record all activity events (extracted tools, test results, and the LLM call) into the database
pub fn record_request_activity(
    state: &AppState,
    session_id: &str,
    request_body: &Value,
    provider: &str,
    model: &str,
    latency_ms: i64,
    prompt_tokens: i64,
    completion_tokens: i64,
    status: u16,
    cost: f64,
) {
    let now = Utc::now().to_rfc3339();
    let total_tokens = prompt_tokens + completion_tokens;

    // 1. Extract tool calls / results from request history
    let extracted = extract_actions_from_request_body(request_body);

    // 2. Create the LLM completion action
    let llm_title = format_llm_title(provider, model);
    let llm_detail = if total_tokens > 0 {
        format!("{model} · {total_tokens} tok · {latency_ms}ms · ${cost:.4}")
    } else {
        format!("{model} · {latency_ms}ms")
    };
    let llm_action = ParsedAction {
        event_type: "llm_call".to_string(),
        title: llm_title,
        detail: Some(llm_detail),
        metadata: Some(serde_json::json!({
            "provider": provider,
            "model": model,
            "latency_ms": latency_ms,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "status": status,
            "cost_usd": cost,
        })),
    };

    let Ok(db) = state.db.lock() else {
        return;
    };

    let Ok(transaction) = db.unchecked_transaction() else {
        return;
    };

    // Persist the bounded action batch atomically. Sanitization happens again
    // here as a last line of defense for every current and future parser.
    for action in extracted.into_iter().take(MAX_ACTIONS_PER_REQUEST) {
        let entry = ActivityEntry {
            id: None,
            timestamp: now.clone(),
            session_id: sanitize_persisted_text(session_id, MAX_TOOL_NAME_CHARS),
            event_type: sanitize_persisted_text(&action.event_type, MAX_TOOL_NAME_CHARS),
            title: sanitize_persisted_text(&action.title, MAX_TITLE_CHARS),
            detail: action
                .detail
                .map(|detail| sanitize_persisted_text(&detail, MAX_DETAIL_CHARS)),
            metadata_json: sanitized_metadata_json(action.metadata),
        };
        if db::log_activity(&transaction, &entry).is_err() {
            return;
        }
    }

    // Log the LLM call action
    let llm_entry = ActivityEntry {
        id: None,
        timestamp: now,
        session_id: sanitize_persisted_text(session_id, MAX_TOOL_NAME_CHARS),
        event_type: sanitize_persisted_text(&llm_action.event_type, MAX_TOOL_NAME_CHARS),
        title: sanitize_persisted_text(&llm_action.title, MAX_TITLE_CHARS),
        detail: llm_action
            .detail
            .map(|detail| sanitize_persisted_text(&detail, MAX_DETAIL_CHARS)),
        metadata_json: sanitized_metadata_json(llm_action.metadata),
    };
    if db::log_activity(&transaction, &llm_entry).is_ok() {
        let _ = transaction.commit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn formats_llm_titles_cleanly() {
        assert_eq!(format_llm_title("kimi", "moonshot-v1-8k"), "→ Kimi");
        assert_eq!(format_llm_title("openai", "gpt-4o"), "→ GPT-4o");
        assert_eq!(format_llm_title("openai", "gpt-4o-mini"), "→ GPT-4o mini");
        assert_eq!(
            format_llm_title("anthropic", "claude-3-7-sonnet"),
            "→ Claude 3.7"
        );
        assert_eq!(
            format_llm_title("gemini", "gemini-2.0-flash"),
            "→ Gemini 2.0 Flash"
        );
        assert_eq!(format_llm_title("deepseek", "deepseek-r1"), "→ DeepSeek-R1");
        assert_eq!(format_llm_title("groq", "llama-3.3-70b"), "→ Groq");
    }

    #[test]
    fn parses_read_file_tool_call() {
        let args = json!({ "path": "src/router.ts" });
        let action = parse_tool_call("read_file", &args).unwrap();
        assert_eq!(action.event_type, "read");
        assert_eq!(action.title, "Read src/router.ts");
    }

    #[test]
    fn parses_edit_file_tool_call() {
        let args = json!({ "TargetFile": "C:\\repo\\src\\router.ts" });
        let action = parse_tool_call("replace_file_content", &args).unwrap();
        assert_eq!(action.event_type, "modify");
        assert_eq!(action.title, "Modified src/router.ts");
    }

    #[test]
    fn parses_test_command_tool_call() {
        let args = json!({ "CommandLine": "cargo test" });
        let action = parse_tool_call("run_command", &args).unwrap();
        assert_eq!(action.event_type, "test_run");
        assert_eq!(action.title, "Ran tests");
        assert_eq!(action.detail.as_deref(), Some("cargo test"));
    }

    #[test]
    fn parses_test_result_output() {
        let output = "test result: ok. 42 passed; 0 failed; 0 ignored; finished in 0.75s";
        let action = parse_tool_output(output).unwrap();
        assert_eq!(action.event_type, "test_result");
        assert_eq!(action.title, "42/42 passed");

        let output2 = "42/42 passed";
        let action2 = parse_tool_output(output2).unwrap();
        assert_eq!(action2.title, "42/42 passed");

        let output3 = "test result: FAILED. 3 failed; 39 passed";
        let action3 = parse_tool_output(output3).unwrap();
        assert_eq!(action3.title, "3 failed");
    }

    #[test]
    fn extracts_only_the_newest_active_tool_batch() {
        let body = json!({
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": "read_file",
                                "arguments": "{\"path\":\"src/router.ts\"}"
                            }
                        }
                    ]
                },
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": "replace_file_content",
                                "arguments": "{\"path\":\"src/router.ts\"}"
                            }
                        },
                        {
                            "type": "function",
                            "function": {
                                "name": "run_command",
                                "arguments": "{\"command\":\"cargo test\"}"
                            }
                        }
                    ]
                },
                {
                    "role": "tool",
                    "content": "test result: ok. 42 passed; 0 failed"
                }
            ]
        });

        let actions = extract_actions_from_request_body(&body);
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].title, "Modified src/router.ts");
        assert_eq!(actions[1].title, "Ran tests");
        assert_eq!(actions[2].title, "42/42 passed");
    }

    #[test]
    fn ignores_completed_historical_tool_batches() {
        let body = json!({
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [{
                        "function": {"name": "read_file", "arguments": "{\"path\":\"secret.txt\"}"}
                    }]
                },
                {"role": "tool", "content": "completed"},
                {"role": "user", "content": "What changed?"}
            ]
        });

        assert!(extract_actions_from_request_body(&body).is_empty());
    }

    #[test]
    fn persisted_activity_is_unicode_safe_bounded_and_redacted() {
        let command = format!(
            "deploy 😀界 with sk-proj-abcdef123456 {}",
            "x".repeat(MAX_DETAIL_CHARS * 2)
        );
        let action = parse_tool_call("run_command", &json!({"command": command})).unwrap();
        let detail = action.detail.unwrap();
        assert!(std::str::from_utf8(detail.as_bytes()).is_ok());
        assert!(detail.chars().count() <= MAX_DETAIL_CHARS);
        assert!(!detail.contains("sk-proj-abcdef123456"));
        assert!(detail.contains("[REDACTED]"));
    }
}
