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
    if parts.len() <= 3 {
        return normalized;
    }
    // Return last 2 or 3 segments (e.g. src/router.ts or router.ts)
    parts[parts.len().saturating_sub(2)..].join("/")
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
                return Some(val.trim().to_string());
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
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

/// Parse a tool call by its function name and arguments
pub fn parse_tool_call(name: &str, args_val: &Value) -> Option<ParsedAction> {
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
            let short_cmd = if cmd.len() > 36 {
                format!("{}...", &cmd[..33])
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

    let lower = text.to_ascii_lowercase();

    // Check for explicit failed counts: e.g. "3 failed", "3 failures", "failed: 3", "3 failed;"
    let mut failed_count = 0usize;
    let mut found_explicit_failure = false;

    let words: Vec<&str> = text.split_whitespace().collect();
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
            detail: Some(text.lines().take(3).collect::<Vec<_>>().join(" ")),
            metadata: Some(serde_json::json!({ "output": text })),
        });
    }

    if !passed_str.is_empty() {
        return Some(ParsedAction {
            event_type: "test_result".to_string(),
            title: format!("{passed_str} passed"),
            detail: Some(text.lines().take(3).collect::<Vec<_>>().join(" ")),
            metadata: Some(serde_json::json!({ "output": text })),
        });
    }

    if lower.contains("test result: ok")
        || lower.contains("tests passed")
        || lower.contains("all tests passed")
    {
        return Some(ParsedAction {
            event_type: "test_result".to_string(),
            title: "Tests passed".to_string(),
            detail: Some(text.lines().take(2).collect::<Vec<_>>().join(" ")),
            metadata: Some(serde_json::json!({ "output": text })),
        });
    }

    if lower.contains("test result: failed") || lower.contains("tests failed") {
        return Some(ParsedAction {
            event_type: "test_result".to_string(),
            title: "Tests failed".to_string(),
            detail: Some(text.lines().take(2).collect::<Vec<_>>().join(" ")),
            metadata: Some(serde_json::json!({ "output": text })),
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

    // We only inspect the most recent few messages to avoid repeating past turns
    let start_idx = messages.len().saturating_sub(4);
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

    // Log any extracted actions (avoid duplicates if same title logged recently)
    for action in extracted {
        let entry = ActivityEntry {
            id: None,
            timestamp: now.clone(),
            session_id: session_id.to_string(),
            event_type: action.event_type,
            title: action.title,
            detail: action.detail,
            metadata_json: action.metadata.map(|m| m.to_string()),
        };
        let _ = db::log_activity(&db, &entry);
    }

    // Log the LLM call action
    let llm_entry = ActivityEntry {
        id: None,
        timestamp: now,
        session_id: session_id.to_string(),
        event_type: llm_action.event_type,
        title: llm_action.title,
        detail: llm_action.detail,
        metadata_json: llm_action.metadata.map(|m| m.to_string()),
    };
    let _ = db::log_activity(&db, &llm_entry);
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
    fn extracts_actions_from_full_chat_body() {
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
        assert_eq!(actions.len(), 4);
        assert_eq!(actions[0].title, "Read src/router.ts");
        assert_eq!(actions[1].title, "Modified src/router.ts");
        assert_eq!(actions[2].title, "Ran tests");
        assert_eq!(actions[3].title, "42/42 passed");
    }
}
