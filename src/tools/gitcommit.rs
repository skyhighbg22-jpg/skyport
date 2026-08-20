//! /gitcommit — generate a commit message from a diff using the utility
//! model, so the developer's expensive coding model spends no tokens on it.

use super::{git, resolve_workspace, sanitize_for_model, Workspace};
use crate::api::AppState;
use serde_json::{json, Value};

const MAX_DIFF_CHARS: usize = 12_000;

pub struct GitcommitResult {
    pub commit_message: String,
    pub model: String,
    pub diff_source: String,
}

/// Capture the diff to describe: explicit diff, else staged, else unstaged.
fn capture_diff(workspace: &Workspace) -> Result<(String, String), String> {
    let staged = git(
        workspace,
        &["diff", "--no-ext-diff", "--no-textconv", "--cached"],
    )?;
    if !staged.is_empty() {
        return Ok((staged, "staged changes (git diff --cached)".to_string()));
    }
    let unstaged = git(workspace, &["diff", "--no-ext-diff", "--no-textconv"])?;
    if !unstaged.is_empty() {
        return Ok((unstaged, "unstaged changes (git diff)".to_string()));
    }
    Err("No staged or unstaged changes to describe. Stage or edit files first.".to_string())
}

/// Small models wrap output in code fences or quotes; strip the most common
/// wrappers so the message is directly usable with `git commit -m`.
fn clean_message(raw: &str) -> String {
    // Filter out non-printable control characters and escape sequences
    let filtered: String = raw
        .chars()
        .filter(|&c| c == '\n' || (c >= ' ' && c != '\x7f'))
        .collect();
    let mut text = filtered.trim().trim_matches('`').trim().to_string();
    for quote in ['"', '\''] {
        if text.starts_with(quote) && text.ends_with(quote) && text.len() > 2 {
            let inner = text[1..text.len() - 1].trim();
            if !inner.contains(quote) {
                text = inner.to_string();
            }
        }
    }
    // drop any "commit message:" style prefix the model may add
    for prefix in ["commit message:", "commit:", "message:"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = rest.trim().to_string();
            break;
        }
    }
    // ensure the message does not start with a hyphen to prevent flag injection in git commit
    let trimmed = text.trim();
    let safe = trimmed.trim_start_matches('-');
    safe.trim().to_string()
}

pub async fn run(
    state: &AppState,
    diff: Option<String>,
    workspace: &str,
    instructions: Option<&str>,
) -> Result<GitcommitResult, String> {
    // Validate even when the caller supplied a diff so request data cannot
    // turn this into a workspace-free model endpoint.
    let workspace = resolve_workspace(
        state,
        Some(workspace).filter(|workspace| !workspace.trim().is_empty()),
    )?;
    let (diff, diff_source) = match diff {
        Some(diff) if !diff.trim().is_empty() => (diff, "provided diff".to_string()),
        _ => capture_diff(&workspace)?,
    };
    let stat = git(
        &workspace,
        &["diff", "--no-ext-diff", "--no-textconv", "--stat", "HEAD"],
    )
    .unwrap_or_default();
    let safe_stat = sanitize_for_model(&stat, Some(&workspace), 4_000);
    let safe_diff = sanitize_for_model(&diff, Some(&workspace), MAX_DIFF_CHARS);
    let safe_instructions = instructions.map(|text| sanitize_for_model(text, None, 2_000));

    let system = "You write concise, accurate git commit messages. Reply with ONLY the commit message: a subject line of 50 characters or fewer in the imperative mood, optionally followed by a blank line and a short body of at most 3 bullet points. No code fences, no explanation, no signature.";
    let user = format!(
        "Write a commit message for the change described below.\n\n<diff_summary>\n{}\n</diff_summary>\n\n<diff>\n{}\n</diff>{}",
        safe_stat,
        safe_diff,
        safe_instructions
            .map(|text| format!("\n\n<developer_instructions>\n{}\n</developer_instructions>", text))
            .unwrap_or_default()
    );

    let (raw, model) = super::complete(state, system, &user).await?;
    let commit_message = clean_message(&raw);
    if commit_message.is_empty() {
        return Err("Utility model did not produce a commit message".to_string());
    }
    if let Ok(db) = state.db.lock() {
        let _ = crate::db::log_activity(
            &db,
            &crate::db::ActivityEntry {
                id: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
                session_id: "default".into(),
                event_type: "tool".into(),
                title: "Generated commit message".into(),
                detail: Some(commit_message.clone()),
                metadata_json: Some(
                    serde_json::json!({ "model": model, "diff_source": diff_source }).to_string(),
                ),
            },
        );
    }
    Ok(GitcommitResult {
        commit_message,
        model,
        diff_source,
    })
}

/// Shared response shape for the API and CLI.
pub fn to_json(result: &GitcommitResult) -> Value {
    json!({
        "commit_message": result.commit_message,
        "model": result.model,
        "diff_source": result.diff_source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_common_model_wrappers() {
        assert_eq!(
            clean_message("```\nAdd vault encryption\n```"),
            "Add vault encryption"
        );
        assert_eq!(
            clean_message("\"Fix router failover\""),
            "Fix router failover"
        );
        assert_eq!(clean_message("commit message: Add CLI"), "Add CLI");
        assert_eq!(clean_message("  Update docs  "), "Update docs");
    }
}
