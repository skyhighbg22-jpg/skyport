//! /btw — a side channel for asking questions about the current AI coding
//! session. Answers come from observable facts (gateway telemetry, repository
//! state) plus a cheap utility model; no harness support required.

use super::{repo_facts, resolve_workspace, sanitize_for_model, telemetry_facts};
use crate::api::AppState;
use serde_json::{json, Value};

pub struct BtwResult {
    pub answer: String,
    pub model: Option<String>,
    pub facts: Vec<String>,
}

fn pick_facts(question: &str, facts: &[String]) -> String {
    let q = question.to_lowercase();
    let relevant: Vec<&String> = facts
        .iter()
        .filter(|fact| {
            if q.contains("cost") || q.contains("spend") || q.contains("token") {
                fact.contains("$") || fact.contains("tok") || fact.contains("requests")
            } else if q.contains("file") || q.contains("touched") || q.contains("changed") {
                fact.contains("git ") || fact.starts_with("Workspace")
            } else {
                true
            }
        })
        .collect();
    let chosen: Vec<&str> = if relevant.is_empty() {
        facts.iter().map(String::as_str).collect()
    } else {
        relevant.iter().map(|s| s.as_str()).collect()
    };
    chosen.join("\n")
}

/// Direct, deterministic answers for the common questions so /btw stays
/// useful even when no utility model is configured or reachable.
fn heuristic_answer(question: &str, facts: &[String]) -> String {
    let q = question.to_lowercase();
    let has = |needle: &str| q.contains(needle);
    if has("cost") || has("spend") {
        facts
            .iter()
            .filter(|f| f.contains("$") || f.contains("tokens"))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    } else if has("file") || has("touched") || has("changed") {
        facts
            .iter()
            .filter(|f| f.contains("git") || f.starts_with("Workspace"))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        facts.join("\n")
    }
}

pub async fn run(
    state: &AppState,
    question: &str,
    workspace: Option<&str>,
) -> Result<BtwResult, String> {
    let workspace = resolve_workspace(state, workspace)?;
    let mut facts = telemetry_facts(state, 25);
    facts.extend(repo_facts(&workspace));
    facts = facts
        .into_iter()
        .map(|fact| sanitize_for_model(&fact, None, 8_000))
        .collect();

    let system = "You are Skyport's session inspector. A developer is asking a quick side question while their AI coding session runs through this gateway. Answer using ONLY the provided facts. Be concise and direct: short paragraphs or bullet points, concrete numbers over prose. If the facts do not contain the answer, say so plainly.";
    let user = format!(
        "Facts gathered from the gateway and repository:\n{}\n\nDeveloper question: {question}",
        sanitize_for_model(&pick_facts(question, &facts), None, 16_000)
    );

    let result = match super::complete(state, system, &user).await {
        Ok((answer, model)) => BtwResult {
            answer,
            model: Some(model),
            facts,
        },
        // The side channel must keep working without a model: fall back to
        // the raw observable facts, noting why the model was skipped.
        Err(error) => BtwResult {
            answer: format!(
                "(Utility model unavailable: {error} — answering from raw gateway observations)\n{}",
                heuristic_answer(question, &facts)
            ),
            model: None,
            facts,
        },
    };

    if let Ok(db) = state.db.lock() {
        let _ = crate::db::log_activity(
            &db,
            &crate::db::ActivityEntry {
                id: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
                session_id: "default".into(),
                event_type: "tool".into(),
                title: format!("Asked /btw: {question}"),
                detail: Some(result.answer.chars().take(200).collect()),
                metadata_json: Some(
                    serde_json::json!({ "question": question, "model": result.model }).to_string(),
                ),
            },
        );
    }

    Ok(result)
}

pub fn to_json(result: &BtwResult) -> Value {
    json!({
        "answer": result.answer,
        "model": result.model,
        "facts": result.facts,
    })
}
