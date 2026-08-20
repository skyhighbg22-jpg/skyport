//! Wire-protocol translation between the OpenAI chat format (what clients
//! send to the gateway) and native upstream formats (Anthropic Messages,
//! Google Gemini). Non-streaming bodies translate as whole JSON documents;
//! streaming translates native SSE events into OpenAI chunks.

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Anthropic Messages API
// ---------------------------------------------------------------------------

/// OpenAI chat body -> Anthropic Messages body.
pub fn to_anthropic(body: &Value) -> Value {
    let mut system = Vec::new();
    let mut messages = Vec::new();
    for message in body["messages"].as_array().unwrap_or(&Vec::new()) {
        let role = message["role"].as_str().unwrap_or("user");
        let text = content_to_text(&message["content"]);
        match role {
            "system" | "developer" => system.push(text),
            "assistant" => messages.push(json!({"role": "assistant", "content": text})),
            _ => messages.push(json!({"role": "user", "content": text})),
        }
    }
    let mut out = json!({
        "model": body["model"],
        "max_tokens": body["max_tokens"].as_u64().unwrap_or(1024),
        "messages": messages,
    });
    if !system.is_empty() {
        out["system"] = Value::String(system.join("\n\n"));
    }
    if let Some(stream) = body["stream"].as_bool() {
        out["stream"] = json!(stream);
    }
    if let Some(temperature) = body["temperature"].as_f64() {
        out["temperature"] = json!(temperature);
    }
    if let Some(top_p) = body["top_p"].as_f64() {
        out["top_p"] = json!(top_p);
    }
    if let Some(effort) = body["reasoning_effort"].as_str() {
        if effort != "minimal" {
            out["thinking"] = json!({"type": "enabled", "budget_tokens": 2048});
        }
    }
    out
}

/// Anthropic Messages response -> OpenAI chat completion.
pub fn from_anthropic(resp: &Value) -> Value {
    let content = resp["content"]
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter(|block| block["type"] == "text")
                .filter_map(|block| block["text"].as_str())
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    let reasoning = resp["content"]
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter(|block| block["type"] == "thinking")
                .filter_map(|block| block["thinking"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let finish = match resp["stop_reason"].as_str() {
        Some("max_tokens") => "length",
        Some(_) => "stop",
        None => "stop",
    };
    let mut message = json!({"role": "assistant", "content": content});
    if !reasoning.is_empty() {
        message["reasoning_content"] = Value::String(reasoning);
    }
    json!({
        "id": resp["id"].as_str().unwrap_or("chat_anthropic"),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": resp["model"].as_str().unwrap_or("anthropic"),
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": resp["usage"]["input_tokens"].as_u64().unwrap_or(0),
            "completion_tokens": resp["usage"]["output_tokens"].as_u64().unwrap_or(0),
            "total_tokens": resp["usage"]["input_tokens"].as_u64().unwrap_or(0)
                + resp["usage"]["output_tokens"].as_u64().unwrap_or(0),
        }
    })
}

/// One Anthropic SSE `data:` payload -> an OpenAI chunk, or None to skip.
/// `done` is set when the stream ended.
pub fn anthropic_stream_event(data: &str, done: &mut bool) -> Option<Value> {
    let event: Value = serde_json::from_str(data).ok()?;
    match event["type"].as_str()? {
        "content_block_delta" => {
            let delta = &event["delta"];
            if let Some(text) = delta["text"].as_str() {
                Some(chunk(text, None))
            } else {
                delta["thinking"]
                    .as_str()
                    .map(|thinking| reasoning_chunk(thinking, None))
            }
        }
        "message_delta" => {
            let usage = event["usage"]["output_tokens"].as_u64();
            let finish = match event["delta"]["stop_reason"].as_str() {
                Some("max_tokens") => "length",
                Some(_) => "stop",
                None => "stop",
            };
            Some(final_chunk(usage, finish))
        }
        "message_stop" => {
            *done = true;
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Google Gemini API
// ---------------------------------------------------------------------------

/// OpenAI chat body -> Gemini generateContent body.
pub fn to_gemini(body: &Value) -> Value {
    let mut system_parts = Vec::new();
    let mut contents = Vec::new();
    for message in body["messages"].as_array().unwrap_or(&Vec::new()) {
        let role = message["role"].as_str().unwrap_or("user");
        let text = content_to_text(&message["content"]);
        match role {
            "system" | "developer" => system_parts.push(json!({"text": text})),
            "assistant" => contents.push(json!({"role": "model", "parts": [{"text": text}]})),
            _ => contents.push(json!({"role": "user", "parts": [{"text": text}]})),
        }
    }
    let mut generation_config = json!({});
    if let Some(temperature) = body["temperature"].as_f64() {
        generation_config["temperature"] = json!(temperature);
    }
    if let Some(top_p) = body["top_p"].as_f64() {
        generation_config["topP"] = json!(top_p);
    }
    if let Some(max_tokens) = body["max_tokens"].as_u64() {
        generation_config["maxOutputTokens"] = json!(max_tokens);
    }
    let mut out = json!({"contents": contents, "generationConfig": generation_config});
    if !system_parts.is_empty() {
        out["systemInstruction"] = json!({"parts": system_parts});
    }
    out
}

/// Gemini generateContent response -> OpenAI chat completion.
pub fn from_gemini(resp: &Value) -> Value {
    let candidate = &resp["candidates"][0];
    let mut content = String::new();
    let mut reasoning = String::new();
    if let Some(parts) = candidate["content"]["parts"].as_array() {
        for part in parts {
            let Some(text) = part["text"].as_str() else {
                continue;
            };
            if part["thought"].as_bool().unwrap_or(false) {
                reasoning.push_str(text);
            } else {
                content.push_str(text);
            }
        }
    }
    let finish = match candidate["finishReason"].as_str() {
        Some("MAX_TOKENS") | Some("SAFETY") => "length",
        Some(_) => "stop",
        None => "stop",
    };
    let mut message = json!({"role": "assistant", "content": content});
    if !reasoning.is_empty() {
        message["reasoning_content"] = Value::String(reasoning);
    }
    let usage = &resp["usageMetadata"];
    json!({
        "id": format!("gemini-{}", uuid::Uuid::new_v4().simple()),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": resp["modelVersion"].as_str().unwrap_or("gemini"),
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": usage["promptTokenCount"].as_u64().unwrap_or(0),
            "completion_tokens": usage["candidatesTokenCount"].as_u64().unwrap_or(0),
            "total_tokens": usage["totalTokenCount"].as_u64().unwrap_or(0),
        }
    })
}

/// One Gemini SSE `data:` payload -> an OpenAI chunk, or None to skip.
pub fn gemini_stream_event(data: &str, done: &mut bool) -> Option<Value> {
    let event: Value = serde_json::from_str(data).ok()?;
    if event.get("candidates").is_none() && event.get("usageMetadata").is_none() {
        *done = true;
        return None;
    }
    let part = &event["candidates"][0]["content"]["parts"][0];
    if part.is_null() {
        if let Some(tokens) = event["usageMetadata"]["candidatesTokenCount"].as_u64() {
            return Some(final_chunk(Some(tokens), "stop"));
        }
        *done = true;
        return None;
    }
    let text = part["text"].as_str()?;
    if part["thought"].as_bool().unwrap_or(false) {
        Some(reasoning_chunk(text, None))
    } else {
        Some(chunk(text, None))
    }
}

// ---------------------------------------------------------------------------
// Responses API (ChatGPT Codex backend, Grok CLI proxy)
// ---------------------------------------------------------------------------

/// OpenAI chat body -> Responses API body. The Responses endpoints (Codex
/// backend at chatgpt.com, Grok CLI proxy) accept messages as `input` and
/// take `max_output_tokens` instead of `max_tokens`.
pub fn to_responses(body: &Value) -> Value {
    let mut instructions = Vec::new();
    let mut input = Vec::new();
    for message in body["messages"].as_array().unwrap_or(&Vec::new()) {
        let role = message["role"].as_str().unwrap_or("user");
        let text = content_to_text(&message["content"]);
        match role {
            "system" | "developer" => instructions.push(text),
            "assistant" => input.push(json!({
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}]
            })),
            _ => input.push(json!({
                "role": "user",
                "content": [{"type": "input_text", "text": text}]
            })),
        }
    }
    let mut out = json!({
        "model": body["model"],
        "input": input,
        "stream": body["stream"].as_bool().unwrap_or(false),
    });
    if !instructions.is_empty() {
        out["instructions"] = Value::String(instructions.join("\n\n"));
    }
    if let Some(max_tokens) = body["max_tokens"].as_u64() {
        out["max_output_tokens"] = json!(max_tokens);
    }
    if let Some(temperature) = body["temperature"].as_f64() {
        out["temperature"] = json!(temperature);
    }
    if let Some(top_p) = body["top_p"].as_f64() {
        out["top_p"] = json!(top_p);
    }
    if let Some(effort) = body["reasoning_effort"].as_str() {
        if effort != "minimal" {
            out["reasoning"] = json!({"effort": match effort {
                "low" => "low",
                "medium" => "medium",
                "high" => "high",
                _ => "medium",
            }});
        }
    }
    out
}

/// Responses API response -> OpenAI chat completion.
pub fn from_responses(resp: &Value) -> Value {
    let content = resp["output"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| item["type"] == "message")
                .flat_map(|item| item["content"].as_array().into_iter().flatten())
                .filter(|part| part["type"] == "output_text")
                .filter_map(|part| part["text"].as_str())
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    let reasoning = resp["output"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| item["type"] == "reasoning")
                .flat_map(|item| item["summary"].as_array().into_iter().flatten())
                .filter_map(|part| part["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let finish = match resp["status"].as_str() {
        Some("completed") => "stop",
        Some("incomplete") => "length",
        _ => "stop",
    };
    let mut message = json!({"role": "assistant", "content": content});
    if !reasoning.is_empty() {
        message["reasoning_content"] = Value::String(reasoning);
    }
    let usage = &resp["usage"];
    json!({
        "id": resp["id"].as_str().unwrap_or("resp_skyport"),
        "object": "chat.completion",
        "created": resp["created_at"].as_u64().unwrap_or_else(|| chrono::Utc::now().timestamp() as u64),
        "model": resp["model"].as_str().unwrap_or("responses"),
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": usage["input_tokens"].as_u64().unwrap_or(0),
            "completion_tokens": usage["output_tokens"].as_u64().unwrap_or(0),
            "total_tokens": usage["input_tokens"].as_u64().unwrap_or(0)
                + usage["output_tokens"].as_u64().unwrap_or(0),
        }
    })
}

/// One Responses-API SSE `data:` payload -> an OpenAI chunk, or None to skip.
/// `done` is set when the stream ended.
pub fn responses_stream_event(data: &str, done: &mut bool) -> Option<Value> {
    if data == "[DONE]" {
        return None;
    }
    let event: Value = serde_json::from_str(data).ok()?;
    match event["type"].as_str()? {
        "response.output_text.delta" => Some(chunk(event["delta"].as_str()?, None)),
        "response.reasoning_summary_text.delta" => {
            Some(reasoning_chunk(event["delta"].as_str()?, None))
        }
        "response.completed" => {
            *done = true;
            Some(final_chunk(
                event["response"]["usage"]["output_tokens"].as_u64(),
                "stop",
            ))
        }
        "response.incomplete" => {
            *done = true;
            Some(final_chunk(None, "length"))
        }
        "response.failed" => {
            *done = true;
            Some(final_chunk(None, "stop"))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Shared chunk builders
// ---------------------------------------------------------------------------

fn chunk(text: &str, finish: Option<&str>) -> Value {
    json!({
        "object": "chat.completion.chunk",
        "choices": [{
            "index": 0,
            "delta": {"content": text},
            "finish_reason": finish,
        }]
    })
}

fn reasoning_chunk(text: &str, finish: Option<&str>) -> Value {
    json!({
        "object": "chat.completion.chunk",
        "choices": [{
            "index": 0,
            "delta": {"reasoning_content": text},
            "finish_reason": finish,
        }]
    })
}

fn final_chunk(completion_tokens: Option<u64>, finish: &str) -> Value {
    let mut out = json!({
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
    });
    if let Some(tokens) = completion_tokens {
        out["usage"] = json!({"completion_tokens": tokens});
    }
    out
}

/// Flatten OpenAI message content (string or text-part array) to plain text.
fn content_to_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join(""),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_round_trip() {
        let openai = json!({
            "model": "claude-sonnet-5",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"},
                {"role": "user", "content": "bye"}
            ],
            "max_tokens": 64,
            "temperature": 0.3
        });
        let anthropic = to_anthropic(&openai);
        assert_eq!(anthropic["system"], "be terse");
        assert_eq!(anthropic["messages"].as_array().unwrap().len(), 3);
        assert_eq!(anthropic["messages"][0]["role"], "user");
        assert_eq!(anthropic["max_tokens"], 64);
        assert!(anthropic["messages"].is_array());

        let native = json!({
            "id": "msg_1", "model": "claude-sonnet-5",
            "content": [
                {"type": "thinking", "thinking": "pondering"},
                {"type": "text", "text": "answer"}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });
        let back = from_anthropic(&native);
        assert_eq!(back["choices"][0]["message"]["content"], "answer");
        assert_eq!(
            back["choices"][0]["message"]["reasoning_content"],
            "pondering"
        );
        assert_eq!(back["usage"]["prompt_tokens"], 10);
        assert_eq!(back["usage"]["completion_tokens"], 5);
    }

    #[test]
    fn gemini_round_trip() {
        let openai = json!({
            "model": "gemini-3-pro",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"}
            ],
            "max_tokens": 32
        });
        let gemini = to_gemini(&openai);
        assert_eq!(gemini["systemInstruction"]["parts"][0]["text"], "be terse");
        assert_eq!(gemini["contents"][0]["role"], "user");
        assert_eq!(gemini["generationConfig"]["maxOutputTokens"], 32);

        let native = json!({
            "candidates": [{"content": {"parts": [{"text": "answer"}]}, "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 3, "totalTokenCount": 10},
            "modelVersion": "gemini-3-pro"
        });
        let back = from_gemini(&native);
        assert_eq!(back["choices"][0]["message"]["content"], "answer");
        assert_eq!(back["usage"]["prompt_tokens"], 7);
        assert_eq!(back["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn responses_round_trip() {
        let openai = json!({
            "model": "gpt-5.4-codex-mini",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"}
            ],
            "max_tokens": 64,
            "temperature": 0.3,
            "reasoning_effort": "high"
        });
        let responses = to_responses(&openai);
        assert_eq!(responses["model"], "gpt-5.4-codex-mini");
        assert_eq!(responses["instructions"], "be terse");
        assert_eq!(responses["input"][0]["role"], "user");
        assert_eq!(responses["input"][0]["content"][0]["type"], "input_text");
        assert_eq!(responses["max_output_tokens"], 64);
        assert_eq!(responses["reasoning"]["effort"], "high");
        assert_eq!(responses["stream"], false);

        let native = json!({
            "id": "resp_1", "object": "response", "status": "completed",
            "model": "gpt-5.4-codex-mini", "created_at": 123,
            "output": [
                {"type": "reasoning", "summary": [{"type": "summary_text", "text": "pondering"}]},
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "answer"}
                ]}
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
        });
        let back = from_responses(&native);
        assert_eq!(back["choices"][0]["message"]["content"], "answer");
        assert_eq!(
            back["choices"][0]["message"]["reasoning_content"],
            "pondering"
        );
        assert_eq!(back["choices"][0]["finish_reason"], "stop");
        assert_eq!(back["usage"]["prompt_tokens"], 10);
        assert_eq!(back["usage"]["completion_tokens"], 5);
        assert_eq!(back["usage"]["total_tokens"], 15);
    }

    #[test]
    fn responses_stream_events_translate_to_chat_chunks() {
        let mut done = false;
        let delta = responses_stream_event(
            r#"{"type":"response.output_text.delta","delta":"yo"}"#,
            &mut done,
        )
        .unwrap();
        assert_eq!(delta["choices"][0]["delta"]["content"], "yo");
        assert!(!done);

        let thought = responses_stream_event(
            r#"{"type":"response.reasoning_summary_text.delta","delta":"hmm"}"#,
            &mut done,
        )
        .unwrap();
        assert_eq!(thought["choices"][0]["delta"]["reasoning_content"], "hmm");

        let last = responses_stream_event(
            r#"{"type":"response.completed","response":{"usage":{"output_tokens":5}}}"#,
            &mut done,
        )
        .unwrap();
        assert_eq!(last["choices"][0]["finish_reason"], "stop");
        assert_eq!(last["usage"]["completion_tokens"], 5);
        assert!(done);

        let mut done = false;
        assert!(
            responses_stream_event(r#"{"type":"response.created","response":{}}"#, &mut done)
                .is_none()
        );
        assert!(!done);
        responses_stream_event(r#"{"type":"response.incomplete"}"#, &mut done).unwrap();
        assert!(done, "incomplete must end the stream with a length chunk");
    }

    #[test]
    fn stream_events_translate() {
        let mut done = false;
        let delta = anthropic_stream_event(
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}"#,
            &mut done,
        )
        .unwrap();
        assert_eq!(delta["choices"][0]["delta"]["content"], "hi");
        assert!(!done);
        assert!(anthropic_stream_event(r#"{"type":"message_stop"}"#, &mut done).is_none());
        assert!(done);

        let mut done = false;
        let chunk = gemini_stream_event(
            r#"{"candidates":[{"content":{"parts":[{"text":"yo"}]}}]}"#,
            &mut done,
        )
        .unwrap();
        assert_eq!(chunk["choices"][0]["delta"]["content"], "yo");
        let thought = gemini_stream_event(
            r#"{"candidates":[{"content":{"parts":[{"text":"hmm","thought":true}]}}]}"#,
            &mut done,
        )
        .unwrap();
        assert_eq!(thought["choices"][0]["delta"]["reasoning_content"], "hmm");
    }
}
