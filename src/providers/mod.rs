pub mod deepseek;
pub mod gemini;
pub mod groq;
pub mod kimi;
pub mod local;
pub mod nvidia;
pub mod openai;
pub mod openrouter;
pub mod translate;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    // catch-all for extra fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    #[serde(default)]
    pub content: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EmbeddingRequest {
    pub model: String,
    pub input: serde_json::Value,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub choices: Vec<serde_json::Value>,
    #[serde(default)]
    pub usage: Option<Usage>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub total_tokens: u64,
}

/// Price per 1M tokens (input, output)
#[derive(Debug, Clone)]
pub struct PriceTable {
    pub input_per_m: f64,
    pub output_per_m: f64,
}

impl PriceTable {
    pub fn estimate_cost(&self, prompt_tokens: u64, completion_tokens: u64) -> f64 {
        (prompt_tokens as f64 * self.input_per_m + completion_tokens as f64 * self.output_per_m)
            / 1_000_000.0
    }
}

pub fn default_prices(provider: &str) -> Option<PriceTable> {
    Some(match provider {
        "openai" => PriceTable {
            input_per_m: 2.50,
            output_per_m: 10.00,
        },
        "gemini" => PriceTable {
            input_per_m: 1.25,
            output_per_m: 5.00,
        },
        "nvidia" => PriceTable {
            // NIM hosts its catalog free for prototyping; there is no
            // per-token billing on integrate.api.nvidia.com.
            input_per_m: 0.0,
            output_per_m: 0.0,
        },
        "groq" => PriceTable {
            input_per_m: 0.27,
            output_per_m: 0.27,
        },
        "deepseek" => PriceTable {
            input_per_m: 0.14,
            output_per_m: 0.28,
        },
        "kimi" => PriceTable {
            input_per_m: 1.00,
            output_per_m: 3.00,
        },
        "openrouter" => PriceTable {
            input_per_m: 2.00,
            output_per_m: 6.00,
        },
        "ollama" | "lmstudio" => PriceTable {
            input_per_m: 0.0,
            output_per_m: 0.0,
        },
        _ => return None,
    })
}

/// Each provider adapter transforms the request/response as needed
pub trait ProviderAdapter: Send + Sync {
    fn name(&self) -> &str;
    fn default_base_url(&self) -> &str;
    /// Transform chat request body for this provider (most are OpenAI-compatible, return as-is)
    fn transform_request(&self, req: &ChatRequest) -> serde_json::Value {
        serde_json::to_value(req).unwrap_or_default()
    }
    /// Build headers for the request
    fn auth_headers(&self, api_key: &str) -> Vec<(String, String)> {
        vec![("Authorization".to_string(), format!("Bearer {}", api_key))]
    }
    /// Chat completions endpoint path
    fn chat_endpoint(&self) -> &str {
        "/v1/chat/completions"
    }
    /// Embeddings endpoint path
    fn embeddings_endpoint(&self) -> &str {
        "/v1/embeddings"
    }
    /// Models endpoint path
    fn models_endpoint(&self) -> &str {
        "/v1/models"
    }
}
