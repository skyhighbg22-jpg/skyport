use super::ProviderAdapter;

pub struct GeminiAdapter;

impl ProviderAdapter for GeminiAdapter {
    fn name(&self) -> &str {
        "gemini"
    }

    fn default_base_url(&self) -> &str {
        "https://generativelanguage.googleapis.com/v1beta/openai"
    }
}
