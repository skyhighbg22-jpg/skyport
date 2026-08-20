use super::ProviderAdapter;

pub struct GroqAdapter;

impl ProviderAdapter for GroqAdapter {
    fn name(&self) -> &str {
        "groq"
    }

    fn default_base_url(&self) -> &str {
        "https://api.groq.com/openai"
    }
}
