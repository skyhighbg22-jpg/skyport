use super::ProviderAdapter;

pub struct OpenAiAdapter;

impl ProviderAdapter for OpenAiAdapter {
    fn name(&self) -> &str {
        "openai"
    }

    fn default_base_url(&self) -> &str {
        "https://api.openai.com"
    }
}
