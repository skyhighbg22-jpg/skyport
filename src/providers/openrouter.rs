use super::ProviderAdapter;

pub struct OpenRouterAdapter;

impl ProviderAdapter for OpenRouterAdapter {
    fn name(&self) -> &str {
        "openrouter"
    }

    fn default_base_url(&self) -> &str {
        "https://openrouter.ai/api"
    }
}
