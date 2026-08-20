use super::ProviderAdapter;

pub struct DeepSeekAdapter;

impl ProviderAdapter for DeepSeekAdapter {
    fn name(&self) -> &str {
        "deepseek"
    }

    fn default_base_url(&self) -> &str {
        "https://api.deepseek.com"
    }
}
