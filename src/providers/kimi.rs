use super::ProviderAdapter;

pub struct KimiAdapter;

impl ProviderAdapter for KimiAdapter {
    fn name(&self) -> &str {
        "kimi"
    }

    fn default_base_url(&self) -> &str {
        "https://api.moonshot.cn"
    }
}
