use super::ProviderAdapter;

pub struct LocalAdapter;

impl ProviderAdapter for LocalAdapter {
    fn name(&self) -> &str {
        "local"
    }

    fn default_base_url(&self) -> &str {
        "http://localhost:11434"
    }

    fn auth_headers(&self, _api_key: &str) -> Vec<(String, String)> {
        vec![]
    }
}
