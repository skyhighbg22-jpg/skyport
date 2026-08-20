use super::ProviderAdapter;

pub struct NvidiaAdapter;

impl ProviderAdapter for NvidiaAdapter {
    fn name(&self) -> &str {
        "nvidia"
    }

    fn default_base_url(&self) -> &str {
        "https://integrate.api.nvidia.com"
    }
}
