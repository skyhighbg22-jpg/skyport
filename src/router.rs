use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::config::SkyportConfig;
use crate::vault::Vault;

/// The result of routing a request: which provider, URL, and key to use.
#[derive(Clone)]
pub struct RouteDecision {
    pub provider: String,
    pub base_url: String,
    pub api_key: String,
    pub key_alias: String,
    /// Wire protocol of the upstream ("openai", "anthropic", "gemini",
    /// "responses").
    pub format: String,
    /// Subscription metadata (`oauth_extra`) of the selected key, when the
    /// key was minted by an account sign-in. None = plain API key.
    pub oauth_extra: Option<serde_json::Value>,
}

impl fmt::Debug for RouteDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteDecision")
            .field("provider", &self.provider)
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("key_alias", &self.key_alias)
            .field("format", &self.format)
            .field(
                "oauth_extra",
                &self.oauth_extra.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[cfg(not(test))]
impl Drop for RouteDecision {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.api_key.zeroize();
    }
}

/// Routes requests to providers and manages multi-key failover.
pub struct Router {
    pub vault: Arc<RwLock<Vault>>,
    pub config: Arc<RwLock<SkyportConfig>>,
    round_robin_counters: Arc<RwLock<HashMap<String, usize>>>,
}

impl Router {
    pub fn new(vault: Arc<RwLock<Vault>>, config: Arc<RwLock<SkyportConfig>>) -> Self {
        Self {
            vault,
            config,
            round_robin_counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Resolve a model name to (provider, actual_model).
    ///
    /// Resolution order:
    /// 1. Exact match in `routing.model_map` (value is "provider/model").
    /// 2. Input contains `/` – parse as "provider/model".
    /// 3. Fall back to `routing.default_provider`.
    pub fn resolve_model(
        &self,
        model_name: &str,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        let cfg = self
            .config
            .read()
            .map_err(|e| format!("Config lock poisoned: {e}"))?;

        // 1. Check model_map
        if let Some(mapped) = cfg.routing.model_map.get(model_name) {
            if let Some((provider, model)) = mapped.split_once('/') {
                return Ok((provider.to_string(), model.to_string()));
            }
            // If the mapped value has no slash, treat it as provider with original model name
            return Ok((mapped.clone(), model_name.to_string()));
        }

        // 2. Parse "provider/model"
        if let Some((provider, model)) = model_name.split_once('/') {
            return Ok((provider.to_string(), model.to_string()));
        }

        // 3. Default provider
        if let Some(ref default) = cfg.routing.default_provider {
            return Ok((default.clone(), model_name.to_string()));
        }

        Err(format!("Cannot resolve model: {model_name}").into())
    }

    /// Select an API key for the given provider, respecting priority, cooldowns,
    /// and optional round-robin rotation.
    pub fn select_key(&self, provider: &str) -> Result<RouteDecision, Box<dyn std::error::Error>> {
        let vault = self
            .vault
            .read()
            .map_err(|e| format!("Vault lock poisoned: {e}"))?;
        let cfg = self
            .config
            .read()
            .map_err(|e| format!("Config lock poisoned: {e}"))?;

        let provider_config = cfg
            .providers
            .get(provider)
            .ok_or_else(|| format!("Unknown provider: {provider}"))?;

        if !provider_config.enabled {
            return Err(format!("Provider {provider} is disabled").into());
        }

        let now = Utc::now();
        let all_keys = vault.get_keys_for_provider(provider);

        let eligible: Vec<_> = all_keys
            .into_iter()
            .filter(|k| {
                k.enabled
                    && match k.cooldown_until {
                        Some(cd) => cd < now,
                        None => true,
                    }
            })
            .collect();

        if eligible.is_empty() && Vault::is_keyless_provider(provider) {
            return Ok(RouteDecision {
                provider: provider.to_string(),
                base_url: provider_config.base_url.clone(),
                api_key: String::new(),
                key_alias: "local".to_string(),
                format: provider_config.wire_format().to_string(),
                oauth_extra: None,
            });
        }

        if eligible.is_empty() {
            return Err(format!("No available API key for provider: {provider}").into());
        }

        let selected = if provider_config.round_robin {
            let mut counters = self
                .round_robin_counters
                .write()
                .map_err(|e| format!("RR lock poisoned: {e}"))?;
            let counter = counters.entry(provider.to_string()).or_insert(0);
            let idx = *counter % eligible.len();
            *counter = counter.wrapping_add(1);
            eligible[idx]
        } else {
            eligible[0]
        };

        Ok(RouteDecision {
            provider: provider.to_string(),
            base_url: provider_config.base_url.clone(),
            api_key: selected.api_key.clone(),
            key_alias: selected.key_alias.clone(),
            format: provider_config.wire_format().to_string(),
            oauth_extra: selected.oauth_extra.clone(),
        })
    }

    /// Mark a key as failed based on the HTTP status code.
    ///
    /// - 429 → cooldown for `retry_after` seconds (default 60).
    /// - 401 → permanently disable the key.
    /// - 5xx → short cooldown (10 s).
    pub fn mark_key_failed(&self, alias: &str, status: u16, retry_after: Option<u64>) {
        if let Ok(mut vault) = self.vault.write() {
            match status {
                429 => {
                    let secs = retry_after.unwrap_or(60) as i64;
                    let until = Utc::now() + Duration::seconds(secs);
                    vault.set_cooldown(alias, until);
                }
                401 => {
                    vault.disable_key(alias);
                }
                500..=599 => {
                    let until = Utc::now() + Duration::seconds(10);
                    vault.set_cooldown(alias, until);
                }
                _ => {}
            }
            // Preserve health state across restarts after an upstream failure.
            if vault.save().is_err() {
                tracing::warn!("could not persist provider health state");
            }
        }
    }

    /// Clear any cooldown on a key after a successful request.
    pub fn mark_key_success(&self, alias: &str) {
        if let Ok(mut vault) = self.vault.write() {
            if let Some(entry) = vault.entries.iter_mut().find(|e| e.key_alias == alias) {
                entry.cooldown_until = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{default_config, ProviderConfig};
    use crate::vault::VaultEntry;

    #[test]
    fn routes_priority_and_skips_cooldown() {
        let mut cfg = default_config();
        cfg.providers.insert(
            "test".into(),
            ProviderConfig {
                name: "Test".into(),
                base_url: "http://example.test/v1".into(),
                enabled: true,
                round_robin: false,
                format: None,
            },
        );
        let vault = Vault {
            entries: vec![
                VaultEntry {
                    key_alias: "first".into(),
                    provider: "test".into(),
                    api_key: "a".into(),
                    priority: 1,
                    enabled: true,
                    cooldown_until: Some(Utc::now() + Duration::minutes(1)),
                    ..Default::default()
                },
                VaultEntry {
                    key_alias: "second".into(),
                    provider: "test".into(),
                    api_key: "b".into(),
                    priority: 2,
                    enabled: true,
                    ..Default::default()
                },
            ],
            master_key: vec![],
        };
        let router = Router::new(Arc::new(RwLock::new(vault)), Arc::new(RwLock::new(cfg)));
        assert_eq!(router.select_key("test").unwrap().key_alias, "second");
    }

    #[test]
    fn round_robin_rotates_across_eligible_keys() {
        let mut cfg = default_config();
        cfg.providers.insert(
            "nvidia".into(),
            ProviderConfig {
                name: "NVIDIA NIM".into(),
                base_url: "http://example.test/v1".into(),
                enabled: true,
                round_robin: true,
                format: None,
            },
        );
        let vault = Vault {
            entries: (1..=3)
                .map(|i| VaultEntry {
                    key_alias: format!("key-{i}"),
                    provider: "nvidia".into(),
                    api_key: format!("secret-{i}"),
                    priority: 1,
                    enabled: true,
                    ..Default::default()
                })
                .collect(),
            master_key: vec![],
        };
        let router = Router::new(Arc::new(RwLock::new(vault)), Arc::new(RwLock::new(cfg)));
        let picked: Vec<String> = (0..3)
            .map(|_| router.select_key("nvidia").unwrap().key_alias)
            .collect();
        assert_eq!(picked.len(), 3);
        assert_eq!(
            picked
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );
    }
}
