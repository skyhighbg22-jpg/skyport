use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn default_port() -> u16 {
    5790
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SkyportConfig {
    #[serde(skip)]
    pub(crate) disk_fingerprint: Arc<Mutex<Option<[u8; 32]>>>,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub budgets: HashMap<String, BudgetConfig>,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub utility: UtilityConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Maximum requests per minute globally (None = unlimited).
    #[serde(default)]
    pub max_rpm: Option<u32>,
    /// Maximum requests per second burst limit globally (None = unlimited).
    #[serde(default)]
    pub max_rps: Option<u32>,
}

fn default_retention_days() -> u32 {
    90
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TelemetryConfig {
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
        }
    }
}

/// Settings for harness-independent tools (/gitcommit, /btw) that run on a
/// cheap or local model instead of the developer's coding model.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UtilityConfig {
    /// Route for background tool calls, e.g. "lmstudio/google/gemma-4-e4b".
    pub model: Option<String>,
    /// Default workspace the tools observe when a request omits one.
    pub workspace: Option<String>,
    /// Explicit consent before repository data may be sent to a cloud model.
    #[serde(default)]
    pub allow_cloud: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    /// SHA-256 verifiers only. Raw tokens live in platform-secure storage.
    #[serde(default)]
    pub admin_token_hash: Option<String>,
    #[serde(default)]
    pub inference_token_hash: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            admin_token_hash: None,
            inference_token_hash: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProviderConfig {
    #[serde(default)]
    pub name: String,
    pub base_url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub round_robin: bool,
    /// Upstream wire protocol: "openai" (compat passthrough), "anthropic"
    /// (Messages API translation), or "gemini" (native API translation).
    #[serde(default)]
    pub format: Option<String>,
}

impl ProviderConfig {
    pub fn wire_format(&self) -> &str {
        match self.format.as_deref() {
            Some("anthropic") => "anthropic",
            Some("gemini") => "gemini",
            // Subscription sign-ins (ChatGPT Codex, Grok CLI proxy) speak the
            // OpenAI Responses API natively instead of chat completions.
            Some("responses") => "responses",
            _ => "openai",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BudgetConfig {
    #[serde(default)]
    pub monthly_cap_usd: Option<f64>,
    #[serde(default)]
    pub daily_cap_usd: Option<f64>,
    /// Maximum requests per minute for this scope (None = unlimited).
    #[serde(default)]
    pub max_rpm: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RoutingConfig {
    #[serde(default)]
    pub model_map: HashMap<String, String>,
    #[serde(default)]
    pub default_provider: Option<String>,
}

pub fn config_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".skyport")
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub pid: u32,
    #[serde(default)]
    pub port: Option<u16>,
}

pub fn write_pid(pid: u32, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let dir = config_dir();
    crate::vault::ensure_secure_directory(&dir)?;
    let runtime = serde_json::to_vec(&RuntimeInfo {
        pid,
        port: Some(port),
    })?;
    crate::vault::atomic_write(&dir.join("skyport.pid"), &runtime)?;
    Ok(())
}

pub fn read_runtime_info() -> Result<RuntimeInfo, Box<dyn std::error::Error>> {
    let path = config_dir().join("skyport.pid");
    crate::vault::reject_symlink(&path)?;
    let value = std::fs::read_to_string(path)?;
    if value.len() > 256 {
        return Err("Invalid PID file".into());
    }
    parse_runtime_info(&value)
}

pub fn read_pid() -> Result<u32, Box<dyn std::error::Error>> {
    Ok(read_runtime_info()?.pid)
}

fn parse_runtime_info(value: &str) -> Result<RuntimeInfo, Box<dyn std::error::Error>> {
    let value = value.trim();
    let runtime = match value.parse::<u32>() {
        Ok(pid) => RuntimeInfo { pid, port: None },
        Err(_) => serde_json::from_str::<RuntimeInfo>(value)?,
    };
    if runtime.pid == 0 || runtime.port.is_some_and(|port| port < 1024) {
        return Err("Invalid PID file".into());
    }
    Ok(runtime)
}

pub fn remove_pid() {
    let path = config_dir().join("skyport.pid");
    if crate::vault::reject_symlink(&path).is_ok() {
        let _ = std::fs::remove_file(path);
    }
}

pub fn load_config() -> Result<SkyportConfig, Box<dyn std::error::Error>> {
    let dir = config_dir();
    crate::vault::ensure_secure_directory(&dir)?;
    let _lock = config_lock(&dir)?;
    let config_path = config_dir().join("config.toml");
    crate::vault::reject_symlink(&config_path)?;
    if !config_path.exists() {
        return Ok(default_config());
    }
    let contents = std::fs::read_to_string(&config_path)?;
    let mut config: SkyportConfig = toml::from_str(&contents)?;
    *config
        .disk_fingerprint
        .lock()
        .map_err(|_| "Configuration fingerprint lock poisoned")? =
        Some(file_fingerprint(contents.as_bytes()));
    // Union in bundled providers an existing config has never seen, so new
    // releases add providers without clobbering custom edits. Disable a
    // provider to remove it from routing; deleting it only re-adds it here.
    for (id, provider) in built_in_providers() {
        config.providers.entry(id).or_insert(provider);
    }
    Ok(config)
}

pub fn save_config(config: &SkyportConfig) -> Result<(), Box<dyn std::error::Error>> {
    let dir = config_dir();
    crate::vault::ensure_secure_directory(&dir)?;
    let _lock = config_lock(&dir)?;
    let path = dir.join("config.toml");
    crate::vault::reject_symlink(&path)?;
    let expected = *config
        .disk_fingerprint
        .lock()
        .map_err(|_| "Configuration fingerprint lock poisoned")?;
    let current = match std::fs::read(&path) {
        Ok(contents) => Some(file_fingerprint(&contents)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if current != expected {
        return Err("Configuration changed in another process; reload before saving".into());
    }
    let toml_string = toml::to_string_pretty(config)?;
    crate::vault::atomic_write(&path, toml_string.as_bytes())?;
    *config
        .disk_fingerprint
        .lock()
        .map_err(|_| "Configuration fingerprint lock poisoned")? =
        Some(file_fingerprint(toml_string.as_bytes()));
    Ok(())
}

fn file_fingerprint(contents: &[u8]) -> [u8; 32] {
    Sha256::digest(contents).into()
}

fn config_lock(dir: &std::path::Path) -> io::Result<File> {
    let path = dir.join("config.lock");
    crate::vault::reject_symlink(&path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.lock()?;
    Ok(file)
}

/// The complete built-in provider set: the core nine plus every
/// OpenAI-compatible upstream from the bundled models.dev catalog.
pub fn built_in_providers() -> HashMap<String, ProviderConfig> {
    let mut providers = HashMap::new();

    providers.insert(
        "openai".to_string(),
        ProviderConfig {
            name: "OpenAI".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            enabled: true,
            round_robin: false,
            format: None,
        },
    );

    providers.insert(
        "anthropic".to_string(),
        ProviderConfig {
            name: "Anthropic".to_string(),
            base_url: "https://api.anthropic.com".to_string(),
            enabled: true,
            round_robin: false,
            format: Some("anthropic".to_string()),
        },
    );

    providers.insert(
        "gemini".to_string(),
        ProviderConfig {
            name: "Google Gemini".to_string(),
            base_url: "https://generativelanguage.googleapis.com/v1beta/openai".to_string(),
            enabled: true,
            round_robin: false,
            format: None,
        },
    );

    providers.insert(
        "nvidia".to_string(),
        ProviderConfig {
            name: "NVIDIA NIM".to_string(),
            base_url: "https://integrate.api.nvidia.com/v1".to_string(),
            enabled: true,
            round_robin: false,
            format: None,
        },
    );

    providers.insert(
        "groq".to_string(),
        ProviderConfig {
            name: "Groq".to_string(),
            base_url: "https://api.groq.com/openai/v1".to_string(),
            enabled: true,
            round_robin: false,
            format: None,
        },
    );

    providers.insert(
        "deepseek".to_string(),
        ProviderConfig {
            name: "DeepSeek".to_string(),
            base_url: "https://api.deepseek.com/v1".to_string(),
            enabled: true,
            round_robin: false,
            format: None,
        },
    );

    providers.insert(
        "kimi".to_string(),
        ProviderConfig {
            name: "Kimi (Moonshot)".to_string(),
            base_url: "https://api.moonshot.cn/v1".to_string(),
            enabled: true,
            round_robin: false,
            format: None,
        },
    );

    providers.insert(
        "openrouter".to_string(),
        ProviderConfig {
            name: "OpenRouter".to_string(),
            base_url: "https://openrouter.ai/api/v1".to_string(),
            enabled: true,
            round_robin: false,
            format: None,
        },
    );

    providers.insert(
        "ollama".to_string(),
        ProviderConfig {
            name: "Ollama (Local)".to_string(),
            base_url: "http://localhost:11434/v1".to_string(),
            enabled: true,
            round_robin: false,
            format: None,
        },
    );

    providers.insert(
        "lmstudio".to_string(),
        ProviderConfig {
            name: "LM Studio (Local)".to_string(),
            base_url: "http://localhost:1234/v1".to_string(),
            enabled: true,
            round_robin: false,
            format: None,
        },
    );

    // The long tail of catalog upstreams is unverified and rarely useful; add
    // them disabled so a fresh install only routes through the core providers.
    // Flip `enabled` in the UI (or config.toml) to use one.
    for (id, name, base_url) in crate::provider_table::BUNDLED_PROVIDERS {
        providers.insert(
            id.to_string(),
            ProviderConfig {
                name: name.to_string(),
                base_url: base_url.to_string(),
                enabled: false,
                round_robin: false,
                format: None,
            },
        );
    }

    providers
}

pub fn default_config() -> SkyportConfig {
    SkyportConfig {
        disk_fingerprint: Arc::new(Mutex::new(None)),
        server: ServerConfig {
            port: 5790,
            admin_token_hash: None,
            inference_token_hash: None,
        },
        providers: built_in_providers(),
        routing: RoutingConfig {
            model_map: HashMap::new(),
            default_provider: None,
        },
        budgets: HashMap::new(),
        rate_limit: RateLimitConfig::default(),
        utility: UtilityConfig::default(),
        telemetry: TelemetryConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_providers_cover_the_catalog_and_merge_without_overriding() {
        let providers = built_in_providers();
        assert!(
            providers.len() >= 140,
            "expected broad catalog, got {}",
            providers.len()
        );
        for id in [
            "openai",
            "gemini",
            "groq",
            "lmstudio",
            "openrouter",
            "chutes",
            "togetherai",
            "mistral",
            "xai",
        ] {
            assert!(providers.contains_key(id), "missing {id}");
        }
        // bundled catalog upstreams are off by default; only core providers route
        assert!(providers["openai"].enabled);
        assert!(providers["lmstudio"].enabled);
        assert!(!providers["chutes"].enabled);
        assert!(!providers["302ai"].enabled);
        let enabled_count = providers.values().filter(|p| p.enabled).count();
        assert_eq!(enabled_count, 10, "only the core providers start enabled");

        // merging into an existing config must not clobber custom edits
        let mut config: SkyportConfig = toml::from_str("").unwrap();
        config.providers.insert(
            "openai".to_string(),
            ProviderConfig {
                name: "Custom OpenAI".to_string(),
                base_url: "http://localhost:9999/v1".to_string(),
                enabled: false,
                round_robin: true,
                format: None,
            },
        );
        for (id, provider) in built_in_providers() {
            config.providers.entry(id).or_insert(provider);
        }
        assert_eq!(config.providers["openai"].name, "Custom OpenAI");
        assert!(!config.providers["openai"].enabled);
        assert!(config.providers.contains_key("chutes"));
    }

    #[test]
    fn runtime_fingerprint_is_not_serialized_and_detects_changes() {
        let config = default_config();
        let serialized = toml::to_string(&config).unwrap();
        assert!(!serialized.contains("disk_fingerprint"));
        assert_ne!(file_fingerprint(b"first"), file_fingerprint(b"second"));
    }

    #[test]
    fn runtime_info_supports_current_and_legacy_pid_files() {
        assert_eq!(
            parse_runtime_info(r#"{"pid":42,"port":5790}"#).unwrap(),
            RuntimeInfo {
                pid: 42,
                port: Some(5790)
            }
        );
        assert_eq!(
            parse_runtime_info("42\n").unwrap(),
            RuntimeInfo {
                pid: 42,
                port: None
            }
        );
        assert!(parse_runtime_info(r#"{"pid":0,"port":5790}"#).is_err());
        assert!(parse_runtime_info(r#"{"pid":42,"port":80}"#).is_err());
    }
}
