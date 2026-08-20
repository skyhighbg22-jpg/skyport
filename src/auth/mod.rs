//! Account-subscription sign-in for the dashboard. Each provider describes a
//! real-world "log in with my subscription" flow:
//!
//! - `chatgpt` — OpenAI device-code flow (the Codex CLI's public device auth).
//!   The access token only works against the `chatgpt.com/backend-api/codex`
//!   Responses endpoint, handled upstream as the `"responses"` wire format.
//! - `grok` — xAI SuperGrok device-code flow (RFC 8628). The token works
//!   against the Grok CLI chat proxy (`cli-chat-proxy.grok.com`), also in the
//!   `"responses"` wire format with Grok-CLI identity headers.
//! - `claude` — Anthropic console PKCE flow (the Anthropic CLI's public OAuth
//!   client). The token works against the normal Messages API with the
//!   `anthropic-beta: oauth-2025-04-20` header.
//! - `openrouter` — no consumer subscription login; OpenRouter's OAuth mints
//!   keys for registered apps only, so it degrades to paste-an-API-key.
//! - `gemini` — Google removed consumer Gemini Code Assist OAuth on
//!   2026-06-18; the flow is unavailable. API keys from AI Studio still work.
//!
//! All flows are "best effort" against undocumented or lightly-documented
//! provider surfaces; failures surface as readable errors in the dashboard.

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// How the user authorizes a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthFlow {
    /// Show a verification URL + short code; poll until approved.
    Device,
    /// Open a browser URL; a local callback listener catches the redirect.
    Browser,
    /// Paste an existing credential into the dashboard.
    Paste,
    /// The provider no longer supports subscription logins.
    Unavailable,
}

/// One subscription login entry shown in the dashboard.
pub struct SubscriptionProvider {
    /// Dashboard key, e.g. "chatgpt".
    pub id: &'static str,
    /// Display name.
    pub label: &'static str,
    /// Skyport config provider id the credential is stored under.
    pub provider_id: &'static str,
    /// Base URL for the config entry created on first link.
    pub base_url: &'static str,
    /// Wire format for the config entry: "openai", "anthropic", "responses".
    pub format: &'static str,
    /// OAuth client id used against the provider.
    pub client_id: &'static str,
    /// The flow kind.
    pub flow: AuthFlow,
    /// Provider description / limits for the dashboard.
    pub copy: &'static str,
    /// Example model ids for the playground.
    pub model_hint: &'static str,
    /// Helper text for the sign-in dialog.
    pub help: &'static str,
    /// Where the user must enable/verify beforehand, if any.
    pub verify_url: Option<&'static str>,
    /// Device-flow endpoints (only for `AuthFlow::Device`).
    pub device: Option<DeviceEndpoints>,
    /// Browser-flow endpoints (only for `AuthFlow::Browser`).
    pub browser: Option<BrowserEndpoints>,
}

/// RFC 8628 device-flow endpoints.
pub struct DeviceEndpoints {
    pub device_code_url: &'static str,
    pub token_url: &'static str,
    pub scope: &'static str,
    /// The URL the user opens (displayed with the user code).
    pub verification_uri: &'static str,
    /// How device-code/token bodies are encoded.
    pub form: BodyFormat,
}

/// PKCE authorization-code endpoints (browser flow).
pub struct BrowserEndpoints {
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    /// OAuth scope string, when the provider requires one.
    pub scope: &'static str,
    /// The registered redirect URI. `{port}` is substituted with the local
    /// listener port.
    pub redirect_uri: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFormat {
    Json,
    Form,
}

// ---------------------------------------------------------------------------
// Registered providers
// ---------------------------------------------------------------------------

/// The public Grok-CLI OAuth client id (no secret). xAI only allows this
/// allowlisted client for device-code flows. Source: the Grok CLI itself.
pub const GROK_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
/// Scopes for the Grok CLI chat proxy; conversations scopes are required or
/// the minted token is rejected by `cli-chat-proxy.grok.com`.
pub const GROK_SCOPE: &str =
    "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write";

/// The public Codex/ChatGPT OAuth client id (no secret), used by the codex
/// `device_code_auth` flow and its community ports.
pub const CHATGPT_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// The Anthropic console OAuth client used by the Anthropic CLI.
pub const ANTHROPIC_CLIENT_ID: &str = "0oa2vnIbwDqBov4HqV4g";

/// Registered subscription providers. Kept as a static array so lookups
/// return `&'static` entries the request pipeline can hold across awaits.
static PROVIDERS: &[SubscriptionProvider] = &[
        SubscriptionProvider {
            id: "chatgpt",
            label: "ChatGPT (Plus / Pro)",
            provider_id: "chatgpt",
            base_url: "https://chatgpt.com/backend-api/codex",
            format: "responses",
            client_id: CHATGPT_CLIENT_ID,
            flow: AuthFlow::Device,
            copy: "Use your ChatGPT subscription through the Codex-compatible surface. Models are the gpt-5.x-codex family and count against your plan's limits.",
            model_hint: "gpt-5.4-codex-mini",
            help: "First enable device-code authentication for Codex in your ChatGPT security settings, then open the verification URL and enter the code.",
            verify_url: Some("https://chatgpt.com/codex/settings/general"),
            device: Some(DeviceEndpoints {
                device_code_url: "https://auth.openai.com/api/accounts/deviceauth/usercode",
                token_url: "https://auth.openai.com/oauth/token",
                scope: "openid profile email offline_access",
                verification_uri: "https://auth.openai.com/codex/device",
                form: BodyFormat::Json,
            }),
            browser: None,
        },
        SubscriptionProvider {
            id: "grok",
            label: "Grok (SuperGrok)",
            provider_id: "grok",
            base_url: "https://cli-chat-proxy.grok.com/v1",
            format: "responses",
            client_id: GROK_CLIENT_ID,
            flow: AuthFlow::Device,
            copy: "Use your SuperGrok / X Premium+ subscription via the Grok CLI chat proxy. Tier gating varies by account; API keys always work via the xai provider.",
            model_hint: "grok-4.6",
            help: "Open the verification URL on any device, enter the code, and approve.",
            verify_url: None,
            device: Some(DeviceEndpoints {
                device_code_url: "https://auth.x.ai/oauth2/device/code",
                token_url: "https://auth.x.ai/oauth2/token",
                scope: GROK_SCOPE,
                verification_uri: "https://auth.x.ai/device",
                form: BodyFormat::Form,
            }),
            browser: None,
        },
        SubscriptionProvider {
            id: "claude",
            label: "Claude (Pro / Max)",
            provider_id: "claude",
            base_url: "https://api.anthropic.com",
            format: "anthropic",
            client_id: ANTHROPIC_CLIENT_ID,
            flow: AuthFlow::Browser,
            copy: "Sign in with your Claude account; requests are sent to the normal Messages API with the OAuth beta header. Anthropic prohibits subscription use in third-party tools — your own gateway is your call, but the account can be restricted.",
            model_hint: "claude-sonnet-4-5",
            help: "A browser tab opens. Approve the login; this window completes automatically.",
            verify_url: None,
            device: None,
            browser: Some(BrowserEndpoints {
                authorize_url: "https://console.anthropic.com/oauth/authorize",
                token_url: "https://console.anthropic.com/oauth/token",
                scope: "claude.auth",
                redirect_uri: "http://localhost:8080/oauth/callback",
            }),
        },
        SubscriptionProvider {
            id: "openrouter",
            label: "OpenRouter",
            provider_id: "openrouter",
            base_url: "https://openrouter.ai/api/v1",
            format: "openai",
            client_id: "",
            flow: AuthFlow::Paste,
            copy: "OpenRouter has no subscription login; its OAuth only mints keys for registered apps. Paste an API key from your OpenRouter dashboard.",
            model_hint: "openai/gpt-5.1:free",
            help: "Get a key at openrouter.ai/keys and paste it below.",
            verify_url: Some("https://openrouter.ai/keys"),
            device: None,
            browser: None,
        },
        SubscriptionProvider {
            id: "gemini",
            label: "Google Gemini",
            provider_id: "gemini",
            base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
            format: "openai",
            client_id: "",
            flow: AuthFlow::Unavailable,
            copy: "Google removed consumer Gemini subscription OAuth on June 18, 2026 (Gemini Code Assist for individuals, AI Pro, AI Ultra). Non-consumer Code Assist Standard/Enterprise still work; everyone else needs an API key from AI Studio.",
            model_hint: "gemini-2.5-flash",
            help: "Use an API key from AI Studio instead — the Gemini (free tier) provider already accepts one.",
            verify_url: Some("https://aistudio.google.com/apikey"),
            device: None,
            browser: None,
        },
    ];

pub fn subscription_providers() -> &'static [SubscriptionProvider] {
    PROVIDERS
}

pub fn find_provider(id: &str) -> Option<&'static SubscriptionProvider> {
    PROVIDERS.iter().find(|provider| provider.id == id)
}

/// The alias used in the vault for a provider's subscription entry.
pub fn subscription_alias(id: &str) -> String {
    format!("subscription-{id}")
}

// ---------------------------------------------------------------------------
// Token parsing
// ---------------------------------------------------------------------------

/// Access token + refresh token pair returned by a provider.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub id_token: Option<String>,
    /// Non-secret provider metadata used for account labels and request headers.
    pub account_id: Option<String>,
    pub chatgpt_account_id: Option<String>,
    pub user_id: Option<String>,
}

impl fmt::Debug for AuthTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthTokens")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_in", &self.expires_in)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("account_id", &self.account_id)
            .field("chatgpt_account_id", &self.chatgpt_account_id)
            .field("user_id", &self.user_id)
            .finish()
    }
}

#[cfg(not(test))]
impl Drop for AuthTokens {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

/// Parse a token response; None when no access token is present.
pub fn parse_tokens(value: &serde_json::Value) -> Option<AuthTokens> {
    let access_token = value.get("access_token")?.as_str()?.to_string();
    Some(AuthTokens {
        access_token,
        refresh_token: value
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        expires_in: value.get("expires_in").and_then(|v| v.as_u64()),
        id_token: value
            .get("id_token")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        account_id: value
            .get("account_id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        chatgpt_account_id: value
            .get("chatgpt_account_id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        user_id: value
            .get("user_id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// OAuth responses are small JSON documents. Refuse oversized or malformed
/// bodies rather than buffering an unbounded provider response.
pub(crate) async fn read_oauth_json(
    mut response: reqwest::Response,
) -> Result<serde_json::Value, ()> {
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;

    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(());
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ())
}

/// Dispatch an expired access-token refresh against the right token endpoint.
/// Returns the same `AuthTokens` shape as a login.
pub async fn refresh_access_token(
    client: &reqwest::Client,
    provider: &SubscriptionProvider,
    refresh_token: &str,
) -> Result<AuthTokens, String> {
    let (token_url, form) = match provider.flow {
        AuthFlow::Device => {
            let device = provider
                .device
                .as_ref()
                .expect("device provider has endpoints");
            (device.token_url, true)
        }
        AuthFlow::Browser => {
            let browser = provider
                .browser
                .as_ref()
                .expect("browser provider has endpoints");
            (browser.token_url, true)
        }
        _ => return Err("provider has no refreshable credential".to_string()),
    };
    let mut body = vec![
        ("grant_type", "refresh_token"),
        ("client_id", provider.client_id),
        ("refresh_token", refresh_token),
    ];
    let mut request = client.post(token_url).header("accept", "application/json");
    if form {
        request = request.form(&body);
    } else {
        let json_body: serde_json::Map<String, serde_json::Value> = body
            .drain(..)
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        request = request.json(&serde_json::Value::Object(json_body));
    }
    let response = request
        .send()
        .await
        .map_err(|_| "token refresh request failed".to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("token refresh rejected (HTTP {})", status.as_u16()));
    }
    let value = read_oauth_json(response)
        .await
        .map_err(|_| "token refresh response was invalid".to_string())?;
    parse_tokens(&value).ok_or_else(|| "token response missing access_token".to_string())
}

/// Expiry timestamp for a token response, when the provider gave one.
pub fn token_expiry(tokens: &AuthTokens, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    tokens
        .expires_in
        .map(|secs| now + chrono::Duration::seconds(secs as i64))
}

/// A user-facing account label for a linked account. Prefers the id_token
/// email/sub claims, then falls back to explicit response account identifiers.
pub fn account_label(tokens: &AuthTokens) -> String {
    if let Some(id_token) = &tokens.id_token {
        if let Ok(claims) = decode_jwt_payload(id_token) {
            for key in ["email", "preferred_username", "sub"] {
                if let Some(value) = claims.get(key).and_then(|v| v.as_str()) {
                    return value.to_string();
                }
            }
            if let Some(auth) = claims.get("https://api.openai.com/auth") {
                if let Some(id) = auth.get("chatgpt_account_id").and_then(|v| v.as_str()) {
                    if let Some(short) = id.get(..8) {
                        return format!("account {short}…");
                    }
                }
            }
        }
    }
    if let Some(value) = [
        tokens.account_id.as_deref(),
        tokens.chatgpt_account_id.as_deref(),
        tokens.user_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .next()
    {
        if let Some(short) = value.get(..8) {
            return format!("account {short}…");
        }
        return value.to_string();
    }
    "subscription".to_string()
}

/// Decode a JWT payload (the middle, base64url segment) without verifying the
/// signature — we only read display claims.
pub fn decode_jwt_payload(token: &str) -> Result<serde_json::Value, String> {
    let segment = token.split('.').nth(1).ok_or("not a JWT")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| "invalid JWT encoding".to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid JWT payload".to_string())
}

// ---------------------------------------------------------------------------
// PKCE helpers (browser flows)
// ---------------------------------------------------------------------------

/// Generate a PKCE verifier + S256 challenge pair.
pub fn pkce_pair() -> (String, String) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let challenge = sha256_b64url(verifier.as_bytes());
    (verifier, challenge)
}

/// SHA-256 hashed to base64url (S256 code challenge).
pub fn sha256_b64url(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Access-token expiry stored per vault entry.
pub type Expiry = Option<DateTime<Utc>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingSession {
    pub provider: String,
    /// Unix seconds the flow was started; poll windows are measured from here.
    pub started_secs: u64,
    pub kind: PendingKind,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum PendingKind {
    Device {
        device_auth_id: String,
        user_code: String,
        interval: u64,
        expires_in_secs: u64,
    },
    Browser {
        verifier: Option<String>,
        outcome: Option<BrowserOutcome>,
    },
}

impl fmt::Debug for PendingKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device {
                interval,
                expires_in_secs,
                ..
            } => formatter
                .debug_struct("Device")
                .field("device_auth_id", &"[REDACTED]")
                .field("user_code", &"[REDACTED]")
                .field("interval", interval)
                .field("expires_in_secs", expires_in_secs)
                .finish(),
            Self::Browser { verifier, outcome } => formatter
                .debug_struct("Browser")
                .field("verifier", &verifier.as_ref().map(|_| "[REDACTED]"))
                .field("outcome", outcome)
                .finish(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum BrowserOutcome {
    Done(AuthTokens),
    Failed(String),
}

impl fmt::Debug for BrowserOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Done(_) => formatter.write_str("Done([REDACTED])"),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(claims: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{header}.{payload}.signature")
    }

    fn empty_tokens() -> AuthTokens {
        AuthTokens {
            access_token: "at".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: None,
            account_id: None,
            chatgpt_account_id: None,
            user_id: None,
        }
    }

    #[test]
    fn registry_providers_are_well_formed() {
        assert_eq!(find_provider("chatgpt").unwrap().flow, AuthFlow::Device);
        assert_eq!(find_provider("grok").unwrap().flow, AuthFlow::Device);
        assert_eq!(find_provider("claude").unwrap().flow, AuthFlow::Browser);
        assert_eq!(find_provider("openrouter").unwrap().flow, AuthFlow::Paste);
        assert_eq!(find_provider("gemini").unwrap().flow, AuthFlow::Unavailable);
        assert!(find_provider("nope").is_none());
        for provider in subscription_providers() {
            if let Some(device) = provider.device.as_ref() {
                assert!(device.device_code_url.starts_with("https://"));
                assert!(device.token_url.starts_with("https://"));
                assert!(!device.scope.is_empty());
                assert!(!device.verification_uri.is_empty());
            }
            if let Some(browser) = provider.browser.as_ref() {
                assert!(browser.authorize_url.starts_with("https://"));
                assert!(!browser.redirect_uri.is_empty());
            }
        }
    }

    #[test]
    fn pkce_pair_challenge_matches_verifier() {
        let (verifier, challenge) = pkce_pair();
        assert!((32..=96).contains(&verifier.len()));
        assert_eq!(challenge, sha256_b64url(verifier.as_bytes()));
        let (other_verifier, _) = pkce_pair();
        assert_ne!(verifier, other_verifier);
    }

    #[test]
    fn sha256_b64url_matches_known_vector() {
        // sha256("hello") = 2cf24dba…, base64url without padding.
        assert_eq!(
            sha256_b64url(b"hello"),
            "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
        );
    }

    #[test]
    fn parse_tokens_reads_all_token_fields() {
        let value = serde_json::json!({
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 3600,
            "id_token": "it",
            "account_id": "acc-12345678",
            "chatgpt_account_id": "chat-12345678",
            "user_id": "user-12345678"
        });
        let tokens = parse_tokens(&value).unwrap();
        assert_eq!(tokens.access_token, "at");
        assert_eq!(tokens.refresh_token.as_deref(), Some("rt"));
        assert_eq!(tokens.expires_in, Some(3600));
        assert_eq!(tokens.id_token.as_deref(), Some("it"));
        assert_eq!(tokens.account_id.as_deref(), Some("acc-12345678"));
        assert_eq!(tokens.chatgpt_account_id.as_deref(), Some("chat-12345678"));
        assert_eq!(tokens.user_id.as_deref(), Some("user-12345678"));
        assert!(parse_tokens(&serde_json::json!({"error": "x"})).is_none());
        assert!(parse_tokens(&serde_json::json!({})).is_none());
    }

    #[test]
    fn token_and_pending_debug_output_is_redacted() {
        let tokens = AuthTokens {
            access_token: "access-secret".into(),
            refresh_token: Some("refresh-secret".into()),
            expires_in: Some(60),
            id_token: Some("identity-secret".into()),
            account_id: None,
            chatgpt_account_id: None,
            user_id: None,
        };
        let token_debug = format!("{tokens:?}");
        for secret in ["access-secret", "refresh-secret", "identity-secret"] {
            assert!(!token_debug.contains(secret));
        }
        assert!(token_debug.contains("[REDACTED]"));

        let session = PendingSession {
            provider: "test".into(),
            started_secs: 1,
            kind: PendingKind::Browser {
                verifier: Some("verifier-secret".into()),
                outcome: Some(BrowserOutcome::Done(tokens)),
            },
        };
        let session_debug = format!("{session:?}");
        assert!(!session_debug.contains("verifier-secret"));
        assert!(!session_debug.contains("access-secret"));
    }

    #[test]
    fn token_expiry_uses_expires_in() {
        let tokens = empty_tokens();
        let mut with_expiry = tokens.clone();
        with_expiry.expires_in = Some(60);
        let now = Utc::now();
        assert_eq!(
            token_expiry(&with_expiry, now)
                .unwrap()
                .signed_duration_since(now)
                .num_seconds(),
            60
        );
        assert_eq!(token_expiry(&tokens, now), None);
    }

    #[test]
    fn decode_jwt_payload_reads_claims_without_verifying() {
        let claims = serde_json::json!({"sub": "s", "email": "e@example.com"});
        let token = make_jwt(claims.clone());
        assert_eq!(decode_jwt_payload(&token).unwrap(), claims);
        assert!(decode_jwt_payload("not-a-jwt").is_err());
        assert!(decode_jwt_payload("a.b").is_err());
    }

    #[test]
    fn account_label_prefers_id_token_email_then_account_claims() {
        let id = make_jwt(serde_json::json!({"email": "me@example.com"}));
        let mut tokens = empty_tokens();
        tokens.id_token = Some(id);
        assert_eq!(account_label(&tokens), "me@example.com");

        let id = make_jwt(serde_json::json!({
            "https://api.openai.com/auth": {"chatgpt_account_id": "abc12345rest"}
        }));
        let mut tokens = empty_tokens();
        tokens.id_token = Some(id);
        assert_eq!(account_label(&tokens), "account abc12345…");
    }

    #[test]
    fn account_label_falls_back_to_explicit_fields_then_placeholder() {
        let mut tokens = empty_tokens();
        tokens.account_id = Some("xyz98765rest".into());
        assert_eq!(account_label(&tokens), "account xyz98765…");
        assert_eq!(account_label(&empty_tokens()), "subscription");
    }

    #[tokio::test]
    async fn refresh_rejection_does_not_expose_provider_details() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"error_description":"provider-secret-text"}"#),
            )
            .mount(&server)
            .await;
        let token_url: &'static str = Box::leak(format!("{}/token", server.uri()).into_boxed_str());
        let provider = SubscriptionProvider {
            id: "test",
            label: "Test",
            provider_id: "test",
            base_url: "https://example.invalid",
            format: "openai",
            client_id: "public-client",
            flow: AuthFlow::Browser,
            copy: "",
            model_hint: "",
            help: "",
            verify_url: None,
            device: None,
            browser: Some(BrowserEndpoints {
                authorize_url: "https://example.invalid/authorize",
                token_url,
                scope: "scope",
                redirect_uri: "http://localhost/callback",
            }),
        };

        let error =
            refresh_access_token(&reqwest::Client::new(), &provider, "refresh-token-secret")
                .await
                .unwrap_err();
        assert!(error.starts_with("token refresh rejected"));
        for sensitive in ["provider-secret-text", token_url, "refresh-token-secret"] {
            assert!(!error.contains(sensitive));
        }
    }

    #[tokio::test]
    async fn oauth_json_reader_rejects_oversized_bodies() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(64 * 1024 + 1)))
            .mount(&server)
            .await;
        let response = reqwest::Client::new()
            .get(format!("{}/large", server.uri()))
            .send()
            .await
            .unwrap();

        assert!(read_oauth_json(response).await.is_err());
    }
}
