use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use subtle::ConstantTimeEq;
use url::{Host, Url};
use zeroize::Zeroizing;

const MAX_UPSTREAM_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenScope {
    Admin,
    Inference,
}

impl TokenScope {
    pub fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Inference => "inference",
        }
    }

    fn credential_account(self) -> &'static str {
        match self {
            Self::Admin => "admin_token",
            Self::Inference => "inference_token",
        }
    }
}

pub fn initialize_auth_tokens(
    config: &mut crate::config::SkyportConfig,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut changed = false;
    if config.server.admin_token_hash.is_none() {
        let token = generate_and_store_token(TokenScope::Admin)?;
        config.server.admin_token_hash = Some(hash_token(&token));
        changed = true;
    }
    if config.server.inference_token_hash.is_none() {
        let token = generate_and_store_token(TokenScope::Inference)?;
        config.server.inference_token_hash = Some(hash_token(&token));
        changed = true;
    }
    Ok(changed)
}

pub fn rotate_auth_token(
    config: &mut crate::config::SkyportConfig,
    scope: TokenScope,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let token = generate_and_store_token(scope)?;
    let hash = hash_token(&token);
    match scope {
        TokenScope::Admin => config.server.admin_token_hash = Some(hash),
        TokenScope::Inference => config.server.inference_token_hash = Some(hash),
    }
    Ok(token)
}

pub fn stored_auth_token(
    config: &crate::config::SkyportConfig,
    scope: TokenScope,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let expected = match scope {
        TokenScope::Admin => config.server.admin_token_hash.as_deref(),
        TokenScope::Inference => config.server.inference_token_hash.as_deref(),
    }
    .ok_or("Authentication is not initialized")?;
    let token = crate::credential_store::read(scope.credential_account())
        .map_err(|_| {
            format!(
                "Could not read the {} token from secure storage",
                scope.name()
            )
        })?
        .ok_or_else(|| format!("The stored {} token is missing; rotate it", scope.name()))?;
    if !verify_token(&token, expected) {
        return Err(format!(
            "The stored {} token does not match its configured verifier; rotate it",
            scope.name()
        )
        .into());
    }
    Ok(token)
}

fn generate_and_store_token(
    scope: TokenScope,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    rand::thread_rng().fill_bytes(bytes.as_mut());
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
    store_auth_token(scope, &token)?;
    Ok(token)
}

pub fn store_auth_token(scope: TokenScope, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    crate::credential_store::write(scope.credential_account(), token).map_err(|_| {
        format!(
            "Could not store the {} token in secure storage",
            scope.name()
        )
    })?;
    Ok(())
}

pub fn hash_token(token: &str) -> String {
    BASE64.encode(Sha256::digest(token.as_bytes()))
}

pub fn verify_token(token: &str, expected_hash: &str) -> bool {
    let Ok(expected) = BASE64.decode(expected_hash) else {
        return false;
    };
    let actual = Sha256::digest(token.as_bytes());
    constant_time_eq(actual.as_slice(), &expected)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    bool::from(left.ct_eq(right))
}

pub fn bearer_token(value: &str) -> Option<&str> {
    let token = value.strip_prefix("Bearer ")?;
    if token.len() < 32 || token.len() > 256 || token.trim() != token {
        return None;
    }
    Some(token)
}

pub fn authorize_path(
    path: &str,
    token: Option<&str>,
    admin_hash: Option<&str>,
    inference_hash: Option<&str>,
) -> bool {
    let admin = token
        .zip(admin_hash)
        .is_some_and(|(token, expected)| verify_token(token, expected));
    if path.starts_with("/api/") {
        return admin;
    }
    admin
        || token
            .zip(inference_hash)
            .is_some_and(|(token, expected)| verify_token(token, expected))
}

pub fn valid_host_header(value: &str, port: u16) -> bool {
    value.eq_ignore_ascii_case(&format!("localhost:{port}")) || value == format!("127.0.0.1:{port}")
}

pub fn valid_browser_origin(value: &str, port: u16) -> bool {
    let Ok(origin) = Url::parse(value) else {
        return false;
    };
    origin.scheme() == "http"
        && origin.port_or_known_default() == Some(port)
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.query().is_none()
        && origin.fragment().is_none()
        && origin
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1")
}

pub fn validate_provider_url(provider: &str, raw: &str, credentialed: bool) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "Provider URL is invalid".to_string())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Provider URL cannot contain credentials, a query, or a fragment".to_string());
    }
    if url.path_segments().is_some_and(|segments| {
        segments
            .into_iter()
            .any(|segment| segment == "." || segment == "..")
    }) {
        return Err("Provider URL cannot contain relative path segments".to_string());
    }
    let host = url
        .host()
        .ok_or_else(|| "Provider URL must include a host".to_string())?;
    let loopback = host_is_loopback(&host);
    if let Host::Domain(domain) = &host {
        let lower = domain.to_ascii_lowercase();
        if lower.ends_with(".local")
            || lower.ends_with(".internal")
            || lower.ends_with(".invalid")
            || lower.ends_with(".test")
            || lower.ends_with(".example")
            || lower.ends_with(".localhost")
        {
            if !(!credentialed && crate::vault::Vault::is_keyless_provider(provider) && loopback) {
                return Err("Provider URL cannot target a local or reserved domain".to_string());
            }
        }
    }
    #[cfg(test)]
    if matches!(provider, "mock" | "native") && url.scheme() == "http" && loopback {
        return Ok(url);
    }
    match url.scheme() {
        "https" if !loopback => {}
        "http"
            if !credentialed && crate::vault::Vault::is_keyless_provider(provider) && loopback => {}
        "http" if credentialed => {
            return Err("Credential-bearing providers must use HTTPS".to_string())
        }
        "http" => {
            return Err("HTTP is allowed only for built-in keyless loopback providers".to_string())
        }
        "https" => return Err("Remote providers cannot target loopback".to_string()),
        _ => return Err("Provider URL must use HTTPS".to_string()),
    }
    Ok(url)
}

pub async fn validate_resolved_destination(
    provider: &str,
    url: &Url,
    credentialed: bool,
) -> Result<(), String> {
    let host = url
        .host_str()
        .ok_or_else(|| "Provider URL must include a host".to_string())?;
    #[cfg(test)]
    if matches!(provider, "mock" | "native") && host.eq_ignore_ascii_case("127.0.0.1") {
        return Ok(());
    }
    if !credentialed && crate::vault::Vault::is_keyless_provider(provider) {
        return Ok(());
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "Provider URL has no usable port".to_string())?;
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "Provider host could not be resolved".to_string())?;
    let mut found = false;
    for address in addresses {
        found = true;
        if !is_public_ip(address.ip()) {
            return Err("Provider host resolves to a private or reserved address".to_string());
        }
    }
    if !found {
        return Err("Provider host did not resolve to an address".to_string());
    }
    Ok(())
}

pub fn append_url_path(base: &Url, path: &str) -> Result<Url, String> {
    let mut url = base.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| "Provider URL cannot be used as a base".to_string())?;
        segments.pop_if_empty();
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            segments.push(segment);
        }
    }
    Ok(url)
}

pub fn valid_model_path_segment(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 200
        && model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub fn safe_network_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "Upstream request timed out"
    } else if error.is_connect() {
        "Could not connect to upstream provider"
    } else {
        "Upstream request failed"
    }
}

pub async fn read_upstream_body(response: reqwest::Response) -> Result<Vec<u8>, String> {
    read_limited_body(response, MAX_UPSTREAM_BODY_BYTES).await
}

pub async fn read_limited_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err("Upstream response exceeded the size limit".to_string());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Could not read upstream response".to_string())?
    {
        if chunk.len() > max_bytes.saturating_sub(body.len()) {
            return Err("Upstream response exceeded the size limit".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn host_is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => {
            ip.is_loopback()
                || ip
                    .to_ipv4_mapped()
                    .or_else(|| ip.to_ipv4())
                    .is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(ipv4);
    }
    if let Some(ipv4) = ip.to_ipv4() {
        return is_public_ipv4(ipv4);
    }
    let segments = ip.segments();
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        let ipv4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        return is_public_ipv4(ipv4);
    }
    if segments[0] == 0x2002 {
        let ipv4 = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        );
        return is_public_ipv4(ipv4);
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x2001 && segments[1] == 0x0000)
        || (segments[0] == 0x0100 && (segments[1] & 0xfff0) == 0x0000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_verification_rejects_modified_values() {
        let hash = hash_token("a-high-entropy-token-value-that-is-long");
        assert!(verify_token(
            "a-high-entropy-token-value-that-is-long",
            &hash
        ));
        assert!(!verify_token(
            "a-high-entropy-token-value-that-is-wrong",
            &hash
        ));
    }

    #[test]
    fn provider_urls_enforce_https_and_loopback_rules() {
        assert!(validate_provider_url("openai", "https://api.openai.com/v1", true).is_ok());
        assert!(validate_provider_url("openai", "http://api.openai.com/v1", true).is_err());
        assert!(validate_provider_url("openai", "https://127.0.0.1/v1", true).is_err());
        assert!(validate_provider_url("ollama", "http://localhost:11434/v1", false).is_ok());
        assert!(validate_provider_url("custom", "http://localhost:9000/v1", false).is_err());
        assert!(validate_provider_url("openai", "https://user@example.com/v1", true).is_err());
    }

    #[test]
    fn host_and_origin_are_exactly_local() {
        assert!(valid_host_header("localhost:5790", 5790));
        assert!(valid_browser_origin("http://127.0.0.1:5790", 5790));
        assert!(!valid_host_header("attacker.test:5790", 5790));
        assert!(!valid_browser_origin("http://attacker.test:5790", 5790));
    }

    #[test]
    fn inference_tokens_cannot_cross_the_admin_boundary() {
        let admin = hash_token("admin-token-value-with-sufficient-entropy");
        let inference = hash_token("inference-token-value-with-enough-entropy");
        assert!(authorize_path(
            "/api/keys",
            Some("admin-token-value-with-sufficient-entropy"),
            Some(&admin),
            Some(&inference),
        ));
        assert!(!authorize_path(
            "/api/keys",
            Some("inference-token-value-with-enough-entropy"),
            Some(&admin),
            Some(&inference),
        ));
        assert!(authorize_path(
            "/v1/models",
            Some("inference-token-value-with-enough-entropy"),
            Some(&admin),
            Some(&inference),
        ));
        assert!(!authorize_path(
            "/v1/models",
            None,
            Some(&admin),
            Some(&inference),
        ));
    }

    #[test]
    fn ipv6_ssrf_rejects_mapped_and_reserved_ips() {
        use std::str::FromStr;
        // IPv4-mapped loopback ::ffff:127.0.0.1
        let mapped_loopback = Ipv6Addr::from_str("::ffff:127.0.0.1").unwrap();
        assert!(!is_public_ipv6(mapped_loopback));
        assert!(host_is_loopback(&Host::Ipv6(mapped_loopback)));

        // IPv4-mapped private 10.0.0.1
        let mapped_private = Ipv6Addr::from_str("::ffff:10.0.0.1").unwrap();
        assert!(!is_public_ipv6(mapped_private));

        // IPv4-mapped cloud metadata 169.254.169.254
        let mapped_meta = Ipv6Addr::from_str("::ffff:169.254.169.254").unwrap();
        assert!(!is_public_ipv6(mapped_meta));

        // Standard loopback ::1
        let loopback = Ipv6Addr::from_str("::1").unwrap();
        assert!(!is_public_ipv6(loopback));
        assert!(host_is_loopback(&Host::Ipv6(loopback)));

        // ULA fc00::1
        let ula = Ipv6Addr::from_str("fc00::1").unwrap();
        assert!(!is_public_ipv6(ula));

        // Public IPv6 2606:4700:4700::1111 (Cloudflare DNS)
        let public_v6 = Ipv6Addr::from_str("2606:4700:4700::1111").unwrap();
        assert!(is_public_ipv6(public_v6));
    }

    #[test]
    fn provider_urls_reject_reserved_tlds() {
        assert!(validate_provider_url("openai", "https://api.openai.local/v1", true).is_err());
        assert!(validate_provider_url("openai", "https://service.internal/v1", true).is_err());
        assert!(validate_provider_url("openai", "https://endpoint.test/v1", true).is_err());
    }
}
