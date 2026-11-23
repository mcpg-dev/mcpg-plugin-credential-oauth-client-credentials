//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.oauth-client-credentials`.
//!
//! ```yaml
//! plugins:
//!   - id: dev.mcpg.credential.oauth-client-credentials
//!     config:
//!       providers:
//!         github:
//!           token_url: https://github.com/login/oauth/access_token
//!           client_id: gh-app-id
//!           client_secret: ${env.GH_CLIENT_SECRET}
//!           scopes: [repo, read:org]
//!           resource: https://mcp.example.com/mcp   # optional (RFC 8707)
//!         partner:                                  # private_key_jwt (RFC 7523)
//!           token_url: https://auth.partner.example/oauth/token
//!           client_id: mcpg-agent
//!           client_auth: private_key_jwt
//!           private_key: ${secret.PARTNER_CLIENT_KEY}   # PEM or private JWK
//!           key_id: mcpg-2026-11
//!           signing_alg: ES256
//!           issuer: https://auth.partner.example    # the assertion `aud`
//!           metadata_url: https://auth.partner.example/.well-known/oauth-authorization-server
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::client_auth::{
    AssertionAudience, ClientAuth, ClientAuthMethod, ClientAuthSettings, SigningAlg,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    /// Named OAuth client_credentials providers. The map key is
    /// the provider name; bindings reference a token via the URI
    /// `cred://dev.mcpg.credential.oauth-client-credentials/<name>`.
    pub providers: BTreeMap<String, ProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Token endpoint URL (e.g. `https://auth.example.com/oauth/token`).
    pub token_url: String,

    /// OAuth client ID.
    pub client_id: String,

    /// OAuth client secret, for the two secret methods. Source it via
    /// `${secret.NAME}` or `${env.VAR}` so the literal does not appear in
    /// YAML or process logs. Must be unset with `private_key_jwt`.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Client authentication at the token endpoint: `client_secret_post`,
    /// `client_secret_basic` or `private_key_jwt`. Unset:
    /// `private_key_jwt` when `private_key` is set, else
    /// `client_secret_post`.
    #[serde(default)]
    pub client_auth: Option<ClientAuthMethod>,

    /// `private_key_jwt`: the signing key, a PEM private key (PKCS#8, or
    /// PKCS#1 for RSA) or a private JWK (RSA, EC on P-256, OKP on
    /// Ed25519). Parsed and trial-signed at load. Source it via
    /// `${secret.NAME}` or `${env.VAR}`.
    #[serde(default)]
    pub private_key: Option<String>,

    /// `private_key_jwt`: the `kid` header of the client assertion.
    /// Unset: the JWK's `kid`, else no `kid`.
    #[serde(default)]
    pub key_id: Option<String>,

    /// `private_key_jwt`: the assertion's JWS algorithm (`RS256`, `RS384`,
    /// `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `EdDSA`).
    /// Unset: the JWK's `alg`, else the one the key type implies (RSA:
    /// RS256, P-256: ES256, P-384: ES384, Ed25519: EdDSA).
    #[serde(default)]
    pub signing_alg: Option<SigningAlg>,

    /// `private_key_jwt`: the assertion's `aud`: `issuer` (the authorization
    /// server's issuer identifier, the form the MCP `oauth-client-credentials`
    /// extension requires; the metadata's `issuer` when `metadata_url` is
    /// set, else `issuer`) or `token_endpoint` (the `token_url`, for servers
    /// that expect it). Unset: `issuer` when `issuer` or `metadata_url` is
    /// set, else `token_endpoint`.
    #[serde(default)]
    pub assertion_audience: Option<AssertionAudience>,

    /// The authorization server's issuer identifier. When `metadata_url`
    /// is also set, the metadata's `issuer` must equal it.
    #[serde(default)]
    pub issuer: Option<String>,

    /// RFC 8414 authorization server metadata URL. When set, the plugin
    /// fetches it before the first token request and refuses to request a
    /// token unless `token_endpoint_auth_methods_supported` lists the
    /// configured method (and, for `private_key_jwt`, a published
    /// `token_endpoint_auth_signing_alg_values_supported` lists the
    /// algorithm).
    #[serde(default)]
    pub metadata_url: Option<String>,

    /// OAuth scopes to request. Sent space-joined per RFC 6749 §3.3.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// RFC 8707 `resource` sent on every token request: the canonical
    /// URI of the protected resource the token is for, such as an MCP
    /// server. When set, it is always sent; when absent, the per-call
    /// `resource` the host supplies (a federation sends the canonical URI
    /// of its upstream) is sent, and without either none is.
    #[serde(default)]
    pub resource: Option<String>,

    /// OAuth grant type. Defaults to `client_credentials`. v0.1 only
    /// supports `client_credentials`; any other value is rejected at
    /// validation time.
    #[serde(default = "default_grant_type")]
    pub grant_type: String,

    /// Milliseconds before the token's actual expiry at which the
    /// plugin treats the cached entry as stale and refreshes
    /// proactively. The reported `IssuedCredential.ttl_seconds` is
    /// `expires_in - refresh_buffer_ms / 1000` so the host's
    /// credential cache evicts before the OAuth provider rejects
    /// the token. Default 60 000 (60 s).
    #[serde(default = "default_refresh_buffer_ms")]
    pub refresh_buffer_ms: u64,

    /// Per-request timeout for the token endpoint. Default 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl ProviderConfig {
    /// The provider's client authentication, with any signing key parsed.
    pub(crate) fn client_auth(&self) -> Result<ClientAuth, String> {
        let configured = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.is_empty());
        ClientAuth::compile(&ClientAuthSettings {
            method: self.client_auth,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_deref(),
            private_key: self.private_key.as_deref(),
            key_id: self.key_id.as_deref(),
            signing_alg: self.signing_alg,
            assertion_audience: self.assertion_audience,
            issuer_available: configured(&self.issuer) || configured(&self.metadata_url),
        })
    }
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

fn default_grant_type() -> String {
    "client_credentials".to_owned()
}

fn default_refresh_buffer_ms() -> u64 {
    60_000
}

fn default_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.oauth-client-credentials config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("credential.oauth-client-credentials: providers must be non-empty")]
    EmptyProviders,
    #[error("credential.oauth-client-credentials: provider `{name}` token_url is empty")]
    EmptyTokenUrl { name: String },
    #[error(
        "credential.oauth-client-credentials: provider `{name}` token_url must start with http:// or https://"
    )]
    InvalidTokenUrlScheme { name: String },
    #[error("credential.oauth-client-credentials: provider `{name}` client_id is empty")]
    EmptyClientId { name: String },
    #[error("credential.oauth-client-credentials: provider `{name}` {reason}")]
    ClientAuth { name: String, reason: String },
    #[error(
        "credential.oauth-client-credentials: provider `{name}` {field} must be an http:// or https:// URL"
    )]
    InvalidUrl { name: String, field: &'static str },
    #[error(
        "credential.oauth-client-credentials: provider `{name}` grant_type=`{grant_type}` not supported (only `client_credentials` in v0.1)"
    )]
    UnsupportedGrantType { name: String, grant_type: String },
    #[error(
        "credential.oauth-client-credentials: provider `{name}` timeout_ms={timeout}; must be 100..=60_000"
    )]
    InvalidTimeoutMs { name: String, timeout: u64 },
    #[error(
        "credential.oauth-client-credentials: provider `{name}` refresh_buffer_ms={buffer}; must be 0..=600_000"
    )]
    InvalidRefreshBufferMs { name: String, buffer: u64 },
    #[error(
        "credential.oauth-client-credentials: provider `{name}` resource must be an absolute http:// or https:// URI without a fragment"
    )]
    InvalidResource { name: String },
}

/// Whether `resource` can be an RFC 8707 resource indicator: an absolute
/// `http(s)` URI without a fragment.
pub(crate) fn is_resource_uri(resource: &str) -> bool {
    let rest = resource
        .strip_prefix("https://")
        .or_else(|| resource.strip_prefix("http://"));
    rest.is_some_and(|rest| {
        !rest.is_empty()
            && !rest.starts_with('/')
            && !resource.contains('#')
            && !resource.chars().any(char::is_whitespace)
    })
}

impl OAuthConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.providers.is_empty() {
            return Err(ConfigError::EmptyProviders);
        }
        for (name, provider) in &self.providers {
            if provider.token_url.trim().is_empty() {
                return Err(ConfigError::EmptyTokenUrl { name: name.clone() });
            }
            if !is_http_url(&provider.token_url) {
                return Err(ConfigError::InvalidTokenUrlScheme { name: name.clone() });
            }
            if provider.client_id.trim().is_empty() {
                return Err(ConfigError::EmptyClientId { name: name.clone() });
            }
            if provider
                .metadata_url
                .as_deref()
                .is_some_and(|url| !is_http_url(url))
            {
                return Err(ConfigError::InvalidUrl {
                    name: name.clone(),
                    field: "metadata_url",
                });
            }
            if provider
                .issuer
                .as_deref()
                .is_some_and(|url| !is_http_url(url))
            {
                return Err(ConfigError::InvalidUrl {
                    name: name.clone(),
                    field: "issuer",
                });
            }
            provider
                .client_auth()
                .map_err(|reason| ConfigError::ClientAuth {
                    name: name.clone(),
                    reason,
                })?;
            if provider.grant_type != "client_credentials" {
                return Err(ConfigError::UnsupportedGrantType {
                    name: name.clone(),
                    grant_type: provider.grant_type.clone(),
                });
            }
            if provider.timeout_ms < 100 || provider.timeout_ms > 60_000 {
                return Err(ConfigError::InvalidTimeoutMs {
                    name: name.clone(),
                    timeout: provider.timeout_ms,
                });
            }
            if provider.refresh_buffer_ms > 600_000 {
                return Err(ConfigError::InvalidRefreshBufferMs {
                    name: name.clone(),
                    buffer: provider.refresh_buffer_ms,
                });
            }
            if provider
                .resource
                .as_deref()
                .is_some_and(|resource| !is_resource_uri(resource))
            {
                return Err(ConfigError::InvalidResource { name: name.clone() });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> serde_json::Value {
        json!({
            "providers": {
                "github": {
                    "token_url": "https://github.com/login/oauth/access_token",
                    "client_id": "gh-app",
                    "client_secret": "secret",
                    "scopes": ["repo"]
                }
            }
        })
    }

    #[test]
    fn parses_minimal() {
        let cfg = OAuthConfig::parse(&minimal().to_string()).unwrap();
        let p = cfg.providers.get("github").unwrap();
        assert_eq!(p.grant_type, "client_credentials");
        assert_eq!(p.refresh_buffer_ms, 60_000);
        assert_eq!(p.timeout_ms, 5_000);
        assert_eq!(p.resource, None);
    }

    #[test]
    fn accepts_a_resource_uri_and_rejects_anything_else() {
        let mut v = minimal();
        v["providers"]["github"]["resource"] = json!("https://mcp.example.com/mcp");
        let cfg = OAuthConfig::parse(&v.to_string()).unwrap();
        assert_eq!(
            cfg.providers["github"].resource.as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        for bad in [
            "",
            "mcp.example.com",
            "https://",
            "https:///mcp",
            "https://mcp.example.com/mcp#frag",
            "ftp://mcp.example.com",
        ] {
            v["providers"]["github"]["resource"] = json!(bad);
            assert!(
                matches!(
                    OAuthConfig::parse(&v.to_string()).unwrap_err(),
                    ConfigError::InvalidResource { .. }
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn rejects_empty_providers() {
        let v = json!({ "providers": {} });
        assert!(matches!(
            OAuthConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyProviders
        ));
    }

    #[test]
    fn rejects_missing_token_url() {
        let mut v = minimal();
        v["providers"]["github"]["token_url"] = json!("");
        assert!(matches!(
            OAuthConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyTokenUrl { .. }
        ));
    }

    #[test]
    fn rejects_unknown_token_url_scheme() {
        let mut v = minimal();
        v["providers"]["github"]["token_url"] = json!("file:///etc/oauth");
        assert!(matches!(
            OAuthConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidTokenUrlScheme { .. }
        ));
    }

    #[test]
    fn rejects_empty_client_secret() {
        let mut v = minimal();
        v["providers"]["github"]["client_secret"] = json!("");
        match OAuthConfig::parse(&v.to_string()).unwrap_err() {
            ConfigError::ClientAuth { reason, .. } => {
                assert!(reason.contains("requires client_secret"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    const EC_PRIV: &str = include_str!("testdata/ec_priv.pem");

    fn private_key_jwt() -> serde_json::Value {
        json!({
            "providers": {
                "partner": {
                    "token_url": "https://auth.partner.example/oauth/token",
                    "client_id": "mcpg-agent",
                    "client_auth": "private_key_jwt",
                    "private_key": EC_PRIV,
                    "key_id": "k1",
                    "signing_alg": "ES256",
                    "issuer": "https://auth.partner.example",
                    "assertion_audience": "issuer",
                    "metadata_url": "https://auth.partner.example/.well-known/oauth-authorization-server"
                }
            }
        })
    }

    #[test]
    fn parses_private_key_jwt() {
        let cfg = OAuthConfig::parse(&private_key_jwt().to_string()).unwrap();
        let p = &cfg.providers["partner"];
        assert_eq!(p.client_auth, Some(ClientAuthMethod::PrivateKeyJwt));
        assert_eq!(p.signing_alg, Some(SigningAlg::Es256));
        assert_eq!(p.assertion_audience, Some(AssertionAudience::Issuer));
        assert_eq!(p.client_secret, None);
    }

    #[test]
    fn private_key_jwt_config_errors_name_the_provider_not_the_key() {
        for (field, value, expected) in [
            (
                "client_secret",
                json!("shh"),
                "client_secret must not be set",
            ),
            (
                "private_key",
                json!("not a key"),
                "private_key cannot sign ES256",
            ),
            ("signing_alg", json!("RS256"), "cannot sign RS256"),
            ("metadata_url", json!("file:///x"), "metadata_url must be"),
            ("issuer", json!("auth.partner.example"), "issuer must be"),
        ] {
            let mut v = private_key_jwt();
            v["providers"]["partner"][field] = value;
            let err = OAuthConfig::parse(&v.to_string()).unwrap_err().to_string();
            assert!(
                err.contains("provider `partner`") && err.contains(expected),
                "{field}: {err}"
            );
            assert!(!err.contains("BEGIN"), "key material leaked: {err}");
        }
        let mut v = private_key_jwt();
        let provider = v["providers"]["partner"].as_object_mut().unwrap();
        provider.remove("issuer");
        provider.remove("metadata_url");
        let err = OAuthConfig::parse(&v.to_string()).unwrap_err().to_string();
        assert!(err.contains("requires issuer or metadata_url"), "{err}");
    }

    #[test]
    fn rejects_unsupported_grant_type() {
        let mut v = minimal();
        v["providers"]["github"]["grant_type"] = json!("password");
        assert!(matches!(
            OAuthConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::UnsupportedGrantType { .. }
        ));
    }

    #[test]
    fn rejects_oversize_timeout() {
        let mut v = minimal();
        v["providers"]["github"]["timeout_ms"] = json!(120_000);
        assert!(matches!(
            OAuthConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidTimeoutMs { .. }
        ));
    }

    #[test]
    fn rejects_oversize_refresh_buffer() {
        let mut v = minimal();
        v["providers"]["github"]["refresh_buffer_ms"] = json!(700_000);
        assert!(matches!(
            OAuthConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidRefreshBufferMs { .. }
        ));
    }
}
