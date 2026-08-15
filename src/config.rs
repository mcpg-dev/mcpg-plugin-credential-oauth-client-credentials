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
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

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

    /// OAuth client secret. Operators should source this from a
    /// secret backend via `${env.VAR}` or `cred://...` so the
    /// literal does not appear in YAML or process logs.
    pub client_secret: String,

    /// OAuth scopes to request. Sent space-joined per RFC 6749 §3.3.
    #[serde(default)]
    pub scopes: Vec<String>,

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
    #[error("credential.oauth-client-credentials: provider `{name}` client_secret is empty")]
    EmptyClientSecret { name: String },
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
            if !provider.token_url.starts_with("http://")
                && !provider.token_url.starts_with("https://")
            {
                return Err(ConfigError::InvalidTokenUrlScheme { name: name.clone() });
            }
            if provider.client_id.trim().is_empty() {
                return Err(ConfigError::EmptyClientId { name: name.clone() });
            }
            if provider.client_secret.is_empty() {
                return Err(ConfigError::EmptyClientSecret { name: name.clone() });
            }
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
        assert!(matches!(
            OAuthConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyClientSecret { .. }
        ));
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
