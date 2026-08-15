//! `dev.mcpg.credential.oauth-client-credentials` — outbound
//! OAuth 2.0 credential_issuer plugin (RFC 6749 §4.4).
//!
//! Operators declare named providers; bindings reference issued
//! tokens via the standard `cred://<plugin_id>/<provider>` URI
//! scheme. The plugin POSTs the `client_credentials` grant to each
//! provider's `token_url`, caches the result in-process keyed by
//! provider name, and refreshes proactively before expiry. A
//! per-provider mutex serializes refreshes so concurrent callers
//! don't all hit the token endpoint at once.
//!
//! ## Caching layers
//!
//! Two caches sit in front of the OAuth provider:
//!
//! 1. **In-plugin token cache** (this crate) — keyed by provider
//!    name only, so every caller identity sees the same access
//!    token. Holds tokens until `expires_at - refresh_buffer_ms`.
//! 2. **Host credential cache** — per
//!    `(identity_hash, plugin_id, target)` — caches the
//!    `IssuedCredential` so repeat callers don't even cross the
//!    plugin boundary. The reported `ttl_seconds` matches the
//!    in-plugin cache horizon, so both layers evict in lockstep.
//!
//! ## Failure semantics
//!
//! On token endpoint failure the plugin returns the stale token if
//! within a 5-minute grace window past expiry, with a warn log + a
//! `mcpg_oauth_token_refresh_error_total` metric. Operators get
//! continuity over correctness during transient outages; an
//! unrecoverable secret rotation surfaces once the grace window
//! expires.

mod config;

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::Value;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as TokioMutex;
use tracing::warn;

pub use config::{ConfigError, OAuthConfig, ProviderConfig};

const PLUGIN_ID: &str = "dev.mcpg.credential.oauth-client-credentials";

/// Grace window past actual expiry during which a refresh failure
/// falls back to the stale token. Mirrors the legacy
/// `OAuthTokenManager` policy.
const STALE_GRACE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    token_type: String,
    expires_at: Instant,
    /// `expires_at - refresh_buffer_ms`. The host cache + the
    /// `is_valid` check both treat this as the effective expiry.
    refresh_at: Instant,
    /// Issued-at timestamp surfaced through `IssuedCredential` for
    /// audit ledger correlation.
    issued_at_rfc3339: String,
}

impl CachedToken {
    fn is_valid_now(&self) -> bool {
        Instant::now() < self.refresh_at
    }

    fn within_grace_now(&self) -> bool {
        Instant::now() < self.expires_at + STALE_GRACE
    }
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default = "default_token_type")]
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

fn default_token_type() -> String {
    "Bearer".to_owned()
}

pub struct OAuthClientCredentialsPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: OAuthConfig,
    http_client: reqwest::Client,
    tokens: DashMap<String, CachedToken>,
    refresh_guards: BTreeMap<String, TokioMutex<()>>,
    /// Tokio runtime for the SyncCredentialIssuer FFI path.
    /// Lazily built on first sync call so async-only consumers
    /// (and tests) don't pay for a runtime they never use — and
    /// so dropping the plugin from inside a tokio context doesn't
    /// trigger the "drop runtime in async context" panic.
    sync_runtime: OnceLock<Runtime>,
}

impl OAuthClientCredentialsPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = OAuthConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "oauth-client-credentials: config parse failed; refusing to register"
            );
            panic!(
                "oauth-client-credentials config parse failed: {err}. A misconfigured \
                 credential issuer is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: OAuthConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .build()
            .expect("oauth-client-credentials: failed to build HTTP client");
        let refresh_guards: BTreeMap<String, TokioMutex<()>> = cfg
            .providers
            .keys()
            .map(|name| (name.clone(), TokioMutex::new(())))
            .collect();
        tracing::info!(
            plugin_id = PLUGIN_ID,
            provider_count = cfg.providers.len(),
            "oauth-client-credentials: configured"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "OAuth 2.0 Client Credentials Issuer".into(),
                    plugin_class: PluginClass::CredentialIssuer,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                http_client,
                tokens: DashMap::new(),
                refresh_guards,
                sync_runtime: OnceLock::new(),
            }),
        }
    }
}

async fn issue_inner(
    inner: &Inner,
    provider_name: &str,
) -> Result<IssuedCredential, CredentialError> {
    let provider = inner.config.providers.get(provider_name).ok_or_else(|| {
        CredentialError::Misconfigured {
            reason: format!("unknown provider `{provider_name}`"),
        }
    })?;

    // Fast path: cache hit before refresh window.
    if let Some(cached) = inner.tokens.get(provider_name)
        && cached.is_valid_now()
    {
        metrics::counter!(
            "mcpg_oauth_token_cache_hit_total",
            "provider" => provider_name.to_owned(),
        )
        .increment(1);
        return Ok(cached_to_issued(&cached));
    }

    // Slow path: serialize refreshes per-provider so concurrent
    // callers don't all hit the token endpoint.
    let guard = inner
        .refresh_guards
        .get(provider_name)
        .expect("refresh guard exists for every configured provider");
    let _lock = guard.lock().await;

    if let Some(cached) = inner.tokens.get(provider_name)
        && cached.is_valid_now()
    {
        metrics::counter!(
            "mcpg_oauth_token_cache_hit_total",
            "provider" => provider_name.to_owned(),
        )
        .increment(1);
        return Ok(cached_to_issued(&cached));
    }

    match fetch_token(inner, provider_name, provider).await {
        Ok(fresh) => {
            metrics::counter!(
                "mcpg_oauth_token_refresh_total",
                "provider" => provider_name.to_owned(),
            )
            .increment(1);
            let issued = cached_to_issued(&fresh);
            inner.tokens.insert(provider_name.to_owned(), fresh);
            Ok(issued)
        }
        Err(refresh_err) => {
            metrics::counter!(
                "mcpg_oauth_token_refresh_error_total",
                "provider" => provider_name.to_owned(),
            )
            .increment(1);
            if let Some(cached) = inner.tokens.get(provider_name)
                && cached.within_grace_now()
            {
                warn!(
                    plugin_id = PLUGIN_ID,
                    provider = provider_name,
                    error = ?refresh_err,
                    "OAuth token refresh failed; serving stale token within grace period"
                );
                return Ok(cached_to_issued(&cached));
            }
            Err(refresh_err)
        }
    }
}

fn cached_to_issued(cached: &CachedToken) -> IssuedCredential {
    let now = Instant::now();
    // ttl_seconds is the time until the in-plugin cache treats the
    // entry as stale (i.e. `refresh_at`). Capping at 0 avoids
    // negative durations once we're inside the grace window.
    let ttl_seconds = cached.refresh_at.saturating_duration_since(now).as_secs();
    let mut parts = BTreeMap::new();
    parts.insert("access_token".to_string(), cached.access_token.clone());
    parts.insert("token_type".to_string(), cached.token_type.clone());
    let mut metadata = BTreeMap::new();
    metadata.insert("oauth.token_type".to_string(), cached.token_type.clone());
    IssuedCredential {
        value: Some(cached.access_token.clone()),
        parts,
        ttl_seconds,
        lease_id: None,
        issued_at: cached.issued_at_rfc3339.clone(),
        metadata,
    }
}

async fn fetch_token(
    inner: &Inner,
    provider_name: &str,
    provider: &ProviderConfig,
) -> Result<CachedToken, CredentialError> {
    let timeout = Duration::from_millis(provider.timeout_ms);
    let scope_joined = provider.scopes.join(" ");
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", provider.grant_type.as_str()),
        ("client_id", provider.client_id.as_str()),
        ("client_secret", provider.client_secret.as_str()),
    ];
    if !provider.scopes.is_empty() {
        form.push(("scope", scope_joined.as_str()));
    }
    let started = Instant::now();
    let response = inner
        .http_client
        .post(&provider.token_url)
        .timeout(timeout)
        .form(&form)
        .send()
        .await
        .map_err(|e| CredentialError::Backend {
            reason: format!("OAuth token endpoint unreachable for `{provider_name}`: {e}"),
        })?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    metrics::histogram!(
        "mcpg_oauth_token_endpoint_latency_ms",
        "provider" => provider_name.to_owned(),
    )
    .record(elapsed_ms as f64);

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".to_owned());
        // SECURITY: never embed the raw token-endpoint response body in the
        // error reason — it is upstream-internal detail that propagates into
        // logs / audit, and a misbehaving endpoint could echo secrets into
        // it. Surface only the standard RFC 6749 §5.2 `error` code (a fixed,
        // non-sensitive enum) when present; drop `error_description` / body.
        let oauth_error = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            });
        let reason = match oauth_error.as_deref() {
            Some(code) => {
                format!(
                    "token endpoint returned HTTP {status} for `{provider_name}` (error: {code})"
                )
            }
            None => format!("token endpoint returned HTTP {status} for `{provider_name}`"),
        };
        return Err(match status.as_u16() {
            // 4xx indicates a config problem (bad client_id/secret,
            // unsupported grant_type, missing scope) — operators
            // need to fix YAML, not retry.
            400..=499 if status.as_u16() == 429 => CredentialError::Throttled { reason },
            400..=499 => CredentialError::Misconfigured { reason },
            // 5xx is upstream-side; let the gateway return 503 so
            // callers see a transient outage shape.
            _ => CredentialError::Backend { reason },
        });
    }

    let token_resp: TokenResponse =
        response
            .json()
            .await
            .map_err(|e| CredentialError::Backend {
                reason: format!(
                    "failed to parse token endpoint response for `{provider_name}`: {e}"
                ),
            })?;

    let expires_in = token_resp.expires_in.unwrap_or(3600);
    let now = Instant::now();
    let expires_at = now + Duration::from_secs(expires_in);
    let refresh_at = expires_at - Duration::from_millis(provider.refresh_buffer_ms);
    Ok(CachedToken {
        access_token: token_resp.access_token,
        token_type: token_resp.token_type,
        expires_at,
        refresh_at,
        issued_at_rfc3339: now_rfc3339(),
    })
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[async_trait]
impl CredentialIssuer for OAuthClientCredentialsPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn issue(
        &self,
        _identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_inner(&self.inner, target).await
    }

    // OAuth client_credentials tokens have no per-token lease; the
    // OAuth provider's expires_in is the only revocation primitive.
    // No-op revoke.
}

impl SyncCredentialIssuer for OAuthClientCredentialsPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn issue(
        &self,
        _identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        let runtime = self.inner.sync_runtime.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("oauth-client-credentials: failed to build tokio runtime")
        });
        let inner = Arc::clone(&self.inner);
        let target = target.to_owned();
        runtime.block_on(async move { issue_inner(&inner, &target).await })
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        credential_issuer as entity {
            inner_name: "",
            plugin_type: OAuthClientCredentialsPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> OAuthClientCredentialsPlugin {
                OAuthClientCredentialsPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn anon_identity() -> PluginIdentity {
        PluginIdentity {
            kind: "anonymous".into(),
            trust_level: "unauthenticated".into(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: BTreeMap::new(),
        }
    }

    fn build_with_token_url(url: &str) -> OAuthClientCredentialsPlugin {
        let cfg = json!({
            "providers": {
                "test": {
                    "token_url": url,
                    "client_id": "cid",
                    "client_secret": "csecret",
                    "scopes": ["read", "write"]
                }
            }
        });
        OAuthClientCredentialsPlugin::from_config_json(&cfg.to_string())
    }

    #[test]
    fn from_config_json_succeeds() {
        let plugin = build_with_token_url("https://example.com/token");
        assert_eq!(plugin.inner.manifest.id, PLUGIN_ID);
        assert_eq!(plugin.inner.config.providers.len(), 1);
    }

    #[test]
    #[should_panic(expected = "oauth-client-credentials config parse failed")]
    fn malformed_config_panics_at_construction() {
        OAuthClientCredentialsPlugin::from_config_json("{ not json");
    }

    #[test]
    #[should_panic(expected = "oauth-client-credentials config parse failed")]
    fn empty_providers_panics_at_construction() {
        OAuthClientCredentialsPlugin::from_config_json(&json!({ "providers": {} }).to_string());
    }

    #[tokio::test]
    async fn first_issue_hits_token_endpoint_and_caches() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=cid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-abc",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let cred = CredentialIssuer::issue(&plugin, &anon_identity(), "test", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("tok-abc"));
        assert_eq!(
            cred.parts.get("token_type").map(String::as_str),
            Some("Bearer")
        );
        // ttl_seconds = 3600 - refresh_buffer_ms/1000 = 3600 - 60 = 3540
        assert!((3530..=3540).contains(&cred.ttl_seconds));
    }

    #[tokio::test]
    async fn second_issue_returns_cached_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-once",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let id = anon_identity();
        let _ = CredentialIssuer::issue(&plugin, &id, "test", &json!({}))
            .await
            .unwrap();
        let cred = CredentialIssuer::issue(&plugin, &id, "test", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("tok-once"));
    }

    #[tokio::test]
    async fn unknown_provider_returns_misconfigured() {
        let plugin = build_with_token_url("https://example.com/token");
        let err = CredentialIssuer::issue(&plugin, &anon_identity(), "missing", &json!({}))
            .await
            .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("missing"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn token_endpoint_error_surfaces_as_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": "invalid_client",
                "error_description": "client_secret LEAKED_SECRET_xyz789 invalid"
            })))
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let err = CredentialIssuer::issue(&plugin, &anon_identity(), "test", &json!({}))
            .await
            .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("401"), "status preserved: {reason}");
                // Standard RFC 6749 error code is surfaced (actionable).
                assert!(
                    reason.contains("invalid_client"),
                    "OAuth error code should be surfaced: {reason}"
                );
                // SECURITY: the raw token-endpoint response body must NOT leak
                // into the reason (it could echo the client_secret etc.).
                assert!(
                    !reason.contains("LEAKED_SECRET_xyz789"),
                    "token endpoint error body leaked into the reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn issued_at_is_rfc3339() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let cred = CredentialIssuer::issue(&plugin, &anon_identity(), "test", &json!({}))
            .await
            .unwrap();
        assert!(cred.issued_at.contains('T'));
        assert!(cred.issued_at.len() >= 20);
    }

    #[tokio::test]
    async fn scopes_are_sent_space_joined() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("scope=read+write"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let _ = CredentialIssuer::issue(&plugin, &anon_identity(), "test", &json!({}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn missing_expires_in_defaults_to_one_hour() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok",
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let cred = CredentialIssuer::issue(&plugin, &anon_identity(), "test", &json!({}))
            .await
            .unwrap();
        // 3600 - 60 = 3540 with default refresh_buffer_ms=60_000
        assert!((3530..=3540).contains(&cred.ttl_seconds));
    }
}
