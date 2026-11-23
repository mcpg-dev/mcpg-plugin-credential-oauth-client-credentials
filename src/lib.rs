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
//! Each token request carries the RFC 8707 `resource` the MCP
//! authorization spec requires: the provider's configured `resource`,
//! else the `resource` of the per-call config (a federation passes the
//! canonical URI of its upstream).
//!
//! ## Client authentication
//!
//! A provider authenticates with `client_secret_post` (the default),
//! `client_secret_basic`, or `private_key_jwt`: a fresh RFC 7523 §2.2
//! client assertion per token request, signed with the configured PEM or
//! JWK private key, with no client secret. With `metadata_url` set, the
//! plugin first checks that the authorization server's RFC 8414 metadata
//! lists the method.
//!
//! ## Caching layers
//!
//! Two caches sit in front of the OAuth provider:
//!
//! 1. **In-plugin token cache** (this crate) — keyed by provider
//!    name and `resource`, so every caller identity sees the same
//!    access token for one resource. Holds tokens until `expires_at - refresh_buffer_ms`.
//! 2. **Host credential cache** — per
//!    `(identity_hash, plugin_id, target, per-call config)` — caches the
//!    `IssuedCredential` so repeat callers don't even cross the
//!    plugin boundary. The per-call config carries the `resource`, so
//!    the host keeps one entry per resource too. The reported
//!    `ttl_seconds` matches the in-plugin cache horizon, so both layers
//!    evict in lockstep.
//!
//! ## Failure semantics
//!
//! On token endpoint failure the plugin returns the stale token if
//! within a 5-minute grace window past expiry, with a warn log + a
//! `mcpg_oauth_token_refresh_error_total` metric. Operators get
//! continuity over correctness during transient outages; an
//! unrecoverable secret rotation surfaces once the grace window
//! expires.

mod client_auth;
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

use client_auth::ClientAuth;
pub use client_auth::{AssertionAudience, ClientAuthMethod, SigningAlg};
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

/// A cached token: the provider name and the `resource` it was requested
/// for, since a token is audience-restricted to that resource.
type TokenKey = (String, Option<String>);

pub struct OAuthClientCredentialsPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: OAuthConfig,
    http_client: reqwest::Client,
    tokens: DashMap<TokenKey, CachedToken>,
    /// Client authentication per provider, keys parsed at load.
    client_auth: BTreeMap<String, ClientAuth>,
    /// Issuer identifier of each provider whose `metadata_url` passed
    /// [`client_auth::check_metadata`]; fetched once, before the first
    /// token request.
    verified_issuers: DashMap<String, String>,
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
        let client_auth: BTreeMap<String, ClientAuth> = cfg
            .providers
            .iter()
            .map(|(name, provider)| {
                let auth = provider
                    .client_auth()
                    .expect("client authentication validated by OAuthConfig::parse");
                (name.clone(), auth)
            })
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
                client_auth,
                verified_issuers: DashMap::new(),
                refresh_guards,
                sync_runtime: OnceLock::new(),
            }),
        }
    }
}

/// The `resource` a token request of `provider` carries: the configured
/// one, else a non-empty `resource` string of the per-call `call_config`.
fn requested_resource(
    provider_name: &str,
    provider: &ProviderConfig,
    call_config: &Value,
) -> Result<Option<String>, CredentialError> {
    if let Some(ref resource) = provider.resource {
        return Ok(Some(resource.clone()));
    }
    match call_config.get("resource") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(resource)) if resource.is_empty() => Ok(None),
        Some(Value::String(resource)) if config::is_resource_uri(resource) => {
            Ok(Some(resource.clone()))
        }
        Some(_) => Err(CredentialError::Misconfigured {
            reason: format!(
                "per-call resource for `{provider_name}` must be an absolute http(s) URI \
                 without a fragment"
            ),
        }),
    }
}

async fn issue_inner(
    inner: &Inner,
    provider_name: &str,
    call_config: &Value,
) -> Result<IssuedCredential, CredentialError> {
    let provider = inner.config.providers.get(provider_name).ok_or_else(|| {
        CredentialError::Misconfigured {
            reason: format!("unknown provider `{provider_name}`"),
        }
    })?;
    let resource = requested_resource(provider_name, provider, call_config)?;
    let key: TokenKey = (provider_name.to_owned(), resource);

    // Fast path: cache hit before refresh window.
    if let Some(cached) = inner.tokens.get(&key)
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

    if let Some(cached) = inner.tokens.get(&key)
        && cached.is_valid_now()
    {
        metrics::counter!(
            "mcpg_oauth_token_cache_hit_total",
            "provider" => provider_name.to_owned(),
        )
        .increment(1);
        return Ok(cached_to_issued(&cached));
    }

    match fetch_token(inner, provider_name, provider, key.1.as_deref()).await {
        Ok(fresh) => {
            metrics::counter!(
                "mcpg_oauth_token_refresh_total",
                "provider" => provider_name.to_owned(),
            )
            .increment(1);
            let issued = cached_to_issued(&fresh);
            inner.tokens.insert(key, fresh);
            Ok(issued)
        }
        Err(refresh_err) => {
            metrics::counter!(
                "mcpg_oauth_token_refresh_error_total",
                "provider" => provider_name.to_owned(),
            )
            .increment(1);
            if let Some(cached) = inner.tokens.get(&key)
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

/// The issuer identifier of `provider`'s authorization server: the one its
/// `metadata_url` publishes once the metadata passed
/// [`client_auth::check_metadata`], else the configured `issuer`.
async fn verified_issuer(
    inner: &Inner,
    provider_name: &str,
    provider: &ProviderConfig,
    auth: &ClientAuth,
) -> Result<Option<String>, CredentialError> {
    let Some(metadata_url) = provider.metadata_url.as_deref() else {
        return Ok(provider.issuer.clone());
    };
    if let Some(issuer) = inner.verified_issuers.get(provider_name) {
        return Ok(Some(issuer.clone()));
    }
    let response = inner
        .http_client
        .get(metadata_url)
        .timeout(Duration::from_millis(provider.timeout_ms))
        .send()
        .await
        .map_err(|e| CredentialError::Backend {
            reason: format!("authorization server metadata unreachable for `{provider_name}`: {e}"),
        })?;
    let status = response.status();
    if !status.is_success() {
        let reason =
            format!("authorization server metadata returned HTTP {status} for `{provider_name}`");
        return Err(if status.is_client_error() {
            CredentialError::Misconfigured { reason }
        } else {
            CredentialError::Backend { reason }
        });
    }
    let metadata: Value = response
        .json()
        .await
        .map_err(|e| CredentialError::Backend {
            reason: format!(
                "failed to parse authorization server metadata for `{provider_name}`: {e}"
            ),
        })?;
    let issuer = client_auth::check_metadata(&metadata, auth.method(), auth.signing_alg())
        .map_err(|reason| CredentialError::Misconfigured {
            reason: format!("provider `{provider_name}`: {reason}"),
        })?;
    if let Some(configured) = provider.issuer.as_deref()
        && configured != issuer
    {
        return Err(CredentialError::Misconfigured {
            reason: format!(
                "provider `{provider_name}`: the metadata issuer does not match the configured \
                 issuer {configured:?}"
            ),
        });
    }
    inner
        .verified_issuers
        .insert(provider_name.to_owned(), issuer.clone());
    Ok(Some(issuer))
}

async fn fetch_token(
    inner: &Inner,
    provider_name: &str,
    provider: &ProviderConfig,
    resource: Option<&str>,
) -> Result<CachedToken, CredentialError> {
    let timeout = Duration::from_millis(provider.timeout_ms);
    let auth = inner
        .client_auth
        .get(provider_name)
        .expect("client authentication exists for every configured provider");
    let issuer = verified_issuer(inner, provider_name, provider, auth).await?;
    let mut form: Vec<(&'static str, String)> = vec![("grant_type", provider.grant_type.clone())];
    if let Some(resource) = resource {
        form.push(("resource", resource.to_owned()));
    }
    if !provider.scopes.is_empty() {
        form.push(("scope", provider.scopes.join(" ")));
    }
    let request = inner.http_client.post(&provider.token_url).timeout(timeout);
    let request = auth
        .authenticate(request, &mut form, &provider.token_url, issuer.as_deref())
        .map_err(|reason| CredentialError::Misconfigured {
            reason: format!("client authentication for `{provider_name}`: {reason}"),
        })?;
    let started = Instant::now();
    let response = request
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
        config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_inner(&self.inner, target, config).await
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
        config: &Value,
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
        let config = config.clone();
        runtime.block_on(async move { issue_inner(&inner, &target, &config).await })
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

    fn build_with_resource(url: &str, resource: Option<&str>) -> OAuthClientCredentialsPlugin {
        let mut cfg = json!({
            "providers": {
                "test": {
                    "token_url": url,
                    "client_id": "cid",
                    "client_secret": "csecret"
                }
            }
        });
        if let Some(resource) = resource {
            cfg["providers"]["test"]["resource"] = json!(resource);
        }
        OAuthClientCredentialsPlugin::from_config_json(&cfg.to_string())
    }

    /// The `resource` field of the one token request `server` received.
    async fn sent_resource(server: &MockServer) -> Option<String> {
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 1, "one token request");
        let body = std::str::from_utf8(&requests[0].body).expect("form body");
        body.split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(name, _)| *name == "resource")
            .map(|(_, value)| form_decode(value))
    }

    fn form_decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' => {
                    let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("escape");
                    out.push(u8::from_str_radix(hex, 16).expect("hex"));
                    i += 2;
                }
                b => out.push(b),
            }
            i += 1;
        }
        String::from_utf8(out).expect("utf-8")
    }

    async fn token_server(token: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": token,
                "expires_in": 3600
            })))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn the_configured_resource_is_sent() {
        let server = token_server("tok").await;
        let plugin = build_with_resource(
            &format!("{}/token", server.uri()),
            Some("https://mcp.example.com/mcp"),
        );
        let call = json!({ "resource": "https://other.example.com/mcp" });
        CredentialIssuer::issue(&plugin, &anon_identity(), "test", &call)
            .await
            .unwrap();
        assert_eq!(
            sent_resource(&server).await.as_deref(),
            Some("https://mcp.example.com/mcp"),
            "the configured resource wins over the per-call one"
        );
    }

    #[tokio::test]
    async fn the_per_call_resource_is_sent_when_none_is_configured() {
        let server = token_server("tok").await;
        let plugin = build_with_resource(&format!("{}/token", server.uri()), None);
        let call = json!({ "resource": "https://mcp.example.com/mcp", "audience": "ignored" });
        CredentialIssuer::issue(&plugin, &anon_identity(), "test", &call)
            .await
            .unwrap();
        assert_eq!(
            sent_resource(&server).await.as_deref(),
            Some("https://mcp.example.com/mcp")
        );
    }

    #[tokio::test]
    async fn no_resource_is_sent_without_one() {
        let server = token_server("tok").await;
        let plugin = build_with_resource(&format!("{}/token", server.uri()), None);
        CredentialIssuer::issue(&plugin, &anon_identity(), "test", &Value::Null)
            .await
            .unwrap();
        assert_eq!(sent_resource(&server).await, None);
    }

    #[tokio::test]
    async fn an_invalid_per_call_resource_is_refused_before_any_request() {
        let server = token_server("tok").await;
        let plugin = build_with_resource(&format!("{}/token", server.uri()), None);
        for bad in [json!("https://mcp.example.com/mcp#x"), json!(7)] {
            let err = CredentialIssuer::issue(
                &plugin,
                &anon_identity(),
                "test",
                &json!({ "resource": bad }),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, CredentialError::Misconfigured { .. }),
                "{err:?}"
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn tokens_are_cached_per_resource() {
        let server = token_server("tok").await;
        let plugin = build_with_resource(&format!("{}/token", server.uri()), None);
        let id = anon_identity();
        for resource in ["https://a.example.com/mcp", "https://b.example.com/mcp"] {
            for _ in 0..2 {
                CredentialIssuer::issue(&plugin, &id, "test", &json!({ "resource": resource }))
                    .await
                    .unwrap();
            }
        }
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "one token request per resource"
        );
    }

    const EC_PRIV: &str = include_str!("testdata/ec_priv.pem");
    const EC_PUB: &str = include_str!("testdata/ec_pub.pem");
    const RSA_JWK: &str = include_str!("testdata/rsa_priv.jwk.json");
    const RSA_PUB: &str = include_str!("testdata/rsa_pub.pem");

    /// Mock token endpoint that accepts a request only when it carries a
    /// `private_key_jwt` client assertion whose signature verifies under
    /// `key` and whose claims are RFC 7523 §3 conformant for `audience`.
    struct AssertionCheckingEndpoint {
        key: jsonwebtoken::DecodingKey,
        alg: jsonwebtoken::Algorithm,
        audience: String,
        seen_jti: std::sync::Mutex<std::collections::BTreeSet<String>>,
    }

    impl AssertionCheckingEndpoint {
        fn verify(&self, request: &wiremock::Request) -> Result<(), String> {
            let form: BTreeMap<String, String> = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            if form.contains_key("client_secret") || request.headers.contains_key("authorization") {
                return Err("a client secret was sent".into());
            }
            if form.get("client_assertion_type").map(String::as_str)
                != Some(client_auth::CLIENT_ASSERTION_TYPE_JWT)
            {
                return Err("wrong client_assertion_type".into());
            }
            let assertion = form.get("client_assertion").ok_or("no client_assertion")?;
            let mut validation = jsonwebtoken::Validation::new(self.alg);
            validation.set_audience(&[&self.audience]);
            validation.set_issuer(&["mcpg-agent"]);
            validation.sub = Some("mcpg-agent".into());
            validation.set_required_spec_claims(&["exp", "iat", "aud", "iss", "sub"]);
            let claims = jsonwebtoken::decode::<Value>(assertion, &self.key, &validation)
                .map_err(|e| format!("assertion rejected: {e}"))?
                .claims;
            let iat = claims["iat"].as_u64().ok_or("no iat")?;
            let exp = claims["exp"].as_u64().ok_or("no exp")?;
            if exp <= iat || exp - iat > 60 {
                return Err("assertion lifetime over 60 s".into());
            }
            let jti = claims["jti"].as_str().ok_or("no jti")?.to_owned();
            if !self.seen_jti.lock().unwrap().insert(jti) {
                return Err("jti replayed".into());
            }
            if form.get("client_id").map(String::as_str) != Some("mcpg-agent") {
                return Err("client_id does not match the assertion".into());
            }
            Ok(())
        }
    }

    impl wiremock::Respond for AssertionCheckingEndpoint {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            match self.verify(request) {
                Ok(()) => ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "tok-jwt",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })),
                Err(reason) => ResponseTemplate::new(401).set_body_json(json!({
                    "error": "invalid_client",
                    "error_description": reason
                })),
            }
        }
    }

    async fn assertion_endpoint(
        key: jsonwebtoken::DecodingKey,
        alg: jsonwebtoken::Algorithm,
        audience: impl Fn(&MockServer) -> String,
    ) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(AssertionCheckingEndpoint {
                key,
                alg,
                audience: audience(&server),
                seen_jti: Default::default(),
            })
            .mount(&server)
            .await;
        server
    }

    fn jwt_provider(server: &MockServer, extra: Value) -> OAuthClientCredentialsPlugin {
        let mut provider = json!({
            "token_url": format!("{}/token", server.uri()),
            "client_id": "mcpg-agent",
            "client_auth": "private_key_jwt",
            "key_id": "k1"
        });
        for (k, v) in extra.as_object().unwrap() {
            provider[k] = v.clone();
        }
        OAuthClientCredentialsPlugin::from_config_json(
            &json!({ "providers": { "partner": provider } }).to_string(),
        )
    }

    #[tokio::test]
    async fn private_key_jwt_sends_a_signed_assertion_per_token_request() {
        let server = assertion_endpoint(
            jsonwebtoken::DecodingKey::from_ec_pem(EC_PUB.as_bytes()).unwrap(),
            jsonwebtoken::Algorithm::ES256,
            |s| format!("{}/token", s.uri()),
        )
        .await;
        let plugin = jwt_provider(
            &server,
            json!({ "private_key": EC_PRIV, "signing_alg": "ES256" }),
        );
        for resource in ["https://a.example.com/mcp", "https://b.example.com/mcp"] {
            let cred = CredentialIssuer::issue(
                &plugin,
                &anon_identity(),
                "partner",
                &json!({ "resource": resource }),
            )
            .await
            .unwrap_or_else(|e| panic!("{resource}: {e:?}"));
            assert_eq!(cred.value.as_deref(), Some("tok-jwt"));
        }
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2, "one assertion per resource");
        let header = |i: usize| {
            let form: BTreeMap<String, String> = url::form_urlencoded::parse(&requests[i].body)
                .into_owned()
                .collect();
            jsonwebtoken::decode_header(&form["client_assertion"]).unwrap()
        };
        assert_eq!(header(0).kid.as_deref(), Some("k1"));
        assert_eq!(header(1).alg, jsonwebtoken::Algorithm::ES256);
    }

    #[tokio::test]
    async fn the_mock_endpoint_refuses_an_assertion_signed_by_another_key() {
        let server = assertion_endpoint(
            jsonwebtoken::DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap(),
            jsonwebtoken::Algorithm::ES256,
            |s| format!("{}/token", s.uri()),
        )
        .await;
        let plugin = jwt_provider(&server, json!({ "private_key": EC_PRIV }));
        let err = CredentialIssuer::issue(&plugin, &anon_identity(), "partner", &json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, CredentialError::Misconfigured { reason } if reason.contains("invalid_client")),
            "{err:?}"
        );
    }

    async fn metadata(server: &MockServer, methods: Value) {
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": server.uri(),
                "token_endpoint": format!("{}/token", server.uri()),
                "token_endpoint_auth_methods_supported": methods,
                "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"]
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_jwk_key_signs_for_the_metadata_issuer_by_default() {
        let server = assertion_endpoint(
            jsonwebtoken::DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap(),
            jsonwebtoken::Algorithm::RS256,
            MockServer::uri,
        )
        .await;
        metadata(&server, json!(["client_secret_basic", "private_key_jwt"])).await;
        let plugin = jwt_provider(
            &server,
            json!({
                "private_key": RSA_JWK,
                "metadata_url": format!("{}/.well-known/oauth-authorization-server", server.uri())
            }),
        );
        for resource in ["https://a.example.com/mcp", "https://b.example.com/mcp"] {
            let cred = CredentialIssuer::issue(
                &plugin,
                &anon_identity(),
                "partner",
                &json!({ "resource": resource }),
            )
            .await
            .unwrap_or_else(|e| panic!("{resource}: {e:?}"));
            assert_eq!(cred.value.as_deref(), Some("tok-jwt"));
        }
        let requests = server.received_requests().await.unwrap();
        let gets = requests
            .iter()
            .filter(|r| r.method == wiremock::http::Method::GET)
            .count();
        assert_eq!(gets, 1, "the metadata is fetched once");
    }

    #[tokio::test]
    async fn metadata_without_private_key_jwt_refuses_before_any_token_request() {
        let server = assertion_endpoint(
            jsonwebtoken::DecodingKey::from_ec_pem(EC_PUB.as_bytes()).unwrap(),
            jsonwebtoken::Algorithm::ES256,
            |s| format!("{}/token", s.uri()),
        )
        .await;
        metadata(
            &server,
            json!(["client_secret_basic", "client_secret_post"]),
        )
        .await;
        let plugin = jwt_provider(
            &server,
            json!({
                "private_key": EC_PRIV,
                "metadata_url": format!("{}/.well-known/oauth-authorization-server", server.uri())
            }),
        );
        let err = CredentialIssuer::issue(&plugin, &anon_identity(), "partner", &json!({}))
            .await
            .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => assert!(
                reason.contains("provider `partner`")
                    && reason.contains("does not list `private_key_jwt`")
                    && reason.contains("client_secret_basic, client_secret_post"),
                "{reason}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        let posts = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .count();
        assert_eq!(posts, 0, "no token request after a failed metadata check");
    }

    #[tokio::test]
    async fn client_secret_basic_sends_the_secret_in_the_header() {
        let server = token_server("tok").await;
        let cfg = json!({
            "providers": {
                "test": {
                    "token_url": format!("{}/token", server.uri()),
                    "client_id": "cid",
                    "client_secret": "csecret",
                    "client_auth": "client_secret_basic"
                }
            }
        });
        let plugin = OAuthClientCredentialsPlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &anon_identity(), "test", &json!({}))
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let body = std::str::from_utf8(&requests[0].body).unwrap();
        assert!(!body.contains("csecret"), "no secret in the body: {body}");
        assert!(requests[0].headers.contains_key("authorization"));
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
