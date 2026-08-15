# OAuth 2.0 Client Credentials Issuer — `dev.mcpg.credential.oauth-client-credentials`

> class `credential_issuer` · `native` · package `mcpg-plugin-credential-oauth-client-credentials` · artifact `libmcpg_plugin_credential_oauth_client_credentials.so` · Apache-2.0

Mints outbound OAuth 2.0 access tokens with the `client_credentials` grant
(RFC 6749 §4.4) so gateway backends can call APIs that expect a machine-to-machine
bearer token. You declare named providers — token endpoint, client id, client
secret, scopes — and the plugin fetches, caches, and proactively refreshes a
token per provider; backends reference the result through a
`cred://dev.mcpg.credential.oauth-client-credentials/<provider>` URI instead of
holding a long-lived secret. Reach for it when a downstream API issues short-lived
service tokens from its own token endpoint and you want the gateway, not each
backend binding, to own the refresh loop.

## What it does
- POSTs a `client_credentials` grant to each provider's `token_url` and caches
  the access token in-process, keyed by provider name.
- Refreshes `refresh_buffer_ms` ahead of real expiry, and reports
  `IssuedCredential.ttl_seconds` against that same horizon so the gateway's own
  credential cache evicts before the provider starts rejecting the token.
- Serializes refreshes per provider behind a mutex, so a burst of concurrent
  callers produces one token request rather than a thundering herd.
- Falls back to the cached token for up to five minutes past expiry when a
  refresh fails, trading strict freshness for continuity through a transient
  outage; past that window the error surfaces to the caller.
- Surfaces the token as `IssuedCredential.value` and, for callers that want the
  pieces, as the `access_token` and `token_type` parts.
- Keeps token-endpoint response bodies out of errors and logs: only the standard
  RFC 6749 §5.2 `error` code is echoed, never `error_description` or the raw body.
- Declares the `network_outbound` capability, consumed by every token request;
  the entry's `granted_capabilities` must list it or the plugin is refused at load.

## Configuration
Loaded from the flat top-level `plugins:` list; bindings then select a provider
per credential reference through a `cred://` URI.

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-client-credentials
    class: credential_issuer
    source: { path: ./plugins/libmcpg_plugin_credential_oauth_client_credentials.so }
    granted_capabilities: ["network_outbound"]
    config:
      providers:
        billing-api:                     # → cred://dev.mcpg.credential.oauth-client-credentials/billing-api
          token_url: https://auth.example.com/oauth/token
          client_id: mcpg-gateway
          client_secret: ${env.BILLING_CLIENT_SECRET}
          scopes: ["invoices.read", "invoices.write"]
          refresh_buffer_ms: 60000
          timeout_ms: 5000
```

| Field | Type | Default | Description |
|---|---|---|---|
| `providers` | map<string, provider> | — (required) | Provider name to provider config; must be non-empty. |

Each entry under `providers`:

| Field | Type | Default | Description |
|---|---|---|---|
| `token_url` | string | — (required) | Token endpoint; must start with `http://` or `https://`. |
| `client_id` | string | — (required) | OAuth client id. |
| `client_secret` | string | — (required) | OAuth client secret; source it with `${env.VAR}` so no literal lands in the config artifact. |
| `scopes` | string[] | `[]` | Scopes requested, sent space-joined per RFC 6749 §3.3. Omitted from the request when empty. |
| `grant_type` | string | `client_credentials` | Only `client_credentials` is accepted; any other value fails validation. |
| `refresh_buffer_ms` | u64 | `60000` | How far ahead of expiry a cached token is treated as stale. Range `0..=600000`. |
| `timeout_ms` | u64 | `5000` | Per-request timeout against the token endpoint. Range `100..=60000`. |

Unknown fields are rejected. A configuration that fails validation aborts the
plugin's registration rather than loading a half-working credential issuer.

## Security
A `cred://<plugin_id>/<provider>` string anywhere in a binding's config is
replaced with the issued token at request time; `cred://<plugin_id>/<provider>#access_token`
and `#token_type` select individual parts. Resolution hard-fails on the first
error, so a binding never runs with some references substituted and others left
as literal URIs.

Token-endpoint failures map onto distinct error kinds so operators can tell a
broken configuration from an upstream outage: HTTP 429 is throttling, other 4xx
responses are treated as misconfiguration (wrong client id, secret, or scope) and
are not worth retrying, and 5xx or transport failures surface as a transient
backend error.

## Observability
- `mcpg_oauth_token_cache_hit_total{provider}` — requests served from the
  in-plugin cache.
- `mcpg_oauth_token_refresh_total{provider}` — successful token fetches.
- `mcpg_oauth_token_refresh_error_total{provider}` — failed fetches, including
  those that fell back to a stale token.
- `mcpg_oauth_token_endpoint_latency_ms{provider}` — token-endpoint round-trip
  latency.

## Build
`cdylib-export` is enabled by default, so the plain build already produces the
loadable artifact. Disable the default features when linking this crate as an
rlib path dependency alongside other plugins, so the build does not emit two
`mcpg_plugin_register` exports.

```bash
cargo build -p mcpg-plugin-credential-oauth-client-credentials --features cdylib-export --release   # → target/release/libmcpg_plugin_credential_oauth_client_credentials.so
```

## Testing
Unit tests stand up a local HTTP mock of the token endpoint, so the whole suite
runs offline:

```bash
cargo test -p mcpg-plugin-credential-oauth-client-credentials
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
- Sibling issuers: `libs/plugins/credential/oauth-token-exchange`,
  `libs/plugins/credential/static`, `libs/plugins/credential/vault-dynamic-db`
