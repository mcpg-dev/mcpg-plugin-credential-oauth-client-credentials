# OAuth 2.0 Client Credentials Issuer — `dev.mcpg.credential.oauth-client-credentials`

> class `credential_issuer` · `native` · package `mcpg-plugin-credential-oauth-client-credentials` · artifact `libmcpg_plugin_credential_oauth_client_credentials.so` · Apache-2.0

Mints outbound OAuth 2.0 access tokens with the `client_credentials` grant
(RFC 6749 §4.4) so gateway backends can call APIs that expect a machine-to-machine
bearer token. You declare named providers — token endpoint, client id, a
client secret or a signing key, scopes — and the plugin fetches, caches, and proactively refreshes a
token per provider; backends reference the result through a
`cred://dev.mcpg.credential.oauth-client-credentials/<provider>` URI instead of
holding a long-lived secret. Reach for it when a downstream API issues short-lived
service tokens from its own token endpoint and you want the gateway, not each
backend binding, to own the refresh loop.

## What it does
- POSTs a `client_credentials` grant to each provider's `token_url` and caches
  the access token in-process, keyed by provider name and `resource`.
- Sends the RFC 8707 `resource` that MCP authorization requires on every token
  request: the provider's `resource`, else the `resource` of the per-call
  config. An MCP federation in `oauth_client_credentials` mode sends the
  canonical URI of its upstream (`upstream.url` without user information,
  query or fragment) unless its `credential_config` names a `resource`.
  Without either, no `resource` is sent.
- Authenticates to the token endpoint with `client_secret_post` (the
  default), `client_secret_basic`, or `private_key_jwt`: an RFC 7523 §2.2
  client assertion, the method OAuth 2.1 and the MCP
  `oauth-client-credentials` extension recommend. Each token request carries
  a fresh assertion (`iss` = `sub` = `client_id`, `aud`, a unique `jti`,
  `iat`, and `exp` 60 s later) as `client_assertion` with
  `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
  and no client secret. The `aud` is the authorization server's issuer
  identifier, the form the extension requires, whenever `issuer` or
  `metadata_url` is set; `assertion_audience: token_endpoint` selects the
  token endpoint URL for servers that expect it.
- With `metadata_url` set, fetches the RFC 8414 authorization server metadata
  once before the first token request and refuses to request a token unless
  `token_endpoint_auth_methods_supported` lists the configured method (an
  absent list means `client_secret_basic` only) and, for `private_key_jwt`, a
  published `token_endpoint_auth_signing_alg_values_supported` lists the
  algorithm.
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
          resource: https://billing.example.com/mcp   # optional (RFC 8707)
          refresh_buffer_ms: 60000
          timeout_ms: 5000
        partner-mcp:                     # private_key_jwt: no client secret
          token_url: https://auth.partner.example/oauth/token
          client_id: mcpg-agent
          client_auth: private_key_jwt
          private_key: ${secret.PARTNER_CLIENT_KEY}   # PEM or private JWK
          key_id: mcpg-2026-11
          signing_alg: ES256
          issuer: https://auth.partner.example   # the assertion `aud` (the spec form)
          metadata_url: https://auth.partner.example/.well-known/oauth-authorization-server
```

`${secret.NAME}` reads a secret file verbatim, so a multi-line PEM or a JWK
document works as is; a PEM passed through `${env.X}` may use literal `\n`
escapes in place of line breaks.

| Field | Type | Default | Description |
|---|---|---|---|
| `providers` | map<string, provider> | — (required) | Provider name to provider config; must be non-empty. |

Each entry under `providers`:

| Field | Type | Default | Description |
|---|---|---|---|
| `token_url` | string | — (required) | Token endpoint; must start with `http://` or `https://`. |
| `client_id` | string | — (required) | OAuth client id. |
| `client_secret` | string | — | OAuth client secret, required for `client_secret_post` and `client_secret_basic` and refused with `private_key_jwt`; source it with `${secret.NAME}` or `${env.VAR}` so no literal lands in the config artifact. |
| `client_auth` | enum | `private_key_jwt` when `private_key` is set, else `client_secret_post` | `client_secret_post` (id and secret in the form body), `client_secret_basic` (in an HTTP Basic header) or `private_key_jwt` (a signed client assertion). |
| `private_key` | string | — | `private_key_jwt` signing key: a PEM private key (PKCS#8, or PKCS#1 for RSA) or a private JWK (`kty` `RSA` with all CRT members, `EC` on `P-256`, or `OKP` on `Ed25519`). Parsed and trial-signed at load; errors never quote it. Source it with `${secret.NAME}` or `${env.VAR}`. |
| `key_id` | string | the JWK's `kid` | `kid` header of the client assertion. Unset and without a JWK `kid`, the assertion carries none. |
| `signing_alg` | enum | the JWK's `alg`, else the key type's | `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384` or `EdDSA`. The key-type default is RS256 for RSA, ES256 for P-256, ES384 for P-384, EdDSA for Ed25519. A value the key cannot sign with fails validation. |
| `assertion_audience` | enum | `issuer` when `issuer` or `metadata_url` is set, else `token_endpoint` | The assertion's `aud`. `issuer` is the authorization server's issuer identifier (the metadata's `issuer` when `metadata_url` is set, else `issuer`): the form the MCP `oauth-client-credentials` extension (2026-07-28) requires, as the only value, following RFC 7523bis. `token_endpoint` (the `token_url`) is for authorization servers that expect the older RFC 7523 form; set it explicitly for them. |
| `issuer` | string | — | The authorization server's issuer identifier. With `metadata_url`, the metadata's `issuer` must equal it. |
| `metadata_url` | string | — | RFC 8414 authorization server metadata URL, checked once before the first token request (see above). Its `issuer` is the assertion `aud` under `assertion_audience: issuer`. |
| `scopes` | string[] | `[]` | Scopes requested, sent space-joined per RFC 6749 §3.3. Omitted from the request when empty. |
| `resource` | string | — | RFC 8707 resource indicator sent on every token request; an absolute `http://` or `https://` URI without a fragment. Takes precedence over the per-call `resource`. |
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

The gateway's credential cache keys each issued token by the per-call config
as well as by caller, plugin and provider, so two federations that share a
provider but send different `resource` values never receive each other's
token from the host cache either.

A failed metadata check is a misconfiguration error that names the method or
algorithm the authorization server does not list; no token request is sent.

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
