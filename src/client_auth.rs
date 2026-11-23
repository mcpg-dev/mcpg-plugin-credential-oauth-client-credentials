//! Client authentication at the token endpoint: `client_secret_post`,
//! `client_secret_basic` (RFC 6749 §2.3.1) and `private_key_jwt` (a signed
//! RFC 7523 §2.2 client assertion, the method OAuth 2.1 and the MCP
//! `oauth-client-credentials` extension recommend).

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2).
pub(crate) const CLIENT_ASSERTION_TYPE_JWT: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Lifetime of a signed client assertion. It is a bearer credential that
/// is used once, right after it is signed.
pub(crate) const ASSERTION_LIFETIME_SECS: u64 = 60;

/// How the plugin authenticates to the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    /// `client_id` and `client_secret` in the form body.
    ClientSecretPost,
    /// `client_id` and `client_secret` in an HTTP Basic header.
    ClientSecretBasic,
    /// A client assertion JWT signed with the client's private key.
    PrivateKeyJwt,
}

impl ClientAuthMethod {
    /// The RFC 8414 `token_endpoint_auth_methods_supported` value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

/// The `aud` of a `private_key_jwt` client assertion. Unset, it is
/// `Issuer` when an issuer identifier is known, else `TokenEndpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionAudience {
    /// The token endpoint URL the assertion is posted to, for authorization
    /// servers that expect the RFC 7523 form.
    TokenEndpoint,
    /// The authorization server's issuer identifier, the only value the
    /// MCP `oauth-client-credentials` extension and RFC 7523bis accept.
    Issuer,
}

/// JWS algorithm of a `private_key_jwt` client assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlg {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    Rs384,
    #[serde(rename = "RS512")]
    Rs512,
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "PS384")]
    Ps384,
    #[serde(rename = "PS512")]
    Ps512,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl SigningAlg {
    /// The algorithm each key type implies, one per type: RSA, P-256, P-384
    /// and Ed25519. A key signs with at most one of them.
    const KEY_TYPE_DEFAULTS: [Self; 4] = [Self::Rs256, Self::Es256, Self::Es384, Self::EdDsa];

    const ALL: [Self; 9] = [
        Self::Rs256,
        Self::Rs384,
        Self::Rs512,
        Self::Ps256,
        Self::Ps384,
        Self::Ps512,
        Self::Es256,
        Self::Es384,
        Self::EdDsa,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.as_str() == name)
    }

    fn algorithm(self) -> Algorithm {
        match self {
            Self::Rs256 => Algorithm::RS256,
            Self::Rs384 => Algorithm::RS384,
            Self::Rs512 => Algorithm::RS512,
            Self::Ps256 => Algorithm::PS256,
            Self::Ps384 => Algorithm::PS384,
            Self::Ps512 => Algorithm::PS512,
            Self::Es256 => Algorithm::ES256,
            Self::Es384 => Algorithm::ES384,
            Self::EdDsa => Algorithm::EdDSA,
        }
    }

    fn is_rsa(self) -> bool {
        matches!(
            self,
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512
        )
    }

    /// `None`: `key` is not a key this algorithm signs with.
    fn load_key(self, key: &PrivateKey) -> Option<EncodingKey> {
        match key {
            PrivateKey::Pem(pem) => {
                let pem = pem.as_bytes();
                let loaded = if self.is_rsa() {
                    EncodingKey::from_rsa_pem(pem)
                } else if self == Self::EdDsa {
                    EncodingKey::from_ed_pem(pem)
                } else {
                    EncodingKey::from_ec_pem(pem)
                };
                loaded.ok()
            }
            PrivateKey::Jwk { der, kind, .. } => match (kind, self) {
                (JwkKind::Rsa, alg) if alg.is_rsa() => Some(EncodingKey::from_rsa_der(der)),
                (JwkKind::P256, Self::Es256) => Some(EncodingKey::from_ec_der(der)),
                (JwkKind::Ed25519, Self::EdDsa) => Some(EncodingKey::from_ed_der(der)),
                _ => None,
            },
        }
    }

    /// The private key this algorithm signs with.
    fn key_type(self) -> &'static str {
        match self {
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                "an RSA key (PKCS#8 or PKCS#1 PEM, or an RSA JWK)"
            }
            Self::Es256 => "a P-256 key (PKCS#8 PEM, or an EC JWK on P-256)",
            Self::Es384 => "a P-384 key in PKCS#8 PEM",
            Self::EdDsa => "an Ed25519 key (PKCS#8 PEM, or an OKP JWK on Ed25519)",
        }
    }
}

/// The client-authentication settings of one provider, as configured.
pub(crate) struct ClientAuthSettings<'a> {
    pub method: Option<ClientAuthMethod>,
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub key_id: Option<&'a str>,
    /// Unset: the JWK's `alg`, else the algorithm the key type implies.
    pub signing_alg: Option<SigningAlg>,
    pub assertion_audience: Option<AssertionAudience>,
    /// Whether an issuer identifier exists (a configured `issuer`, or the
    /// one `metadata_url` publishes). It makes `issuer` the default
    /// `assertion_audience`.
    pub issuer_available: bool,
}

/// Client authentication for the token endpoint, with any signing key
/// already parsed.
pub(crate) enum ClientAuth {
    Post {
        client_id: String,
        client_secret: String,
    },
    Basic {
        client_id: String,
        client_secret: String,
    },
    PrivateKeyJwt(Box<AssertionSigner>),
}

pub(crate) struct AssertionSigner {
    client_id: String,
    alg: SigningAlg,
    key: EncodingKey,
    key_id: Option<String>,
    audience: AssertionAudience,
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    jti: String,
    iat: u64,
    exp: u64,
}

/// A parsed private key: PEM text, or a private JWK converted to DER.
enum PrivateKey {
    Pem(String),
    Jwk {
        kind: JwkKind,
        der: Vec<u8>,
        kid: Option<String>,
        alg: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JwkKind {
    Rsa,
    P256,
    Ed25519,
}

/// The members of a private JWK (RFC 7517 / RFC 7518 §6) this plugin reads.
#[derive(Deserialize)]
struct JwkMembers {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    d: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    p: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    dp: Option<String>,
    #[serde(default)]
    dq: Option<String>,
    #[serde(default)]
    qi: Option<String>,
    #[serde(default)]
    oth: Option<Value>,
}

/// PKCS#8 `PrivateKeyInfo` up to the 32-byte P-256 scalar (RFC 5915 inside
/// RFC 5208, without the optional public key).
const P256_PKCS8_PREFIX: [u8; 35] = [
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
    0x01, 0x04, 0x20,
];

/// PKCS#8 `PrivateKeyInfo` up to the 32-byte Ed25519 seed (RFC 8410 §7).
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

fn present(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.trim().is_empty())
}

/// A PEM passed through an environment variable often carries literal `\n`
/// escapes in place of line breaks.
fn normalize_pem(pem: &str) -> Cow<'_, str> {
    let pem = pem.trim();
    if !pem.contains('\n') && pem.contains("\\n") {
        Cow::Owned(pem.replace("\\n", "\n"))
    } else {
        Cow::Borrowed(pem)
    }
}

/// `application/x-www-form-urlencoded` encoding, which RFC 6749 §2.3.1
/// applies to the id and the secret before they enter a Basic header.
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(body);
    out
}

/// A DER INTEGER of the unsigned big-endian `bytes`.
fn der_uint(bytes: &[u8]) -> Vec<u8> {
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let trimmed = &bytes[skip..];
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_none_or(|b| b & 0x80 != 0) {
        body.push(0);
    }
    body.extend_from_slice(trimmed);
    der_tlv(0x02, &body)
}

/// The base64url member `name` of a JWK. Reasons never quote the value.
fn jwk_member(value: Option<&str>, name: &str) -> Result<Vec<u8>, String> {
    let value = value.ok_or_else(|| format!("the JWK has no `{name}` member"))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map_err(|_| format!("the JWK member `{name}` is not base64url"))
}

/// A private JWK, converted to the DER form the signer loads.
fn parse_jwk(text: &str) -> Result<PrivateKey, String> {
    let jwk: JwkMembers = serde_json::from_str(text)
        .map_err(|_| "private_key starts with `{` but is not a JWK object".to_owned())?;
    let d = jwk_member(jwk.d.as_deref(), "d")
        .map_err(|e| format!("private_key is not a private JWK: {e}"))?;
    let (kind, der) = match (jwk.kty.as_str(), jwk.crv.as_deref()) {
        ("RSA", _) => {
            if jwk.oth.is_some() {
                return Err("private_key: multi-prime RSA JWKs (`oth`) are not supported".into());
            }
            let mut body = der_uint(&[]);
            for (value, name) in [
                (&jwk.n, "n"),
                (&jwk.e, "e"),
                (&jwk.d, "d"),
                (&jwk.p, "p"),
                (&jwk.q, "q"),
                (&jwk.dp, "dp"),
                (&jwk.dq, "dq"),
                (&jwk.qi, "qi"),
            ] {
                let bytes = jwk_member(value.as_deref(), name).map_err(|e| {
                    format!("private_key: an RSA JWK needs n, e, d, p, q, dp, dq and qi: {e}")
                })?;
                body.extend(der_uint(&bytes));
            }
            (JwkKind::Rsa, der_tlv(0x30, &body))
        }
        ("EC", Some("P-256")) => {
            if d.len() != 32 {
                return Err("private_key: the P-256 JWK `d` must be 32 bytes".into());
            }
            (JwkKind::P256, [P256_PKCS8_PREFIX.as_slice(), &d].concat())
        }
        ("OKP", Some("Ed25519")) => {
            if d.len() != 32 {
                return Err("private_key: the Ed25519 JWK `d` must be 32 bytes".into());
            }
            (
                JwkKind::Ed25519,
                [ED25519_PKCS8_PREFIX.as_slice(), &d].concat(),
            )
        }
        (kty, crv) => {
            return Err(format!(
                "private_key: JWK kty `{kty}`{} is not supported: use RSA, EC on P-256 or OKP on \
                 Ed25519",
                crv.map(|c| format!(" crv `{c}`")).unwrap_or_default()
            ));
        }
    };
    Ok(PrivateKey::Jwk {
        kind,
        der,
        kid: jwk.kid.filter(|k| !k.is_empty()),
        alg: jwk.alg.filter(|a| !a.is_empty()),
    })
}

fn parse_private_key(text: &str) -> Result<PrivateKey, String> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        parse_jwk(trimmed)
    } else {
        Ok(PrivateKey::Pem(normalize_pem(trimmed).into_owned()))
    }
}

impl ClientAuth {
    /// Validate `settings` and parse the signing key. Reasons name settings,
    /// never their values.
    pub(crate) fn compile(settings: &ClientAuthSettings<'_>) -> Result<Self, String> {
        let client_id = settings.client_id;
        let client_secret = present(settings.client_secret);
        let private_key = present(settings.private_key);
        let method = settings.method.unwrap_or(if private_key.is_some() {
            ClientAuthMethod::PrivateKeyJwt
        } else {
            ClientAuthMethod::ClientSecretPost
        });
        let key_settings = settings.private_key.is_some()
            || settings.key_id.is_some()
            || settings.signing_alg.is_some()
            || settings.assertion_audience.is_some();
        if method != ClientAuthMethod::PrivateKeyJwt && key_settings {
            return Err(
                "private_key, key_id, signing_alg and assertion_audience apply only to \
                 client_auth: private_key_jwt"
                    .to_owned(),
            );
        }
        match method {
            ClientAuthMethod::ClientSecretPost | ClientAuthMethod::ClientSecretBasic => {
                let Some(secret) = client_secret else {
                    return Err(format!(
                        "client_auth: {} requires client_secret (or set private_key for \
                         private_key_jwt)",
                        method.as_str()
                    ));
                };
                let (client_id, client_secret) = (client_id.to_owned(), secret.to_owned());
                Ok(if method == ClientAuthMethod::ClientSecretPost {
                    Self::Post {
                        client_id,
                        client_secret,
                    }
                } else {
                    Self::Basic {
                        client_id,
                        client_secret,
                    }
                })
            }
            ClientAuthMethod::PrivateKeyJwt => {
                if client_secret.is_some() {
                    return Err(
                        "client_secret must not be set with client_auth: private_key_jwt".into(),
                    );
                }
                let Some(text) = private_key else {
                    return Err("client_auth: private_key_jwt requires private_key".into());
                };
                let default_audience = if settings.issuer_available {
                    AssertionAudience::Issuer
                } else {
                    AssertionAudience::TokenEndpoint
                };
                let audience = settings.assertion_audience.unwrap_or(default_audience);
                if audience == AssertionAudience::Issuer && !settings.issuer_available {
                    return Err(
                        "assertion_audience: issuer requires issuer or metadata_url".to_owned()
                    );
                }
                let key = parse_private_key(text)?;
                let (jwk_kid, jwk_alg) = match &key {
                    PrivateKey::Jwk { kid, alg, .. } => (kid.clone(), alg.clone()),
                    PrivateKey::Pem(_) => (None, None),
                };
                let key_id = present(settings.key_id).map(str::to_owned).or(jwk_kid);
                let jwk_alg = match jwk_alg {
                    Some(name) => Some(SigningAlg::from_name(&name).ok_or_else(|| {
                        format!("private_key: the JWK `alg` {name:?} is not a supported algorithm")
                    })?),
                    None => None,
                };
                // A key counts for an algorithm only once it has signed: an EC
                // key loads for ES256 and ES384 alike but signs on one curve.
                // `Err(None)`: the key does not load. A load error can quote
                // bytes of the PEM, so only a signing error is kept.
                let signer_for = |alg: SigningAlg| -> Result<AssertionSigner, Option<String>> {
                    let signer = AssertionSigner {
                        client_id: client_id.to_owned(),
                        alg,
                        key: alg.load_key(&key).ok_or(None)?,
                        key_id: key_id.clone(),
                        audience,
                    };
                    signer
                        .encode("urn:mcpg:key-check", 0)
                        .map_err(|e| Some(e.to_string()))?;
                    Ok(signer)
                };
                let signer = match settings.signing_alg.or(jwk_alg) {
                    Some(alg) => signer_for(alg).map_err(|cause| {
                        let reason = format!(
                            "private_key cannot sign {}: expected {}",
                            alg.as_str(),
                            alg.key_type()
                        );
                        match cause {
                            Some(cause) => format!("{reason} ({cause})"),
                            None => reason,
                        }
                    })?,
                    None => SigningAlg::KEY_TYPE_DEFAULTS
                        .into_iter()
                        .find_map(|alg| signer_for(alg).ok())
                        .ok_or_else(|| {
                            "private_key is not a usable private key: expected an RSA (RS256), \
                             P-256 (ES256), P-384 (ES384) or Ed25519 (EdDSA) key in PKCS#8 PEM, \
                             an RSA key in PKCS#1 PEM, or a private JWK"
                                .to_owned()
                        })?,
                };
                Ok(Self::PrivateKeyJwt(Box::new(signer)))
            }
        }
    }

    /// The method this client authenticates with.
    pub(crate) fn method(&self) -> ClientAuthMethod {
        match self {
            Self::Post { .. } => ClientAuthMethod::ClientSecretPost,
            Self::Basic { .. } => ClientAuthMethod::ClientSecretBasic,
            Self::PrivateKeyJwt(_) => ClientAuthMethod::PrivateKeyJwt,
        }
    }

    /// The assertion algorithm, for `private_key_jwt`.
    pub(crate) fn signing_alg(&self) -> Option<SigningAlg> {
        match self {
            Self::PrivateKeyJwt(signer) => Some(signer.alg),
            _ => None,
        }
    }

    /// Attach this client's credentials to a token request. `issuer` is the
    /// authorization server's issuer identifier, when one is known.
    pub(crate) fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
        form: &mut Vec<(&'static str, String)>,
        token_url: &str,
        issuer: Option<&str>,
    ) -> Result<reqwest::RequestBuilder, String> {
        match self {
            Self::Post {
                client_id,
                client_secret,
            } => {
                form.push(("client_id", client_id.clone()));
                form.push(("client_secret", client_secret.clone()));
                Ok(request)
            }
            Self::Basic {
                client_id,
                client_secret,
            } => Ok(request.basic_auth(form_encode(client_id), Some(form_encode(client_secret)))),
            Self::PrivateKeyJwt(signer) => {
                let audience = match signer.audience {
                    AssertionAudience::TokenEndpoint => token_url,
                    AssertionAudience::Issuer => issuer.ok_or_else(|| {
                        "no issuer identifier for the client assertion audience".to_owned()
                    })?,
                };
                let assertion = signer.sign(audience)?;
                form.push(("client_id", signer.client_id.clone()));
                form.push((
                    "client_assertion_type",
                    CLIENT_ASSERTION_TYPE_JWT.to_owned(),
                ));
                form.push(("client_assertion", assertion));
                Ok(request)
            }
        }
    }
}

/// Check RFC 8414 authorization server `metadata` against this client:
/// `token_endpoint_auth_methods_supported` must list `method` (absent, it
/// means `client_secret_basic` only), and for `private_key_jwt` a published
/// `token_endpoint_auth_signing_alg_values_supported` must list `alg`.
/// Returns the metadata's `issuer`.
pub(crate) fn check_metadata(
    metadata: &Value,
    method: ClientAuthMethod,
    alg: Option<SigningAlg>,
) -> Result<String, String> {
    let issuer = metadata
        .get("issuer")
        .and_then(Value::as_str)
        .filter(|i| !i.is_empty())
        .ok_or_else(|| "the authorization server metadata has no `issuer`".to_owned())?;
    let strings = |name: &str| -> Option<Vec<&str>> {
        metadata
            .get(name)
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
    };
    let methods = strings("token_endpoint_auth_methods_supported")
        .unwrap_or_else(|| vec![ClientAuthMethod::ClientSecretBasic.as_str()]);
    if !methods.contains(&method.as_str()) {
        return Err(format!(
            "the authorization server does not list `{}` in token_endpoint_auth_methods_supported \
             (it lists: {}); configure client_auth to a method it supports",
            method.as_str(),
            methods.join(", ")
        ));
    }
    if let (Some(alg), Some(algs)) = (
        alg,
        strings("token_endpoint_auth_signing_alg_values_supported"),
    ) && !algs.contains(&alg.as_str())
    {
        return Err(format!(
            "the authorization server does not list `{}` in \
             token_endpoint_auth_signing_alg_values_supported (it lists: {}); set signing_alg \
             to one it supports",
            alg.as_str(),
            algs.join(", ")
        ));
    }
    Ok(issuer.to_owned())
}

impl AssertionSigner {
    /// A fresh client assertion: `iss` = `sub` = client id, a new `jti`, and
    /// an expiry [`ASSERTION_LIFETIME_SECS`] after `iat`.
    fn sign(&self, audience: &str) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_secs();
        self.encode(audience, now)
            .map_err(|e| format!("client assertion signing failed: {e}"))
    }

    /// The assertion issued at `iat`, in Unix seconds.
    fn encode(&self, audience: &str, iat: u64) -> jsonwebtoken::errors::Result<String> {
        let claims = AssertionClaims {
            iss: &self.client_id,
            sub: &self.client_id,
            aud: audience,
            jti: uuid::Uuid::new_v4().to_string(),
            iat,
            exp: iat + ASSERTION_LIFETIME_SECS,
        };
        let mut header = Header::new(self.alg.algorithm());
        header.kid = self.key_id.clone();
        jsonwebtoken::encode(&header, &claims, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation};
    use serde_json::json;

    const RSA_PRIV: &str = include_str!("testdata/rsa_priv.pem");
    const RSA_PUB: &str = include_str!("testdata/rsa_pub.pem");
    const RSA_JWK: &str = include_str!("testdata/rsa_priv.jwk.json");
    const EC_PRIV: &str = include_str!("testdata/ec_priv.pem");
    const EC_PUB: &str = include_str!("testdata/ec_pub.pem");
    const EC_JWK: &str = include_str!("testdata/ec_priv.jwk.json");
    const ED_PRIV: &str = include_str!("testdata/ed25519_priv.pem");
    const ED_PUB: &str = include_str!("testdata/ed25519_pub.pem");
    const ED_JWK: &str = include_str!("testdata/ed25519_priv.jwk.json");

    const TOKEN_URL: &str = "https://auth.example.com/oauth/token";

    fn settings<'a>(method: Option<ClientAuthMethod>) -> ClientAuthSettings<'a> {
        ClientAuthSettings {
            method,
            client_id: "agent-1",
            client_secret: None,
            private_key: None,
            key_id: None,
            signing_alg: None,
            assertion_audience: None,
            issuer_available: false,
        }
    }

    fn key_settings(key: &str) -> ClientAuthSettings<'_> {
        ClientAuthSettings {
            private_key: Some(key),
            key_id: Some("kid-1"),
            ..settings(Some(ClientAuthMethod::PrivateKeyJwt))
        }
    }

    fn jwt_settings(key: &str, alg: SigningAlg) -> ClientAuthSettings<'_> {
        ClientAuthSettings {
            signing_alg: Some(alg),
            ..key_settings(key)
        }
    }

    fn form_of(
        auth: &ClientAuth,
        issuer: Option<&str>,
    ) -> (reqwest::Request, Vec<(&'static str, String)>) {
        let mut form = Vec::new();
        let request = reqwest::Client::new().post(TOKEN_URL);
        let request = auth
            .authenticate(request, &mut form, TOKEN_URL, issuer)
            .unwrap()
            .build()
            .unwrap();
        (request, form)
    }

    fn field<'a>(form: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
        form.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    fn decode(assertion: &str, alg: Algorithm, key: &DecodingKey, aud: &str) -> Value {
        let mut validation = Validation::new(alg);
        validation.set_audience(&[aud]);
        validation.set_issuer(&["agent-1"]);
        validation.set_required_spec_claims(&["exp", "iat", "aud", "iss", "sub"]);
        jsonwebtoken::decode::<Value>(assertion, key, &validation)
            .unwrap()
            .claims
    }

    fn assert_assertion_claims(claims: &Value) {
        assert_eq!(claims["iss"], "agent-1");
        assert_eq!(claims["sub"], "agent-1");
        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert_eq!(exp - iat, ASSERTION_LIFETIME_SECS);
        assert!(!claims["jti"].as_str().unwrap().is_empty());
    }

    #[test]
    fn a_secret_alone_selects_client_secret_post() {
        let auth = ClientAuth::compile(&ClientAuthSettings {
            client_secret: Some("shh"),
            ..settings(None)
        })
        .unwrap();
        assert_eq!(auth.method(), ClientAuthMethod::ClientSecretPost);
        let (request, form) = form_of(&auth, None);
        assert_eq!(field(&form, "client_id"), Some("agent-1"));
        assert_eq!(field(&form, "client_secret"), Some("shh"));
        assert!(request.headers().get("authorization").is_none());
    }

    #[test]
    fn a_private_key_alone_selects_private_key_jwt() {
        let auth = ClientAuth::compile(&ClientAuthSettings {
            private_key: Some(RSA_PRIV),
            ..settings(None)
        })
        .unwrap();
        assert_eq!(auth.method(), ClientAuthMethod::PrivateKeyJwt);
        assert_eq!(auth.signing_alg(), Some(SigningAlg::Rs256));
    }

    #[test]
    fn neither_a_secret_nor_a_key_is_refused() {
        let err = ClientAuth::compile(&settings(None)).err().unwrap();
        assert!(err.contains("requires client_secret"), "{err}");
    }

    #[test]
    fn basic_puts_form_encoded_credentials_in_the_header_only() {
        let auth = ClientAuth::compile(&ClientAuthSettings {
            client_id: "agent:1",
            client_secret: Some("s3cr+t/="),
            ..settings(Some(ClientAuthMethod::ClientSecretBasic))
        })
        .unwrap();
        let (request, form) = form_of(&auth, None);
        assert!(form.is_empty(), "no credentials in the body");
        let header = request.headers()["authorization"].to_str().unwrap();
        // base64("agent%3A1:s3cr%2Bt%2F%3D")
        assert_eq!(header, "Basic YWdlbnQlM0ExOnMzY3IlMkJ0JTJGJTNE");
    }

    #[test]
    fn private_key_jwt_rs256_targets_the_token_endpoint_by_default() {
        let auth = ClientAuth::compile(&jwt_settings(RSA_PRIV, SigningAlg::Rs256)).unwrap();
        let (request, form) = form_of(&auth, None);
        assert!(request.headers().get("authorization").is_none());
        assert_eq!(field(&form, "client_id"), Some("agent-1"));
        assert_eq!(field(&form, "client_secret"), None);
        assert_eq!(
            field(&form, "client_assertion_type"),
            Some(CLIENT_ASSERTION_TYPE_JWT)
        );
        let assertion = field(&form, "client_assertion").unwrap();
        let header = jsonwebtoken::decode_header(assertion).unwrap();
        assert_eq!(header.kid.as_deref(), Some("kid-1"));
        let claims = decode(
            assertion,
            Algorithm::RS256,
            &DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap(),
            TOKEN_URL,
        );
        assert_assertion_claims(&claims);
        assert_eq!(claims["aud"], TOKEN_URL);
    }

    #[test]
    fn private_key_jwt_es256_can_target_the_issuer() {
        let auth = ClientAuth::compile(&ClientAuthSettings {
            assertion_audience: Some(AssertionAudience::Issuer),
            issuer_available: true,
            ..jwt_settings(EC_PRIV, SigningAlg::Es256)
        })
        .unwrap();
        let (_, form) = form_of(&auth, Some("https://auth.example.com"));
        let claims = decode(
            field(&form, "client_assertion").unwrap(),
            Algorithm::ES256,
            &DecodingKey::from_ec_pem(EC_PUB.as_bytes()).unwrap(),
            "https://auth.example.com",
        );
        assert_assertion_claims(&claims);
    }

    #[test]
    fn a_known_issuer_is_the_default_audience_and_token_endpoint_stays_selectable() {
        let public = DecodingKey::from_ec_pem(EC_PUB.as_bytes()).unwrap();
        let issuer = "https://auth.example.com";
        let auth = ClientAuth::compile(&ClientAuthSettings {
            issuer_available: true,
            ..jwt_settings(EC_PRIV, SigningAlg::Es256)
        })
        .unwrap();
        let (_, form) = form_of(&auth, Some(issuer));
        let claims = decode(
            field(&form, "client_assertion").unwrap(),
            Algorithm::ES256,
            &public,
            issuer,
        );
        assert_eq!(claims["aud"], issuer);

        let auth = ClientAuth::compile(&ClientAuthSettings {
            issuer_available: true,
            assertion_audience: Some(AssertionAudience::TokenEndpoint),
            ..jwt_settings(EC_PRIV, SigningAlg::Es256)
        })
        .unwrap();
        let (_, form) = form_of(&auth, Some(issuer));
        let claims = decode(
            field(&form, "client_assertion").unwrap(),
            Algorithm::ES256,
            &public,
            TOKEN_URL,
        );
        assert_eq!(claims["aud"], TOKEN_URL);
    }

    #[test]
    fn every_assertion_has_a_fresh_jti() {
        let auth = ClientAuth::compile(&jwt_settings(ED_PRIV, SigningAlg::EdDsa)).unwrap();
        let key = DecodingKey::from_ed_pem(ED_PUB.as_bytes()).unwrap();
        let (_, first) = form_of(&auth, None);
        let (_, second) = form_of(&auth, None);
        let a = decode(
            field(&first, "client_assertion").unwrap(),
            Algorithm::EdDSA,
            &key,
            TOKEN_URL,
        );
        let b = decode(
            field(&second, "client_assertion").unwrap(),
            Algorithm::EdDSA,
            &key,
            TOKEN_URL,
        );
        assert_ne!(a["jti"], b["jti"], "jti is never reused");
    }

    #[test]
    fn a_jwk_signs_like_its_pem_and_lends_its_kid() {
        for (jwk, public, alg, kid) in [
            (
                RSA_JWK,
                DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap(),
                Algorithm::RS256,
                "rsa-jwk-1",
            ),
            (
                EC_JWK,
                DecodingKey::from_ec_pem(EC_PUB.as_bytes()).unwrap(),
                Algorithm::ES256,
                "ec-jwk-1",
            ),
            (
                ED_JWK,
                DecodingKey::from_ed_pem(ED_PUB.as_bytes()).unwrap(),
                Algorithm::EdDSA,
                "ed-jwk-1",
            ),
        ] {
            let auth = ClientAuth::compile(&ClientAuthSettings {
                private_key: Some(jwk),
                ..settings(Some(ClientAuthMethod::PrivateKeyJwt))
            })
            .unwrap_or_else(|e| panic!("{alg:?}: {e}"));
            let (_, form) = form_of(&auth, None);
            let assertion = field(&form, "client_assertion").unwrap();
            let header = jsonwebtoken::decode_header(assertion).unwrap();
            assert_eq!(header.alg, alg);
            assert_eq!(header.kid.as_deref(), Some(kid));
            assert_assertion_claims(&decode(assertion, alg, &public, TOKEN_URL));
        }
    }

    #[test]
    fn the_jwk_alg_and_an_explicit_signing_alg_pick_the_algorithm() {
        let mut jwk: Value = serde_json::from_str(RSA_JWK).unwrap();
        jwk["alg"] = json!("PS256");
        let text = jwk.to_string();
        let auth = ClientAuth::compile(&key_settings(&text)).unwrap();
        assert_eq!(auth.signing_alg(), Some(SigningAlg::Ps256));
        let auth = ClientAuth::compile(&jwt_settings(&text, SigningAlg::Rs512)).unwrap();
        assert_eq!(auth.signing_alg(), Some(SigningAlg::Rs512));
        let public = DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap();
        let (_, form) = form_of(&auth, None);
        decode(
            field(&form, "client_assertion").unwrap(),
            Algorithm::RS512,
            &public,
            TOKEN_URL,
        );
    }

    #[test]
    fn the_rsa_jwk_becomes_the_pkcs1_key_of_its_pem() {
        // The PKCS#8 PEM wraps the PKCS#1 RSAPrivateKey the JWK converts to.
        let PrivateKey::Jwk { der, .. } = parse_private_key(RSA_JWK).unwrap() else {
            panic!("a JWK");
        };
        let body: String = RSA_PRIV
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let pkcs8 = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();
        assert!(
            pkcs8.windows(der.len()).any(|w| w == der.as_slice()),
            "the converted DER is the key inside the PEM"
        );
    }

    #[test]
    fn escaped_newlines_from_an_env_var_are_accepted() {
        let escaped = RSA_PRIV.trim().replace('\n', "\\n");
        assert!(ClientAuth::compile(&jwt_settings(&escaped, SigningAlg::Rs256)).is_ok());
    }

    #[test]
    fn private_key_jwt_rejects_bad_combinations() {
        let public_jwk = r#"{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}"#;
        let cases: Vec<(ClientAuthSettings<'_>, &str)> = vec![
            (
                ClientAuthSettings {
                    private_key: None,
                    ..jwt_settings(RSA_PRIV, SigningAlg::Rs256)
                },
                "requires private_key",
            ),
            (
                ClientAuthSettings {
                    client_secret: Some("shh"),
                    ..jwt_settings(RSA_PRIV, SigningAlg::Rs256)
                },
                "client_secret must not be set",
            ),
            (
                ClientAuthSettings {
                    assertion_audience: Some(AssertionAudience::Issuer),
                    ..jwt_settings(RSA_PRIV, SigningAlg::Rs256)
                },
                "requires issuer or metadata_url",
            ),
            (key_settings("not a pem"), "is not a usable private key"),
            (
                jwt_settings(EC_PRIV, SigningAlg::Rs256),
                "cannot sign RS256: expected an RSA key",
            ),
            (
                jwt_settings(RSA_PRIV, SigningAlg::Es256),
                "cannot sign ES256: expected a P-256 key",
            ),
            (
                jwt_settings(EC_JWK, SigningAlg::EdDsa),
                "cannot sign EdDSA: expected an Ed25519 key",
            ),
            (key_settings(public_jwk), "is not a private JWK"),
            (key_settings("{ nope"), "is not a JWK object"),
            (
                key_settings(r#"{"kty":"EC","crv":"P-521","d":"AA"}"#),
                "is not supported",
            ),
            (
                key_settings(r#"{"kty":"RSA","d":"AA","n":"AA"}"#),
                "an RSA JWK needs n, e, d, p, q, dp, dq and qi",
            ),
        ];
        for (settings, expected) in cases {
            let err = ClientAuth::compile(&settings).err().unwrap();
            assert!(err.contains(expected), "{expected:?} not in {err:?}");
            assert!(!err.contains("BEGIN"), "key material leaked: {err}");
        }
    }

    #[test]
    fn key_settings_without_private_key_jwt_are_rejected() {
        let err = ClientAuth::compile(&ClientAuthSettings {
            client_secret: Some("shh"),
            key_id: Some("kid"),
            ..settings(Some(ClientAuthMethod::ClientSecretBasic))
        })
        .err()
        .unwrap();
        assert!(err.contains("client_auth: private_key_jwt"), "{err}");
    }

    #[test]
    fn metadata_must_list_the_method_and_the_algorithm() {
        let metadata = json!({
            "issuer": "https://auth.example.com",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        });
        assert_eq!(
            check_metadata(
                &metadata,
                ClientAuthMethod::PrivateKeyJwt,
                Some(SigningAlg::Es256)
            )
            .unwrap(),
            "https://auth.example.com"
        );
        let err = check_metadata(
            &metadata,
            ClientAuthMethod::PrivateKeyJwt,
            Some(SigningAlg::Rs256),
        )
        .unwrap_err();
        assert!(err.contains("`RS256`"), "{err}");
        let err = check_metadata(&metadata, ClientAuthMethod::ClientSecretPost, None).unwrap_err();
        assert!(err.contains("`client_secret_post`"), "{err}");

        // Absent, the list means `client_secret_basic` (RFC 8414 §2).
        let bare = json!({ "issuer": "https://auth.example.com" });
        let err = check_metadata(&bare, ClientAuthMethod::PrivateKeyJwt, None).unwrap_err();
        assert!(
            err.contains("does not list `private_key_jwt`") && err.contains("client_secret_basic"),
            "{err}"
        );
        assert!(check_metadata(&bare, ClientAuthMethod::ClientSecretBasic, None).is_ok());
        assert!(check_metadata(&json!({}), ClientAuthMethod::ClientSecretBasic, None).is_err());
    }
}
