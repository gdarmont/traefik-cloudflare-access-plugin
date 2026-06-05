//! Cloudflare Access JWT verification: RS256 signature plus claim validation.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
// Bring the `Verifier` trait's methods into scope without colliding with our own
// `Verifier` struct below.
use rsa::signature::Verifier as _;
use serde::Deserialize;
use sha2::Sha256;

use crate::config::PluginConfig;

/// Reasons a token may fail verification.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The token is not a well-formed JWS compact serialization.
    Malformed,
    /// The token's `alg` header is not `RS256`.
    UnsupportedAlg(String),
    /// No configured key matches the token (by `kid`, or none verified).
    UnknownKey,
    /// The signature did not verify against the selected key.
    BadSignature,
    /// The `iss` claim does not match the expected issuer.
    BadIssuer,
    /// The token is expired (`exp` in the past).
    Expired,
    /// The token is not yet valid (`nbf` in the future).
    NotYetValid,
    /// The `aud` claim does not contain the configured client ID.
    BadAudience,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::Malformed => write!(f, "malformed token"),
            VerifyError::UnsupportedAlg(alg) => write!(f, "unsupported algorithm: {alg}"),
            VerifyError::UnknownKey => write!(f, "no matching signing key"),
            VerifyError::BadSignature => write!(f, "signature verification failed"),
            VerifyError::BadIssuer => write!(f, "issuer mismatch"),
            VerifyError::Expired => write!(f, "token expired"),
            VerifyError::NotYetValid => write!(f, "token not yet valid"),
            VerifyError::BadAudience => write!(f, "audience mismatch"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// A signing key ready for verification: its `kid` (empty when the JWK omits
/// one) and the pre-built RS256 verifying key.
#[derive(Debug, Clone)]
struct SigningKey {
    kid: String,
    verifying_key: VerifyingKey<Sha256>,
}

/// Verifies Cloudflare Access JWTs against a fixed issuer, audience, and key set.
#[derive(Debug, Clone)]
pub struct Verifier {
    issuer: String,
    client_id: String,
    skip_client_id_check: bool,
    skip_expiry_check: bool,
    keys: Vec<SigningKey>,
}

impl Verifier {
    /// Build a verifier from the plugin configuration.
    ///
    /// The RSA keys are parsed once here rather than on every request: each
    /// usable RSA JWK is turned into a [`VerifyingKey`] up front. Non-RSA keys
    /// and keys whose `n`/`e` material cannot be decoded are dropped (and thus
    /// excluded from [`Self::key_count`]).
    pub fn from_config(config: &PluginConfig) -> Self {
        let keys = config
            .jwks
            .keys
            .iter()
            .filter(|jwk| jwk.is_rsa())
            .filter_map(|jwk| {
                let public_key = jwk.to_public_key().ok()?;
                Some(SigningKey {
                    kid: jwk.kid.clone(),
                    verifying_key: VerifyingKey::<Sha256>::new(public_key),
                })
            })
            .collect();
        Self {
            issuer: config.issuer(),
            client_id: config.client_id.clone(),
            skip_client_id_check: config.skip_client_id_check,
            skip_expiry_check: config.skip_expiry_check,
            keys,
        }
    }

    /// The number of usable RS256 keys parsed from the configuration.
    ///
    /// A verifier with zero keys rejects every token, so this is worth logging
    /// at startup as a misconfiguration signal.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Verify a compact-serialized JWT.
    ///
    /// `now_unix` is the current time in seconds since the Unix epoch, used for
    /// `exp`/`nbf` validation. Returns `Ok(())` if the token is valid.
    pub fn verify(&self, token: &str, now_unix: u64) -> Result<(), VerifyError> {
        let mut parts = token.split('.');
        let (header_b64, payload_b64, sig_b64) =
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() => (h, p, s),
                _ => return Err(VerifyError::Malformed),
            };

        let header: Header = decode_json(header_b64).ok_or(VerifyError::Malformed)?;
        if !header.alg.eq_ignore_ascii_case("RS256") {
            return Err(VerifyError::UnsupportedAlg(header.alg));
        }

        let signature = URL_SAFE_NO_PAD
            .decode(sig_b64.as_bytes())
            .map_err(|_| VerifyError::Malformed)?;
        let signing_input = format!("{header_b64}.{payload_b64}");
        self.verify_signature(header.kid.as_deref(), signing_input.as_bytes(), &signature)?;

        let claims: Claims = decode_json(payload_b64).ok_or(VerifyError::Malformed)?;
        self.validate_claims(&claims, now_unix)
    }

    /// Verify the signature against the matching key(s).
    fn verify_signature(
        &self,
        kid: Option<&str>,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), VerifyError> {
        let sig = Signature::try_from(signature).map_err(|_| VerifyError::BadSignature)?;

        // When the header names a key id, only that key may sign the token.
        // Otherwise, accept any configured RSA key that verifies.
        let candidates = self.keys.iter().filter(|k| match kid {
            Some(kid) if !kid.is_empty() => k.kid == kid,
            _ => true,
        });

        let mut had_candidate = false;
        for key in candidates {
            had_candidate = true;
            if key.verifying_key.verify(signing_input, &sig).is_ok() {
                return Ok(());
            }
        }

        if had_candidate {
            Err(VerifyError::BadSignature)
        } else {
            Err(VerifyError::UnknownKey)
        }
    }

    /// Validate the registered claims (issuer, expiry, audience).
    fn validate_claims(&self, claims: &Claims, now_unix: u64) -> Result<(), VerifyError> {
        if claims.iss != self.issuer {
            return Err(VerifyError::BadIssuer);
        }

        if !self.skip_expiry_check {
            match claims.exp {
                Some(exp) if now_unix >= exp => return Err(VerifyError::Expired),
                None => return Err(VerifyError::Expired),
                _ => {}
            }
            if let Some(nbf) = claims.nbf {
                if now_unix < nbf {
                    return Err(VerifyError::NotYetValid);
                }
            }
        }

        if !self.skip_client_id_check {
            let ok = claims
                .aud
                .as_ref()
                .is_some_and(|aud| aud.contains(&self.client_id));
            if !ok {
                return Err(VerifyError::BadAudience);
            }
        }

        Ok(())
    }
}

/// Decode a base64url (no padding) segment and parse it as JSON.
fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Option<T> {
    let bytes = URL_SAFE_NO_PAD.decode(segment.as_bytes()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The JWS protected header fields we care about.
#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// The subset of registered claims we validate.
#[derive(Debug, Deserialize)]
struct Claims {
    #[serde(default)]
    iss: String,
    aud: Option<Audience>,
    exp: Option<u64>,
    nbf: Option<u64>,
}

/// The `aud` claim, which may be a single string or an array of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    fn contains(&self, value: &str) -> bool {
        if value.is_empty() {
            return false;
        }
        match self {
            Audience::Single(s) => s == value,
            Audience::Multiple(v) => v.iter().any(|s| s == value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Jwks, PluginConfig};

    fn verifier() -> Verifier {
        let config = PluginConfig {
            team_name: "test".to_string(),
            client_id: "aud".to_string(),
            skip_client_id_check: false,
            skip_expiry_check: false,
            jwks: Jwks::default(),
        };
        Verifier::from_config(&config)
    }

    fn b64(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(value.as_bytes())
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let v = verifier();
        assert_eq!(v.verify("only-one-part", 0), Err(VerifyError::Malformed));
        assert_eq!(v.verify("a.b", 0), Err(VerifyError::Malformed));
        assert_eq!(v.verify("a.b.c.d", 0), Err(VerifyError::Malformed));
        assert_eq!(v.verify(".b.c", 0), Err(VerifyError::Malformed));
    }

    #[test]
    fn non_rs256_alg_is_rejected_before_signature() {
        let v = verifier();
        let token = format!("{}.{}.{}", b64(r#"{"alg":"HS256"}"#), b64("{}"), b64("sig"));
        assert_eq!(
            v.verify(&token, 0),
            Err(VerifyError::UnsupportedAlg("HS256".to_string()))
        );
    }

    #[test]
    fn audience_matches_single_and_array() {
        assert!(Audience::Single("a".into()).contains("a"));
        assert!(!Audience::Single("a".into()).contains("b"));
        assert!(Audience::Multiple(vec!["a".into(), "b".into()]).contains("b"));
        assert!(!Audience::Multiple(vec!["a".into()]).contains("b"));
        // An empty client id never matches.
        assert!(!Audience::Single("".into()).contains(""));
    }

    #[test]
    fn error_messages_are_descriptive() {
        assert_eq!(VerifyError::Expired.to_string(), "token expired");
        assert_eq!(VerifyError::BadIssuer.to_string(), "issuer mismatch");
        assert_eq!(
            VerifyError::UnsupportedAlg("HS256".into()).to_string(),
            "unsupported algorithm: HS256"
        );
    }
}
