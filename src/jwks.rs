//! Conversion of JSON Web Keys into usable RSA public keys.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::{BigUint, RsaPublicKey};

use crate::config::Jwk;

/// Errors that can occur while turning a [`Jwk`] into an [`RsaPublicKey`].
#[derive(Debug, PartialEq, Eq)]
pub enum JwkError {
    /// The key type is not `RSA`.
    UnsupportedKeyType(String),
    /// The base64url modulus or exponent could not be decoded.
    InvalidBase64,
    /// The decoded components did not form a valid RSA public key.
    InvalidKey,
}

impl core::fmt::Display for JwkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JwkError::UnsupportedKeyType(kty) => write!(f, "unsupported key type: {kty}"),
            JwkError::InvalidBase64 => write!(f, "invalid base64url in key material"),
            JwkError::InvalidKey => write!(f, "invalid RSA public key"),
        }
    }
}

impl std::error::Error for JwkError {}

impl Jwk {
    /// Whether this key is usable for RSA verification.
    pub fn is_rsa(&self) -> bool {
        self.kty.eq_ignore_ascii_case("RSA")
    }

    /// Build an [`RsaPublicKey`] from the JWK's base64url `n`/`e` components.
    pub fn to_public_key(&self) -> Result<RsaPublicKey, JwkError> {
        if !self.is_rsa() {
            return Err(JwkError::UnsupportedKeyType(self.kty.clone()));
        }
        let n = URL_SAFE_NO_PAD
            .decode(self.n.as_bytes())
            .map_err(|_| JwkError::InvalidBase64)?;
        let e = URL_SAFE_NO_PAD
            .decode(self.e.as_bytes())
            .map_err(|_| JwkError::InvalidBase64)?;
        let n = BigUint::from_bytes_be(&n);
        let e = BigUint::from_bytes_be(&e);
        RsaPublicKey::new(n, e).map_err(|_| JwkError::InvalidKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Jwk;

    fn rsa_jwk(kid: &str, n: &str, e: &str) -> Jwk {
        Jwk {
            kid: kid.to_string(),
            kty: "RSA".to_string(),
            alg: Some("RS256".to_string()),
            n: n.to_string(),
            e: e.to_string(),
        }
    }

    #[test]
    fn rejects_non_rsa_key() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            ..rsa_jwk("k", "AQAB", "AQAB")
        };
        assert!(!jwk.is_rsa());
        assert_eq!(
            jwk.to_public_key().unwrap_err(),
            JwkError::UnsupportedKeyType("EC".to_string())
        );
    }

    #[test]
    fn rejects_invalid_base64() {
        let jwk = rsa_jwk("k", "not base64!!!", "AQAB");
        assert_eq!(jwk.to_public_key().unwrap_err(), JwkError::InvalidBase64);
    }
}
