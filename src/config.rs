//! Plugin configuration, deserialized from the JSON that Traefik passes to the
//! guest (the `plugin.<name>` block of the dynamic configuration).

use serde::Deserialize;

/// Configuration for the Cloudflare Access middleware.
///
/// Field names use the camelCase form expected in Traefik dynamic configuration,
/// mirroring the original Go plugin (`teamName`, `clientId`, `skipClientIdCheck`)
/// plus the `jwks` needed for offline verification.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginConfig {
    /// Cloudflare Access team name. The issuer is derived from it as
    /// `https://<teamName>.cloudflareaccess.com`.
    pub team_name: String,

    /// Expected audience (the Access application "AUD" tag). When empty, or when
    /// [`Self::skip_client_id_check`] is set, the audience is not validated.
    #[serde(default)]
    pub client_id: String,

    /// Skip validation of the `aud` claim against [`Self::client_id`].
    #[serde(default)]
    pub skip_client_id_check: bool,

    /// Skip validation of the `exp`/`nbf` claims. Intended for diagnostics and
    /// tests; leave `false` in production.
    #[serde(default)]
    pub skip_expiry_check: bool,

    /// The signing keys, in JWKS form. This is the JSON served by Cloudflare at
    /// `https://<teamName>.cloudflareaccess.com/cdn-cgi/access/certs`.
    pub jwks: Jwks,
}

/// A JSON Web Key Set: the collection of public keys used to verify signatures.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Jwks {
    /// The individual keys. Non-RSA keys are ignored during verification.
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

/// A single JSON Web Key. Only the fields needed for RSA (`RS256`) verification
/// are modelled; unknown fields in the source JSON are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key ID, matched against the JWT header `kid`.
    #[serde(default)]
    pub kid: String,

    /// Key type. Only `"RSA"` is supported.
    #[serde(default)]
    pub kty: String,

    /// Signature algorithm, e.g. `"RS256"` (optional in the JWKS).
    #[serde(default)]
    pub alg: Option<String>,

    /// RSA modulus, base64url-encoded (no padding).
    #[serde(default)]
    pub n: String,

    /// RSA public exponent, base64url-encoded (no padding).
    #[serde(default)]
    pub e: String,
}

impl PluginConfig {
    /// Parse the configuration from raw JSON bytes provided by the host.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// The OIDC issuer derived from the team name.
    pub fn issuer(&self) -> String {
        format!("https://{}.cloudflareaccess.com", self.team_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let json = br#"{
            "teamName": "myteam",
            "clientId": "aud-tag",
            "skipClientIdCheck": false,
            "jwks": { "keys": [
                { "kid": "k1", "kty": "RSA", "alg": "RS256", "n": "AQAB", "e": "AQAB" }
            ] }
        }"#;
        let cfg = PluginConfig::from_json(json).expect("config should parse");
        assert_eq!(cfg.team_name, "myteam");
        assert_eq!(cfg.client_id, "aud-tag");
        assert!(!cfg.skip_client_id_check);
        assert!(!cfg.skip_expiry_check);
        assert_eq!(cfg.issuer(), "https://myteam.cloudflareaccess.com");
        assert_eq!(cfg.jwks.keys.len(), 1);
        assert_eq!(cfg.jwks.keys[0].kid, "k1");
    }

    #[test]
    fn applies_defaults_for_optional_fields() {
        let json = br#"{ "teamName": "t", "jwks": { "keys": [] } }"#;
        let cfg = PluginConfig::from_json(json).expect("config should parse");
        assert_eq!(cfg.client_id, "");
        assert!(!cfg.skip_client_id_check);
        assert!(!cfg.skip_expiry_check);
        assert!(cfg.jwks.keys.is_empty());
    }

    #[test]
    fn missing_required_field_is_error() {
        // No teamName.
        let json = br#"{ "jwks": { "keys": [] } }"#;
        assert!(PluginConfig::from_json(json).is_err());
    }
}
