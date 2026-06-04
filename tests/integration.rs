//! End-to-end tests for the Cloudflare Access verifier.
//!
//! These run on the host target (`cargo test`) and exercise the real crypto
//! path: a fresh RSA key signs a JWT, a JWKS is built from the public key, and
//! the verifier validates (or rejects) it. They mirror the original Go test
//! suite (missing token, valid header/cookie token, bad issuer, bad key) and add
//! coverage for expiry and audience handling.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::Sha256;

use cloudflare_access::config::PluginConfig;
use cloudflare_access::token::extract_token;
use cloudflare_access::verifier::{Verifier, VerifyError};

const TEAM: &str = "test";
const ISSUER: &str = "https://test.cloudflareaccess.com";
const CLIENT_ID: &str = "test-aud-tag";
const NOW: u64 = 1_000_000_000;

/// A signing identity: the private key plus the `kid` advertised in tokens/JWKS.
struct Signer256 {
    key: SigningKey<Sha256>,
    public: RsaPublicKey,
    kid: String,
}

impl Signer256 {
    fn new(kid: &str) -> Self {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        let public = RsaPublicKey::from(&private);
        Self {
            key: SigningKey::<Sha256>::new(private),
            public,
            kid: kid.to_string(),
        }
    }

    /// The matching JWKS entry for this key.
    fn jwk(&self) -> Value {
        json!({
            "kid": self.kid,
            "kty": "RSA",
            "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(self.public.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(self.public.e().to_bytes_be()),
        })
    }

    /// Sign `claims` into a compact JWT, with a header carrying this key's `kid`.
    fn sign(&self, claims: Value) -> String {
        let header = json!({ "alg": "RS256", "typ": "JWT", "kid": self.kid });
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = self.key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }
}

/// Build a verifier from JSON config (also exercises config parsing).
fn make_verifier(skip_aud: bool, skip_exp: bool, keys: Vec<Value>) -> Verifier {
    let config_json = json!({
        "teamName": TEAM,
        "clientId": CLIENT_ID,
        "skipClientIdCheck": skip_aud,
        "skipExpiryCheck": skip_exp,
        "jwks": { "keys": keys },
    })
    .to_string();
    let config = PluginConfig::from_json(config_json.as_bytes()).expect("parse config");
    Verifier::from_config(&config)
}

/// Standard valid claims: correct issuer, audience, and a future expiry.
fn valid_claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": [CLIENT_ID],
        "exp": NOW + 3600,
        "nbf": NOW - 10,
        "email": "user@example.com",
    })
}

#[test]
fn missing_token_is_none() {
    // Mirrors TestCloudflareAccessMissingHeader.
    assert_eq!(extract_token(None, None), None);
}

#[test]
fn valid_token_via_header() {
    // Mirrors TestCloudflareAccessValidHeaderToken.
    let signer = Signer256::new("key-1");
    let verifier = make_verifier(false, false, vec![signer.jwk()]);
    let token = signer.sign(valid_claims());

    let extracted = extract_token(Some(token.as_bytes()), None).expect("token from header");
    assert_eq!(verifier.verify(&extracted, NOW), Ok(()));
}

#[test]
fn valid_token_via_cookie() {
    // Mirrors TestCloudflareAccessValidCookieToken.
    let signer = Signer256::new("key-1");
    let verifier = make_verifier(false, false, vec![signer.jwk()]);
    let token = signer.sign(valid_claims());

    let cookie = format!("CF_AUTHORIZATION={token}");
    let extracted = extract_token(None, Some(cookie.as_bytes())).expect("token from cookie");
    assert_eq!(verifier.verify(&extracted, NOW), Ok(()));
}

#[test]
fn invalid_issuer_is_rejected() {
    // Mirrors TestCloudflareAccessInvalidIssuerToken.
    let signer = Signer256::new("key-1");
    let verifier = make_verifier(false, false, vec![signer.jwk()]);
    let mut claims = valid_claims();
    claims["iss"] = json!("https://test.cloudflareaccess.com.evil");
    let token = signer.sign(claims);

    assert_eq!(verifier.verify(&token, NOW), Err(VerifyError::BadIssuer));
}

#[test]
fn wrong_signing_key_is_rejected() {
    // Mirrors TestCloudflareAccessInvalidKeyToken: token signed by a key that is
    // not the one published in the JWKS (same kid, different key material).
    let published = Signer256::new("key-1");
    let attacker = Signer256::new("key-1");
    let verifier = make_verifier(false, false, vec![published.jwk()]);
    let token = attacker.sign(valid_claims());

    assert_eq!(verifier.verify(&token, NOW), Err(VerifyError::BadSignature));
}

#[test]
fn unknown_kid_is_rejected() {
    let signer = Signer256::new("key-1");
    let other = Signer256::new("key-2");
    // JWKS only contains key-2, but the token's header advertises key-1.
    let verifier = make_verifier(false, false, vec![other.jwk()]);
    let token = signer.sign(valid_claims());

    assert_eq!(verifier.verify(&token, NOW), Err(VerifyError::UnknownKey));
}

#[test]
fn expired_token_is_rejected_but_can_be_skipped() {
    let signer = Signer256::new("key-1");
    let mut claims = valid_claims();
    claims["exp"] = json!(NOW - 1);
    let token = signer.sign(claims);

    let strict = make_verifier(false, false, vec![signer.jwk()]);
    assert_eq!(strict.verify(&token, NOW), Err(VerifyError::Expired));

    let lenient = make_verifier(false, true, vec![signer.jwk()]);
    assert_eq!(lenient.verify(&token, NOW), Ok(()));
}

#[test]
fn not_yet_valid_token_is_rejected() {
    let signer = Signer256::new("key-1");
    let mut claims = valid_claims();
    claims["nbf"] = json!(NOW + 60);
    let token = signer.sign(claims);

    let verifier = make_verifier(false, false, vec![signer.jwk()]);
    assert_eq!(verifier.verify(&token, NOW), Err(VerifyError::NotYetValid));
}

#[test]
fn audience_mismatch_is_rejected_but_can_be_skipped() {
    let signer = Signer256::new("key-1");
    let mut claims = valid_claims();
    claims["aud"] = json!(["some-other-app"]);
    let token = signer.sign(claims);

    let strict = make_verifier(false, false, vec![signer.jwk()]);
    assert_eq!(strict.verify(&token, NOW), Err(VerifyError::BadAudience));

    let lenient = make_verifier(true, false, vec![signer.jwk()]);
    assert_eq!(lenient.verify(&token, NOW), Ok(()));
}

#[test]
fn audience_as_single_string_is_accepted() {
    let signer = Signer256::new("key-1");
    let mut claims = valid_claims();
    claims["aud"] = json!(CLIENT_ID); // single string instead of array
    let token = signer.sign(claims);

    let verifier = make_verifier(false, false, vec![signer.jwk()]);
    assert_eq!(verifier.verify(&token, NOW), Ok(()));
}

#[test]
fn token_without_kid_matches_any_rsa_key() {
    // A token whose header omits `kid` is verified against all configured keys.
    let signer = Signer256::new("");
    let header = json!({ "alg": "RS256", "typ": "JWT" });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(valid_claims().to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer.key.sign(signing_input.as_bytes());
    let token = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );

    let mut jwk = signer.jwk();
    jwk["kid"] = json!("published-kid");
    let verifier = make_verifier(false, false, vec![jwk]);
    assert_eq!(verifier.verify(&token, NOW), Ok(()));
}

#[test]
fn no_keys_configured_is_rejected() {
    let signer = Signer256::new("key-1");
    let verifier = make_verifier(false, false, vec![]);
    let token = signer.sign(valid_claims());

    assert_eq!(verifier.verify(&token, NOW), Err(VerifyError::UnknownKey));
}
