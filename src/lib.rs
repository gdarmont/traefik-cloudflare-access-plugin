//! Cloudflare Access JWT validation for Traefik.
//!
//! This crate is the portable, host-independent core of the Traefik
//! Cloudflare Access WASM plugin. It is deliberately free of any `http-wasm`
//! (host ABI) dependency so it builds and unit-tests natively, while the same
//! code is reused by the wasm guest in `src/main.rs`.
//!
//! The flow mirrors the original Go plugin:
//!
//! 1. Extract the Access JWT from the `Cf-Access-Jwt-Assertion` header or the
//!    `CF_AUTHORIZATION` cookie ([`token::extract_token`]).
//! 2. Verify the token (RS256 signature + claims) against the configured
//!    issuer/audience and signing keys ([`verifier::Verifier`]).
//!
//! Unlike the Go version, which fetches Cloudflare's JWKS over the network at
//! verification time, the signing keys are provided up front through the plugin
//! [`config::PluginConfig`] because a thin WASM guest cannot make outbound HTTP
//! requests.

pub mod config;
pub mod jwks;
pub mod token;
pub mod verifier;
