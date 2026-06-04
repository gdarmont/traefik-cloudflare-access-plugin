//! Traefik `http-wasm` guest entrypoint for the Cloudflare Access middleware.
//!
//! All request-handling logic lives in the `cloudflare_access` library (pure and
//! natively testable). This file is only the thin host-ABI glue and is compiled
//! solely for the `wasm32` target; on any other target it is an empty program so
//! that `cargo test`/`cargo build` on the host never link the host FFI symbols.

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    // The plugin is only meaningful as a wasm guest loaded by Traefik. Building
    // natively is supported purely so the library and tests compile and run.
}

#[cfg(target_arch = "wasm32")]
fn main() {
    wasm::init();
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use cloudflare_access::config::PluginConfig;
    use cloudflare_access::token::{self, JWT_HEADER};
    use cloudflare_access::verifier::Verifier;

    use http_wasm_guest::host::{admin, log, Request, Response};
    use http_wasm_guest::{register, Guest};

    use std::time::{SystemTime, UNIX_EPOCH};

    // http-wasm log levels: debug=-1, info=0, warn=1, error=2.
    const LOG_INFO: i32 = 0;
    const LOG_ERROR: i32 = 2;

    const STATUS_UNAUTHORIZED: i32 = 401;
    const COOKIE_HEADER: &[u8] = b"Cookie";

    /// Parse the host-provided configuration and register the guest.
    pub fn init() {
        let config_bytes = admin::config();
        let plugin = match PluginConfig::from_json(&config_bytes) {
            Ok(config) => {
                log::write(
                    LOG_INFO,
                    format!(
                        "cloudflare-access: configured for issuer {} ({} key(s))",
                        config.issuer(),
                        config.jwks.keys.len()
                    )
                    .as_bytes(),
                );
                Plugin {
                    verifier: Some(Verifier::from_config(&config)),
                }
            }
            Err(err) => {
                // Fail closed: without a valid configuration every request is denied.
                log::write(
                    LOG_ERROR,
                    format!("cloudflare-access: invalid configuration: {err}").as_bytes(),
                );
                Plugin { verifier: None }
            }
        };
        register(plugin);
    }

    struct Plugin {
        verifier: Option<Verifier>,
    }

    impl Guest for Plugin {
        fn handle_request(&self, request: &Request, response: &Response) -> (bool, i32) {
            let Some(verifier) = self.verifier.as_ref() else {
                return deny(response, b"Plugin misconfigured");
            };

            let jwt = request.header.get(JWT_HEADER);
            let cookie = request.header.get(COOKIE_HEADER);
            let token = token::extract_token(jwt.as_deref(), cookie.as_deref());

            let Some(token) = token else {
                return deny(response, b"No token on the request");
            };

            match verifier.verify(&token, now_unix()) {
                Ok(()) => (true, 0),
                Err(err) => deny(response, format!("Invalid token: {err}").as_bytes()),
            }
        }
    }

    /// Short-circuit the request with a `401 Unauthorized` and the given message.
    fn deny(response: &Response, message: &[u8]) -> (bool, i32) {
        response.set_status(STATUS_UNAUTHORIZED);
        response.body.write(message);
        (false, 0)
    }

    /// Current time in seconds since the Unix epoch (0 if the clock is unavailable).
    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
