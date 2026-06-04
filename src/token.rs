//! Extraction of the Cloudflare Access JWT from request data.
//!
//! These functions are pure (they take raw bytes rather than touching the host
//! ABI) so the extraction logic can be unit-tested directly.

/// Request header carrying the Access JWT.
pub const JWT_HEADER: &[u8] = b"Cf-Access-Jwt-Assertion";

/// Name of the cookie carrying the Access JWT.
pub const JWT_COOKIE: &str = "CF_AUTHORIZATION";

/// Extract the Access token, preferring the `Cf-Access-Jwt-Assertion` header and
/// falling back to the `CF_AUTHORIZATION` cookie.
///
/// `jwt_header` is the value of the JWT header (if present); `cookie_header` is
/// the raw value of the `Cookie` request header (if present). An empty header
/// value is treated as absent, matching the original Go plugin.
pub fn extract_token(jwt_header: Option<&[u8]>, cookie_header: Option<&[u8]>) -> Option<String> {
    if let Some(value) = jwt_header {
        if let Ok(token) = std::str::from_utf8(value) {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }

    let cookie_header = cookie_header?;
    let cookie_header = std::str::from_utf8(cookie_header).ok()?;
    cookie_value(cookie_header, JWT_COOKIE)
}

/// Find the value of a single cookie within a raw `Cookie` header.
///
/// The header is a list of `name=value` pairs separated by `;`. Surrounding
/// whitespace is ignored. The first match wins.
fn cookie_value(cookie_header: &str, name: &str) -> Option<String> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        let (key, value) = pair.split_once('=')?;
        if key.trim() == name {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_header_over_cookie() {
        let token = extract_token(
            Some(b"header-token"),
            Some(b"CF_AUTHORIZATION=cookie-token"),
        );
        assert_eq!(token.as_deref(), Some("header-token"));
    }

    #[test]
    fn falls_back_to_cookie() {
        let token = extract_token(None, Some(b"CF_AUTHORIZATION=cookie-token"));
        assert_eq!(token.as_deref(), Some("cookie-token"));
    }

    #[test]
    fn empty_header_falls_back_to_cookie() {
        let token = extract_token(Some(b""), Some(b"CF_AUTHORIZATION=cookie-token"));
        assert_eq!(token.as_deref(), Some("cookie-token"));
    }

    #[test]
    fn finds_cookie_among_many() {
        let token = extract_token(None, Some(b"foo=bar; CF_AUTHORIZATION=the-token; baz=qux"));
        assert_eq!(token.as_deref(), Some("the-token"));
    }

    #[test]
    fn no_token_present() {
        assert_eq!(extract_token(None, None), None);
        assert_eq!(extract_token(None, Some(b"other=value")), None);
        assert_eq!(extract_token(Some(b""), Some(b"other=value")), None);
    }
}
