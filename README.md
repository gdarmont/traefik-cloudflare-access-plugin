# Traefik Cloudflare Access Plugin (WASM)

A [Traefik](https://github.com/traefik/traefik) **middleware plugin**, written in
Rust and compiled to **WebAssembly**, that validates requests coming from your
Cloudflare Zero Trust (Access) account.

On every request it:

1. Reads the Access JWT from the `Cf-Access-Jwt-Assertion` header, or — failing
   that — from the `CF_AUTHORIZATION` cookie.
2. Verifies the token's **RS256** signature against your team's public keys.
3. Checks the standard claims: issuer (`https://<teamName>.cloudflareaccess.com`),
   expiry (`exp`/`nbf`), and audience (`aud` must contain your application's AUD tag).
4. Forwards the request to the next handler on success, or returns **`401
   Unauthorized`** on any failure (`No token on the request` / `Invalid token: …`).

This mirrors the behaviour of the original Go version of the plugin.

## How keys are provided (important)

The original Go plugin fetched Cloudflare's signing keys (JWKS) over HTTPS at
verification time (`oidc.NewRemoteKeySet`). A Traefik **WASM guest is sandboxed
and has no outbound HTTP client**, so that runtime fetch is not possible.

Instead, **you supply the JWKS in the plugin configuration**. You paste the JSON
that Cloudflare publishes at:

```
https://<teamName>.cloudflareaccess.com/cdn-cgi/access/certs
```

Cloudflare rotates these keys infrequently. **When they rotate, update the `jwks`
in your dynamic configuration.** The plugin can hold multiple keys at once, so you
can add the new key before the old one is retired for a zero-downtime rotation.

### Fetching the JWKS

```sh
curl -s https://<teamName>.cloudflareaccess.com/cdn-cgi/access/certs | jq .
```

The response looks like:

```json
{
  "keys": [
    {
      "kid": "0123…",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "uib9…",
      "e": "AQAB"
    }
  ]
}
```

Only `kid`, `kty`, `alg`, `n`, and `e` are used; any extra fields are ignored.

## Configuration

### Static configuration

Declare the plugin in Traefik's **static** configuration. Use `plugins` for a
published version, or `localPlugins` for a local checkout (see
[Local development](#local-development)).

```yaml
experimental:
  plugins:
    cloudflareaccess:
      moduleName: "github.com/gdarmont/traefik-cloudflare-access-plugin"
      version: "v0.1.0"
```

### Dynamic configuration

Define the middleware in your **dynamic** configuration and attach it to a router.

```yaml
http:
  middlewares:
    cloudflare-access:
      plugin:
        cloudflareaccess:
          teamName: "myteam"
          clientId: "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2"
          skipClientIdCheck: false
          jwks:
            keys:
              - kid: "0123…"
                kty: "RSA"
                alg: "RS256"
                n: "uib9…"
                e: "AQAB"

  routers:
    my-app:
      rule: "Host(`app.example.com`)"
      service: my-app
      middlewares:
        - cloudflare-access
```

### Configuration reference

| Field               | Type    | Required | Default | Description                                                                                  |
| ------------------- | ------- | -------- | ------- | -------------------------------------------------------------------------------------------- |
| `teamName`          | string  | yes      | —       | Your Cloudflare Access team name. The issuer is `https://<teamName>.cloudflareaccess.com`.    |
| `clientId`          | string  | no       | `""`    | The Access application's **AUD tag**. Validated against the token's `aud` claim.              |
| `skipClientIdCheck` | bool    | no       | `false` | Skip audience (`aud`) validation. Leave `false` unless you intentionally accept any audience. |
| `skipExpiryCheck`   | bool    | no       | `false` | Skip `exp`/`nbf` validation. For diagnostics/testing only — **leave `false` in production**.  |
| `jwks`              | object  | yes      | —       | The JWKS (`{ "keys": [ … ] }`) from the Cloudflare certs endpoint.                            |

If the configuration is missing or invalid, the plugin **fails closed**: every
request is rejected with `401`.

## Building from source

Requirements:

- **Rust**, managed by `rustup`. The exact toolchain version and the
  `wasm32-wasip1` target are pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
  and installed automatically on first `cargo` invocation. The pin keeps the
  committed `plugin.wasm` reproducible; bump it and rebuild in the same change.

Build the WASM artifact:

```sh
make wasm
# or, equivalently:
cargo build --bin plugin --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/plugin.wasm ./plugin.wasm
```

`plugin.wasm` is committed to the repository because Traefik downloads the
prebuilt artifact from the tagged source — it does **not** compile Rust itself.
Rebuild and commit `plugin.wasm` whenever the source changes; CI rebuilds it with
the pinned toolchain and fails if the committed artifact is stale.

### Make targets

| Target       | Description                                                            |
| ------------ | --------------------------------------------------------------------- |
| `make test`  | Run the native test suite (`cargo test`).                              |
| `make lint`  | `cargo clippy --all-targets -D warnings` and `cargo fmt --check`.      |
| `make wasm`  | Build `plugin.wasm` for `wasm32-wasip1` and copy it to the repo root.  |
| `make clean` | `cargo clean` and remove `plugin.wasm`.                                |

## Testing

The verification logic lives in a plain Rust library (`cloudflare_access`) with no
dependency on the host ABI, so it is tested natively — no WASM runtime needed:

```sh
cargo test
```

The integration suite (`tests/integration.rs`) generates a real RSA key, signs
JWTs, builds a JWKS from the public key, and exercises the full verification path
(valid header/cookie tokens, bad issuer, wrong key, unknown `kid`, expiry, and
audience handling).

## Local development

To run the plugin against a local Traefik without publishing it, place the
artifact and manifest under `plugins-local`:

```
plugins-local/
  src/github.com/gdarmont/traefik-cloudflare-access-plugin/
    plugin.wasm
    .traefik.yml
```

Static configuration:

```yaml
experimental:
  localPlugins:
    cloudflareaccess:
      moduleName: "github.com/gdarmont/traefik-cloudflare-access-plugin"
```

Then configure the middleware exactly as in [Dynamic configuration](#dynamic-configuration).

## Project layout

```
src/
  lib.rs        # crate root: config, jwks, token, verifier
  config.rs     # plugin configuration (serde)
  jwks.rs       # JWK -> rsa::RsaPublicKey
  token.rs      # token extraction from header/cookie (pure)
  verifier.rs   # RS256 signature + claim validation (pure)
  main.rs       # http-wasm guest glue (wasm32 target only)
tests/
  integration.rs
_old/           # the previous Go implementation, kept for reference
```

## License

Apache-2.0. See [LICENSE](LICENSE).
