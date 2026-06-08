#!/usr/bin/env sh
#
# refresh-jwks.sh — keep the Cloudflare Access plugin's signing keys current.
#
# A Traefik WASM guest is sandboxed and cannot fetch Cloudflare's JWKS at
# runtime, so the keys are supplied through the plugin configuration. This script
# fetches the published keys and writes a Traefik *dynamic configuration* file
# (for the file provider) containing the middleware definition with the fresh
# `jwks`. Point Traefik's file provider at the output (with `watch: true`) and run
# this on a schedule (cron, a sidecar loop, or a systemd timer); Traefik
# hot-reloads the change with no restart.
#
# It is "fail safe": if the fetch fails or returns no usable keys, the existing
# output file is left untouched (last-known-good), so a transient Cloudflare
# outage never wipes your keys and locks everyone out. The file is also only
# rewritten when the content actually changes, to avoid needless Traefik reloads.
#
# Configuration (environment variables):
#   CF_TEAM_NAME            (required) Cloudflare Access team name.
#   CF_OUTPUT               (required) Path to the dynamic-config file to write.
#   CF_CLIENT_ID            (optional) Access application AUD tag.   Default: "".
#   CF_SKIP_CLIENT_ID_CHECK (optional) "true"/"false".              Default: false.
#   CF_SKIP_EXPIRY_CHECK    (optional) "true"/"false".              Default: false.
#   CF_MIDDLEWARE_NAME      (optional) Middleware name.   Default: cloudflare-access.
#   CF_CURL_OPTS            (optional) Extra curl options (advanced).
#
# Requires: curl, jq.

set -eu

log() { printf '%s refresh-jwks: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# --- Validate inputs -------------------------------------------------------

: "${CF_TEAM_NAME:?CF_TEAM_NAME is required}"
: "${CF_OUTPUT:?CF_OUTPUT is required (path to the dynamic-config file)}"

CF_CLIENT_ID="${CF_CLIENT_ID:-}"
CF_SKIP_CLIENT_ID_CHECK="${CF_SKIP_CLIENT_ID_CHECK:-false}"
CF_SKIP_EXPIRY_CHECK="${CF_SKIP_EXPIRY_CHECK:-false}"
CF_MIDDLEWARE_NAME="${CF_MIDDLEWARE_NAME:-cloudflare-access}"

case "$CF_SKIP_CLIENT_ID_CHECK" in true|false) ;; *) die "CF_SKIP_CLIENT_ID_CHECK must be 'true' or 'false'";; esac
case "$CF_SKIP_EXPIRY_CHECK"    in true|false) ;; *) die "CF_SKIP_EXPIRY_CHECK must be 'true' or 'false'";; esac

command -v curl >/dev/null 2>&1 || die "curl not found"
command -v jq   >/dev/null 2>&1 || die "jq not found"

CERTS_URL="https://${CF_TEAM_NAME}.cloudflareaccess.com/cdn-cgi/access/certs"

# --- Fetch -----------------------------------------------------------------

tmp_certs="$(mktemp)"
tmp_out="$(mktemp)"
trap 'rm -f "$tmp_certs" "$tmp_out"' EXIT

log "fetching $CERTS_URL"
# shellcheck disable=SC2086  # CF_CURL_OPTS is intentionally word-split.
if ! curl --fail --silent --show-error --location --max-time 10 --retry 3 --retry-delay 2 \
        ${CF_CURL_OPTS:-} -o "$tmp_certs" "$CERTS_URL"; then
    die "failed to fetch certs (output left unchanged)"
fi

jq empty "$tmp_certs" 2>/dev/null || die "certs response is not valid JSON (output left unchanged)"

key_count="$(jq '(.keys // []) | length' "$tmp_certs")"
if [ "$key_count" -eq 0 ]; then
    die "certs response contains no keys (output left unchanged)"
fi

# --- Build the dynamic configuration ---------------------------------------

# Keep only the fields the plugin uses; drop any that are absent (e.g. `alg`).
jq -n \
    --arg team "$CF_TEAM_NAME" \
    --arg clientId "$CF_CLIENT_ID" \
    --argjson skipClientId "$CF_SKIP_CLIENT_ID_CHECK" \
    --argjson skipExpiry "$CF_SKIP_EXPIRY_CHECK" \
    --arg mw "$CF_MIDDLEWARE_NAME" \
    --slurpfile certs "$tmp_certs" \
    '{
        http: {
            middlewares: {
                ($mw): {
                    plugin: {
                        cloudflareaccess: {
                            teamName: $team,
                            clientId: $clientId,
                            skipClientIdCheck: $skipClientId,
                            skipExpiryCheck: $skipExpiry,
                            jwks: {
                                keys: (($certs[0].keys // [])
                                    | map({kid, kty, alg, n, e}
                                        | with_entries(select(.value != null))))
                            }
                        }
                    }
                }
            }
        }
    }' > "$tmp_out" || die "failed to render configuration (output left unchanged)"

# --- Write atomically, only when changed -----------------------------------

if [ -f "$CF_OUTPUT" ] && cmp -s "$tmp_out" "$CF_OUTPUT"; then
    log "unchanged ($key_count key(s)); not rewriting $CF_OUTPUT"
    exit 0
fi

mkdir -p "$(dirname "$CF_OUTPUT")"
# Same-directory temp + mv = atomic replace; Traefik never sees a partial file.
final_tmp="${CF_OUTPUT}.tmp.$$"
cp "$tmp_out" "$final_tmp"
mv "$final_tmp" "$CF_OUTPUT"
log "wrote $CF_OUTPUT ($key_count key(s))"
