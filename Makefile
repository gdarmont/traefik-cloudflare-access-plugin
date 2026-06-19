.PHONY: default test lint build wasm clean dist release

WASM_TARGET := wasm32-wasip1
WASM_ARTIFACT := target/$(WASM_TARGET)/release/plugin.wasm

default: lint test

# Run the native test suite (lib unit tests + integration tests).
test:
	cargo test

# Lint everything, treating warnings as errors.
lint:
	cargo clippy --all-targets -- -D warnings
	cargo fmt --check

# Build the WASM guest and copy it to ./plugin.wasm (committed to the repo so
# Traefik can load it directly from the tagged source).
build wasm:
	cargo build --bin plugin --release --target $(WASM_TARGET)
	cp $(WASM_ARTIFACT) ./plugin.wasm

clean:
	cargo clean
	rm -f ./plugin.wasm

dist: build wasm
	mkdir -p dist/traefik-cloudflare-access-plugin
	cp plugin.wasm dist/traefik-cloudflare-access-plugin
	cp .traefik.yml dist/traefik-cloudflare-access-plugin
	cd dist && zip -r traefik-cloudflare-access-plugin.zip traefik-cloudflare-access-plugin

release:
	@[ "$(VERSION)" ] || { echo "Usage: make release VERSION=0.5.0"; exit 1; }
	@git diff --quiet && git diff --cached --quiet || { echo "Error: working tree is dirty"; exit 1; }
	@git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null && { echo "Error: tag v$(VERSION) already exists"; exit 1; } || true
	# Sync the Cargo.toml version with the release tag (Cargo.lock is refreshed by dist).
	sed -i '0,/^version = .*/s//version = "$(VERSION)"/' Cargo.toml
	@grep -q '^version = "$(VERSION)"$$' Cargo.toml || { echo "Error: failed to set version in Cargo.toml"; exit 1; }
	$(MAKE) dist
	git add Cargo.toml Cargo.lock plugin.wasm
	git commit -m "Release v$(VERSION)"
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin HEAD "v$(VERSION)"
	gh release create "v$(VERSION)" \
		--title "v$(VERSION)" \
		--generate-notes \
		"dist/traefik-cloudflare-access-plugin.zip#traefik-cloudflare-access-plugin.zip"