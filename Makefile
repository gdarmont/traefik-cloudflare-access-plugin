.PHONY: default test lint build wasm clean

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
