SHELL := /bin/bash
PROJECT_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CARGO := cargo
GO := go

.PHONY: setup build-rust-ffi test-rust test-go cli demo verify-all clean lint check

setup:
	@echo "=== Axiom Reproducibility Setup ==="
	@which rustup 2>/dev/null || (echo "Installing rustup..." && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y)
	@which go 2>/dev/null || (echo "ERROR: Go is required. Install from https://go.dev/dl/" && exit 1)
	@echo "Setup complete."

build-rust-ffi:
	$(CARGO) build --release -p axiom-core-ffi
	@echo "=== FFI Build Complete ==="

test-rust:
	$(CARGO) test --workspace --quiet

test-go: build-rust-ffi
	@echo "=== Running Go FFI Tests ==="
	LD_LIBRARY_PATH="$(PROJECT_ROOT)target/release:$(PROJECT_ROOT)target/debug:$${LD_LIBRARY_PATH}" \
		CGO_LDFLAGS="-L$(PROJECT_ROOT)target/release -laxiom_core_ffi -lm -ldl" \
		CGO_CFLAGS="-I$(PROJECT_ROOT)crates/axiom-core-ffi/include" \
		$(GO) test ./crates/axiom-core-go/... -v

cli: build-rust-ffi
	$(CARGO) build --release -p axiom-cli
	@echo "=== CLI Build Complete ==="
	@echo "  Binary: target/release/axiom"
	@echo "  Run:    axiom init"

demo: cli
	rm -rf /tmp/axiom-demo && mkdir -p /tmp/axiom-demo && cd /tmp/axiom-demo && \
	$(PROJECT_ROOT)target/release/axiom init && \
	echo "Demo artifact" > artifact.txt && \
	$(PROJECT_ROOT)target/release/axiom hash artifact.txt && \
	$(PROJECT_ROOT)target/release/axiom key generate demo-key && \
	$(PROJECT_ROOT)target/release/axiom sign artifact.txt --key .axiom/keys/demo-key.key --predicate attests --out artifact.axm && \
	$(PROJECT_ROOT)target/release/axiom verify artifact.axm && \
	$(PROJECT_ROOT)target/release/axiom inspect artifact.axm && \
	$(PROJECT_ROOT)target/release/axiom lint artifact.axm && \
	@echo "=== Demo Complete ==="

test-all: cli
	@echo "=== Running CLI built-in tests ==="
	$(PROJECT_ROOT)target/release/axiom test
	@echo "=== Running CLI doctor ==="
	$(PROJECT_ROOT)target/release/axiom doctor
	@echo "=== Running CLI benchmark ==="
	$(PROJECT_ROOT)target/release/axiom benchmark

verify-all:
	./scripts/fresh_clone_test.sh

clean:
	$(CARGO) clean
	rm -rf target

lint:
	$(CARGO) clippy --all-targets -- -D warnings

deny:
	$(CARGO) deny check

precommit:
	@which pre-commit 2>/dev/null || (echo "Installing pre-commit..." && pip install pre-commit)
	pre-commit install --hook-type pre-commit --hook-type commit-msg
	pre-commit run --all-files

setup-dev:
	@echo "=== Installing cargo-deny ==="
	@which cargo-deny 2>/dev/null || cargo install cargo-deny --locked
	@echo "=== Installing pre-commit hooks ==="
	@which pre-commit 2>/dev/null || pip install pre-commit
	pre-commit install --hook-type pre-commit --hook-type commit-msg
	@echo "=== Dev setup complete ==="

check:
	$(CARGO) check --all-targets
