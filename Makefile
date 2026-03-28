# walkie-talkie-core Makefile
# Usage: make [target]

CARGO   ?= cargo
CARGO_FLAGS ?=

.PHONY: all build test check clippy fmt lint clean install examples doc ci

# ── Default ──
all: check test

# ── Build ──
build:
	$(CARGO) build $(CARGO_FLAGS)

build-release:
	$(CARGO) build --release $(CARGO_FLAGS)

# ── Test ──
test:
	$(CARGO) test $(CARGO_FLAGS)

test-release:
	$(CARGO) test --release $(CARGO_FLAGS)

test-verbose:
	$(CARGO) test -- --nocapture $(CARGO_FLAGS)

test-one:
	@read -p "Test name: " NAME; \
	$(CARGO) test $$NAME -- --nocapture $(CARGO_FLAGS)

# ── Quality ──
check: fmt-check clippy

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

lint: fmt-check clippy

# ── Doc ──
doc:
	$(CARGO) doc --no-deps

# ── Examples ──
examples:
	$(CARGO) build --examples

# ── Clean ──
clean:
	$(CARGO) clean

# ── CI (mirrors GitHub Actions pipeline) ──
ci: fmt-check clippy test
	@echo "✅ CI checks passed"
