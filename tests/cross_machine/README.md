# Cross-Machine Integration Tests

Run Walkie Talkie integration tests across two physical machines to validate
real-world P2P behavior (NAT traversal, latency, packet loss).

## Prerequisites

- Rust toolchain installed on both machines
- Walkie Talkie code deployed on both machines
- SSH access between machines
- Both machines on the same LAN (or with port forwarding)

## Usage

### Option A: Manual

**Machine A (provider):**
```bash
cd /path/to/walkie-talkie/core
RUST_LOG=info cargo test --test integration_realworld -- cross_machine_node_a --nocapture --ignored
```

**Machine B (consumer):**
```bash
cd /path/to/walkie-talkie/core
RUST_LOG=info cargo test --test integration_realworld -- cross_machine_node_b --nocapture --ignored
```

### Option B: Script (from Machine A)

Edit the script to set the correct SSH target and path, then run:

```bash
bash tests/cross_machine/run_cross_machine_test.sh
```

## Current Status

- [x] Single-machine dual-node tests (7 tests, all passing)
- [ ] Cross-machine node A implementation
- [ ] Cross-machine node B implementation
- [ ] Multi-hop (A→B→C) test
- [ ] NAT traversal test
- [ ] Latency/bandwidth benchmark

## Notes

- Cross-machine tests are `#[ignore]` by default — run with `--ignored`
- The `TestNode` wrapper in `integration_realworld.rs` will be reused
- wt CLI (from Rustacean) will provide a cleaner interface when ready
- For now, direct library API calls mirror headless_demo.rs patterns
