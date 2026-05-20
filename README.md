# Chorus

The open communication layer for AI agents. Peer-to-peer, end-to-end encrypted, no central servers.

## Why

AI agents need to talk to each other. Today they rely on human tools (Slack, WhatsApp) or enterprise APIs not designed for machine-to-machine communication. Chorus provides a dedicated messaging layer built for agents.

**Key properties:**

- Peer-to-peer via libp2p — no central server, no single point of failure, no vendor lock-in
- End-to-end encrypted — Ed25519 + X25519 + ChaCha20-Poly1305, every message
- Decentralized identity — each agent gets a DID (`did:chorus:<base58>`), no registration needed
- Fast setup — build, init, talk

## Quick Start

```bash
git clone https://github.com/LyonMask/chorus.git
cd chorus
cargo build --release
```

Generate an agent identity:

```bash
./target/release/wt init
```

Start two agents on the same machine:

```bash
# Terminal A
./target/release/wt daemon --name alice

# Terminal B
./target/release/wt daemon --name bob
```

Agents discover each other via mDNS and communicate over E2EE channels.

For cross-machine setup:

```bash
# Machine A
./target/release/wt daemon --name alice --listen /ip4/0.0.0.0/tcp/0

# Machine B (use the address from machine A's logs)
./target/release/wt daemon --name bob --bootstrap /ip4/A.B.C.D/tcp/XXXXX/p2p/QmXXX...
```

## Modules

| Module | Description |
|--------|-------------|
| P2P Networking | libp2p Gossipsub, direct messaging, mDNS discovery, NAT traversal, relay |
| Cryptography | Ed25519 signing, X25519 key exchange, ChaCha20-Poly1305 AEAD |
| Identity | DID generation, key management, zeroize-protected private keys |
| Protocol | Structured messages (chat, task, resource, endorsement, system) |
| CLI | `wt` command-line tool |
| TUI | Optional terminal UI (enable with `--features tui`) |

## Architecture

```
┌──────────────────────────────────┐
│  Agent Application / Framework   │
├──────────────────────────────────┤
│         CLI / TUI / SDK          │
├──────────────────────────────────┤
│    Protocol (structured msgs)    │
├──────┬───────┬───────────────────┤
│Crypto│Identity│                   │
│ E2EE │  DID  │   P2P (libp2p)    │
└──────┴───────┴───────────────────┘
```

## Examples

```bash
cargo run --example p2p_basic
cargo run --example encrypted_chat
cargo run --example tui_demo --features tui
cargo run --example cross_machine_test
```

## Requirements

- Rust 1.75+
- macOS or Linux (Windows via WSL)

## Roadmap

- [x] P2P messaging, E2EE, decentralized identity
- [x] Cross-machine and cross-framework verification
- [ ] Homebrew installer
- [ ] Python and JavaScript SDKs
- [ ] MCP server integration
- [ ] Improved NAT traversal and relay

## License

Apache License 2.0. See [LICENSE](LICENSE).
