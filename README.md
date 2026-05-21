[![CI](https://github.com/LyonMask/chorus/actions/workflows/ci.yml/badge.svg)](https://github.com/LyonMask/chorus/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

# Chorus

The open communication layer for AI agents. Peer-to-peer, end-to-end encrypted, no central servers.

## The Problem

AI agents don't have their own communication layer. They borrow ours.

Today, when two agents need to talk, they go through one of these paths:

- **Human messaging tools** — Slack webhooks, WhatsApp bots, Telegram APIs. Built for people, retrofitted for machines. Every message hits a server you don't control.
- **Enterprise APIs** — OpenAI's API, Anthropic's API, LangChain chains. Vendor-locked, billed per call, with your agents' conversations flowing through someone else's infrastructure.
- **Custom TCP/HTTP** — Everyone reinvents the wheel. Authentication, encryption, discovery, identity — solved badly, solved differently each time.

The result: agent communication is fragile, centralized, and leaky. You're running someone else's protocol, on someone else's server, with someone else's encryption (if any).

## Why Chorus

Chorus gives agents a native communication layer. Not a wrapper around human tools. Not an API gateway. A peer-to-peer mesh where agents talk directly, encrypted end-to-end, with no middleman.

**What this means in practice:**

- **No server to manage.** Agents discover each other via mDNS (local) or bootstrap nodes (remote). The network *is* the infrastructure.
- **No one reads your messages.** Ed25519 signing + X25519 key exchange + ChaCha20-Poly1305 AEAD. Every message, every time. Not "encrypted in transit" — encrypted *period*.
- **No registration required.** Each agent generates its own DID (`did:chorus:<base58>`). Identity is cryptographic, not administrative. No accounts, no API keys, no email verification.
- **No vendor lock-in.** Rust library, Apache 2.0 license. Build it into your agent framework, run it on your hardware, own your stack.

## What It's Not

- Not a framework. Chorus handles communication. You bring the agent logic.
- Not a replacement for LLM APIs. Agents still need inference. Chorus handles *how they talk to each other*.
- Not production-hardened (yet). It works, it's encrypted, it's open source — but expect breaking changes as the protocol evolves.

## Quick Start

```bash
git clone https://github.com/LyonMask/chorus.git
cd chorus
cargo build --release
```

Start two agents on the same machine (mDNS auto-discovery):

```bash
# Terminal A
./target/release/chorus start --name alice

# Terminal B
./target/release/chorus start --name bob
```

Agents discover each other via mDNS and communicate over E2EE channels.

For cross-machine setup:

```bash
# Machine A
./target/release/chorus start --name alice --port 4000

# Machine B (use the address from machine A's output)
./target/release/chorus start --name bob --relay-peer /ip4/A.B.C.D/tcp/4000/p2p/QmXXX...
```

## Modules

| Module | Description |
|--------|-------------|
| P2P Networking | libp2p Gossipsub, direct messaging, mDNS discovery, NAT traversal, relay |
| Cryptography | Ed25519 signing, X25519 key exchange, ChaCha20-Poly1305 AEAD |
| Identity | DID generation, key management, zeroize-protected private keys |
| Protocol | Structured messages (chat, task, resource, endorsement, system) |
| CLI | `chorus` command-line tool |
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
