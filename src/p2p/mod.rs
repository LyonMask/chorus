//! P2P Network Module — Walkie Talkie Core (Phase D: E2EE Integrated)
//!
//! Gossipsub + mDNS + Identify + Ping + **built-in CryptoLayer**.
//!
//! Key exchange is automatic: on peer connect → KeyOffer → DH → session.
//! All `send_encrypted()` calls transparently encrypt; incoming messages
//! are automatically decrypted before emitting `EncryptedMessage` events.

pub mod behaviour;
pub mod config;
pub mod envelope;
pub mod event;
pub mod handler;
pub mod network;

// ─── Public re-exports ───────────────────────────────────────────

pub use behaviour::WalkieBehaviour;
pub use config::P2PConfig;
pub use envelope::{CryptoEnvelope, WT_TOPIC};
pub use event::{Message, P2PEvent};
pub use network::P2PNetwork;

// Re-export the auto-generated behaviour event enum (for network.rs internals).
pub(crate) use behaviour::WalkieBehaviourEvent;
// P2PCommand is pub(crate) in config.rs, used directly by network.rs
