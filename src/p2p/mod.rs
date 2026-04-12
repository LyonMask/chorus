//! P2P Network Module — Walkie Talkie Core (Phase P0-3: Direct Channel + P2P Resource Integration)
//!
//! Gossipsub + mDNS + Identify + Ping + **Direct Channel** + built-in CryptoLayer.
//!
//! Key exchange and point-to-point messages go through the Direct channel
//! (libp2p request-response protocol). Gossipsub is retained for broadcast
//! only (heartbeat, presence, group messages).
//!
//! Resource declarations are exchanged via Direct channel (not Gossipsub)
//! after E2EE session establishment.

pub mod behaviour;
pub mod config;
pub mod direct;
pub mod envelope;
pub mod event;
pub mod handler;
pub mod network;

// ─── Public re-exports ───────────────────────────────────────────

pub use behaviour::WalkieBehaviour;
pub use config::P2PConfig;
pub use direct::{
    DirectCodec, DirectPayload, DirectRequest, DirectResponse, DirectResponseStatus,
    PendingMessageStore, WT_DIRECT_PROTOCOL,
};
pub use envelope::{CryptoEnvelope, WT_TOPIC};
pub use event::{Message, P2PEvent};
pub use network::P2PNetwork;

// Re-export the auto-generated behaviour event enum (for network.rs internals).
pub(crate) use behaviour::WalkieBehaviourEvent;
