//! P2P events emitted by the swarm loop.

use libp2p::{identify, Multiaddr, PeerId};
use std::time::Duration;

use crate::identity::AgentIdentity;
use crate::protocol::AgentMessage;

/// Events emitted by `P2PNetwork`.
#[derive(Debug, Clone)]
pub enum P2PEvent {
    /// Raw (non-crypto) gossipsub message. Emits when the envelope
    /// is not a recognised CryptoEnvelope or has no session.
    RawMessage {
        from: PeerId,
        data: Vec<u8>,
    },
    /// Decrypted message from an established E2EE session.
    EncryptedMessage {
        from: PeerId,
        plaintext: Vec<u8>,
    },
    /// Decrypted structured AgentMessage (parsed from EncryptedMessage).
    StructuredMessage {
        from: PeerId,
        message: AgentMessage,
    },
    /// An encrypted session was established with a peer.
    SessionEstablished {
        peer_id: PeerId,
    },
    /// Key exchange failed.
    SessionFailed {
        peer_id: PeerId,
        reason: String,
    },
    /// Received a verified Agent identity from a peer.
    AgentIdentified {
        peer_id: PeerId,
        identity: AgentIdentity,
    },
    /// Identity verification failed.
    IdentityVerificationFailed {
        peer_id: PeerId,
        reason: String,
    },
    /// A peer connected (transport level).
    PeerConnected {
        peer_id: PeerId,
    },
    /// A peer disconnected.
    PeerDisconnected {
        peer_id: PeerId,
    },
    /// mDNS discovered a peer on the local network.
    PeerDiscovered {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    },
    /// mDNS expired a peer.
    PeerExpired {
        peer_id: PeerId,
    },
    /// Started listening on an address.
    Listening {
        address: Multiaddr,
    },
    /// Received Identify info from a peer.
    Identify {
        peer_id: PeerId,
        info: Box<identify::Info>,
    },
    /// Ping round-trip succeeded.
    PingSuccess {
        peer_id: PeerId,
        rtt: Duration,
    },
    /// Ping failed.
    PingFailure {
        peer_id: PeerId,
        error: String,
    },
}

/// Backwards compat alias.
pub use P2PEvent::RawMessage as Message;
