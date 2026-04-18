//! P2P events emitted by the swarm loop.

use libp2p::{identify, Multiaddr, PeerId};
use std::time::Duration;

use crate::identity::AgentIdentity;
use crate::protocol::AgentMessage;
use crate::resource::{ResourceAdvertisement, ResourceOffer, ResourceValidationError};

use super::direct::{DirectPayload, DirectResponse};

/// Events emitted by `P2PNetwork`.
#[derive(Debug, Clone)]
pub enum P2PEvent {
    /// Raw (non-crypto) gossipsub message. Emits when the envelope
    /// is not a recognised CryptoEnvelope or has no session.
    RawMessage { from: PeerId, data: Vec<u8> },
    /// Decrypted message from an established E2EE session.
    EncryptedMessage { from: PeerId, plaintext: Vec<u8> },
    /// Decrypted structured AgentMessage (parsed from EncryptedMessage).
    StructuredMessage { from: PeerId, message: AgentMessage },
    /// An encrypted session was established with a peer.
    SessionEstablished { peer_id: PeerId },
    /// Key exchange failed.
    SessionFailed { peer_id: PeerId, reason: String },
    /// Received a verified Agent identity from a peer.
    AgentIdentified {
        peer_id: PeerId,
        identity: AgentIdentity,
    },
    /// Identity verification failed.
    IdentityVerificationFailed { peer_id: PeerId, reason: String },
    /// A peer connected (transport level).
    PeerConnected { peer_id: PeerId },
    /// A peer disconnected.
    PeerDisconnected { peer_id: PeerId },
    /// mDNS discovered a peer on the local network.
    PeerDiscovered {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    },
    /// mDNS expired a peer.
    PeerExpired { peer_id: PeerId },
    /// Started listening on an address.
    Listening { address: Multiaddr },
    /// Received Identify info from a peer.
    Identify {
        peer_id: PeerId,
        info: Box<identify::Info>,
    },
    /// Ping round-trip succeeded.
    PingSuccess { peer_id: PeerId, rtt: Duration },
    /// Ping failed.
    PingFailure { peer_id: PeerId, error: String },
    /// ── Direct channel events (P0-3) ──

    /// Incoming direct request from a peer (payload already parsed).
    DirectMessage {
        from: PeerId,
        request_id: u64,
        payload: DirectPayload,
    },
    /// Direct request to a peer failed (peer not connected or send error).
    DirectSendFailed { peer_id: PeerId, reason: String },
    /// Response received for a direct request we sent.
    DirectResponse {
        from: PeerId,
        response: DirectResponse,
    },
    /// Pending messages were drained and sent to a peer that just connected.
    PendingMessagesSent { peer_id: PeerId, count: usize },
    /// ── Resource declaration events (P2P integration) ──

    /// Received and validated a resource declaration from a peer.
    ResourceDeclared {
        peer_id: PeerId,
        advertisement: ResourceAdvertisement,
    },
    /// A resource declaration from a peer failed validation.
    ResourceDeclarationRejected {
        peer_id: PeerId,
        reason: ResourceValidationError,
    },

    /// ── Resource request flow events (Phase 3) ──

    /// We sent a resource offer to a peer.
    ResourceOfferSent { peer_id: PeerId, session_id: String },
    /// Received a resource offer from a provider.
    ResourceOfferReceived {
        peer_id: PeerId,
        offer: ResourceOffer,
    },
    /// A resource session has been started.
    ResourceSessionStarted {
        peer_id: PeerId,
        session_id: String,
        expires_at: u64,
    },
    /// A resource session has been released with contribution delta.
    ResourceReleased {
        peer_id: PeerId,
        session_id: String,
        contribution_delta: f64,
    },
    /// PeerId↔DID binding cryptographically verified (Phase 4).
    IdentityAttestationVerified { peer_id: PeerId, did: String },
    /// A resource request failed (no matching provider).
    ResourceRequestFailed { peer_id: PeerId, reason: String },

    /// ── Relay / NAT traversal events ──

    /// Relay reservation accepted — we can now be reached via this relay.
    RelayReservationAccepted { relay_peer_id: String },
    /// A relayed connection was upgraded to a direct connection (hole punching succeeded).
    RelayConnectionUpgraded { peer_id: PeerId },
}

/// Backwards compat alias.
pub use P2PEvent::RawMessage as Message;
