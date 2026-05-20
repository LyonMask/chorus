//! P2P configuration and internal commands.

use super::direct::DirectRequest;
use crate::identity::AgentIdentity;
use crate::protocol::AgentMessage;

// ─── Configuration ───────────────────────────────────────────────

/// P2P network configuration.
#[derive(Debug, Clone)]
pub struct P2PConfig {
    pub listen_on: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    /// Relay peer multiaddresses (e.g. "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...").
    /// Connected on startup to enable NAT traversal fallback.
    pub relay_peers: Vec<String>,
    /// Act as a relay server — accept reservations and relay traffic for other peers.
    pub relay_server: bool,
    pub enable_mdns: bool,
    pub agent_version: Option<String>,
    pub idle_timeout_secs: u64,
    pub ping_interval_secs: u64,
    pub ping_timeout_secs: u64,
    /// Auto-initiate key exchange when a peer connects.
    pub auto_key_exchange: bool,
    /// Our AgentIdentity (signed). If set, broadcast on session established.
    pub agent_identity: Option<AgentIdentity>,
    /// Ed25519 signing key for message authentication.
    pub signing_key: Option<std::sync::Arc<ed25519_dalek::SigningKey>>,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
            bootstrap_peers: vec![],
            relay_peers: vec![],
            relay_server: false,
            enable_mdns: true,
            agent_version: Some("chorus-core/0.1.0-alpha".to_string()),
            idle_timeout_secs: 60,
            ping_interval_secs: 15,
            ping_timeout_secs: 20,
            auto_key_exchange: true,
            agent_identity: None,
            signing_key: None,
        }
    }
}

// ─── Internal Commands ──────────────────────────────────────────

/// Commands sent from `P2PNetwork` to the swarm loop.
pub(crate) enum P2PCommand {
    Listen {
        addr: String,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    },
    Dial {
        addr: String,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    },
    DialPeer {
        peer_id: libp2p::PeerId,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    },
    Broadcast {
        data: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<libp2p::gossipsub::MessageId>>,
    },
    /// Encrypt plaintext for a specific peer and send via Direct channel.
    SendEncrypted {
        peer_id: libp2p::PeerId,
        plaintext: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    },
    /// Manually trigger key exchange with a peer (via Direct channel).
    InitKeyExchange {
        peer_id: libp2p::PeerId,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    },
    /// Send a structured AgentMessage (encrypted) to a peer.
    #[allow(dead_code)]
    SendStructured {
        peer_id: libp2p::PeerId,
        message: AgentMessage,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    },
    /// Broadcast a structured AgentMessage (encrypted) to all peers.
    #[allow(dead_code)]
    BroadcastStructured {
        message: AgentMessage,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    },
    /// Send a pre-built DirectRequest to a peer via Direct channel.
    #[allow(dead_code)]
    SendDirect {
        peer_id: libp2p::PeerId,
        request: DirectRequest,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    },
    /// Check if we have an encrypted session with a peer.
    HasSession {
        peer_id: libp2p::PeerId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// Check if a peer is currently connected.
    IsConnected {
        peer_id: libp2p::PeerId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    ListPeers {
        reply: tokio::sync::oneshot::Sender<Vec<libp2p::PeerId>>,
    },
    ExternalAddresses {
        reply: tokio::sync::oneshot::Sender<Vec<libp2p::Multiaddr>>,
    },
    Shutdown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = P2PConfig::default();
        assert!(config.enable_mdns);
        assert!(config.auto_key_exchange);
        assert_eq!(config.listen_on.len(), 1);
    }
}
