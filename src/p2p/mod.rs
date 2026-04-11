//! P2P Network Module — Walkie Talkie Core (Phase D: E2EE Integrated)
//!
//! Gossipsub + mDNS + Identify + Ping + **built-in CryptoLayer**.
//!
//! Key exchange is automatic: on peer connect → KeyOffer → DH → session.
//! All `send_encrypted()` calls transparently encrypt; incoming messages
//! are automatically decrypted before emitting `EncryptedMessage` events.

use libp2p::{
    gossipsub, identify, mdns, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId,
};
use std::{collections::HashMap, time::Duration};
use tokio::sync::{mpsc, oneshot};

use futures::StreamExt;

use crate::crypto::CryptoLayer;
use crate::identity::AgentIdentity;
use crate::protocol::AgentMessage;

/// Gossipsub topic for walkie-talkie messages.
pub const WT_TOPIC: &str = "/walkie-talkie/1.0.0";

fn wt_topic() -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(WT_TOPIC)
}

// ─── Wire Protocol (Crypto Envelope) ────────────────────────────
// Serialized as JSON over Gossipsub. All encrypted traffic uses this.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CryptoEnvelope {
    /// Offer our X25519 public key to start a session.
    KeyOffer {
        public_key: Vec<u8>,
    },
    /// Accept a key offer + send our own public key.
    KeyAccept {
        public_key: Vec<u8>,
    },
    /// Encrypted payload (ChaCha20-Poly1305: nonce(12) || ct+tag).
    Encrypted {
        ciphertext: Vec<u8>,
    },
    /// Agent identity claim (sent over encrypted channel after session established).
    IdentityClaim {
        #[serde(with = "crate::identity::bytes_base64")]
        identity_json: Vec<u8>,
    },
}

// ─── Events ──────────────────────────────────────────────────────

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

// Backwards compat alias
pub use P2PEvent::RawMessage as Message;

// ─── Configuration ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct P2PConfig {
    pub listen_on: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    pub enable_mdns: bool,
    pub agent_version: Option<String>,
    pub idle_timeout_secs: u64,
    pub ping_interval_secs: u64,
    pub ping_timeout_secs: u64,
    /// Auto-initiate key exchange when a peer connects.
    pub auto_key_exchange: bool,
    /// Our AgentIdentity (signed). If set, broadcast on session established.
    pub agent_identity: Option<AgentIdentity>,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
            bootstrap_peers: vec![],
            enable_mdns: true,
            agent_version: Some("walkie-talkie-core/0.2.0".to_string()),
            idle_timeout_secs: 60,
            ping_interval_secs: 15,
            ping_timeout_secs: 20,
            auto_key_exchange: true,
            agent_identity: None,
        }
    }
}

// ─── Internal Commands ──────────────────────────────────────────

enum P2PCommand {
    Listen {
        addr: String,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    Dial {
        addr: String,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    DialPeer {
        peer_id: PeerId,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    Broadcast {
        data: Vec<u8>,
        reply: oneshot::Sender<anyhow::Result<gossipsub::MessageId>>,
    },
    /// Encrypt plaintext for a specific peer and send via Gossipsub.
    SendEncrypted {
        peer_id: PeerId,
        plaintext: Vec<u8>,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Manually trigger key exchange with a peer.
    InitKeyExchange {
        peer_id: PeerId,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Send a structured AgentMessage (encrypted) to a peer.
    #[allow(dead_code)]
    #[allow(dead_code)]    SendStructured {
        peer_id: PeerId,
        message: AgentMessage,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Broadcast a structured AgentMessage (encrypted) to all peers.
    #[allow(dead_code)]
    #[allow(dead_code)]    BroadcastStructured {
        message: AgentMessage,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Check if we have an encrypted session with a peer.
    HasSession {
        peer_id: PeerId,
        reply: oneshot::Sender<bool>,
    },
    ListPeers {
        reply: oneshot::Sender<Vec<PeerId>>,
    },
    ExternalAddresses {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    Shutdown,
}

// ─── Network Behaviour ──────────────────────────────────────────

#[derive(NetworkBehaviour)]
pub struct WalkieBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

// ─── P2PNetwork Handle ──────────────────────────────────────────

#[derive(Clone)]
pub struct P2PNetwork {
    peer_id: PeerId,
    cmd_tx: mpsc::UnboundedSender<P2PCommand>,
}

impl P2PNetwork {
    /// Create a new P2P network node with integrated E2EE.
    ///
    /// Generates an X25519 keypair for this node. Key exchange is
    /// automatically initiated when peers connect (configurable).
    pub fn new(
        config: P2PConfig,
    ) -> anyhow::Result<(Self, mpsc::UnboundedReceiver<P2PEvent>)> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<P2PCommand>();

        // Generate our X25519 keypair
        let crypto = CryptoLayer::new();
        let my_keys = crypto.generate_keypair()
            .map_err(|e| anyhow::anyhow!("keypair generation: {e}"))?;

        // ── Transport: TCP + Noise + Yamux ──
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(|key: &libp2p::identity::Keypair| {
                let local_peer_id = key.public().to_peer_id();

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub::ConfigBuilder::default()
                        .validation_mode(gossipsub::ValidationMode::Strict)
                        .build()
                        .map_err(|e| anyhow::anyhow!("gossipsub: {e}"))?,
                )?;

                let agent_version = config
                    .agent_version
                    .clone()
                    .unwrap_or_else(|| "walkie-talkie-core/0.2.0".into());
                let identify = identify::Behaviour::new(
                    identify::Config::new("/walkie-talkie/id/1.0.0".into(), key.public())
                        .with_agent_version(agent_version),
                );

                let ping = ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(Duration::from_secs(config.ping_interval_secs))
                        .with_timeout(Duration::from_secs(config.ping_timeout_secs)),
                );

                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    local_peer_id,
                )?;

                Ok(WalkieBehaviour { gossipsub, identify, ping, mdns })
            })?
            .with_swarm_config(|cfg: libp2p::swarm::Config| {
                cfg.with_idle_connection_timeout(Duration::from_secs(config.idle_timeout_secs))
            })
            .build();

        let peer_id = *swarm.local_peer_id();

        swarm.behaviour_mut().gossipsub
            .subscribe(&wt_topic())
            .expect("valid topic");

        for addr_str in &config.listen_on {
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                swarm.listen_on(addr)
                    .map_err(|e| anyhow::anyhow!("listen_on {addr_str}: {e}"))?;
            }
        }

        // Bootstrap
        let bootstrap = config.bootstrap_peers.clone();
        let bootstrap_cmd_tx = cmd_tx.clone();
        if !bootstrap.is_empty() {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                for addr_str in bootstrap {
                    tracing::info!(target: "p2p", "dialing bootstrap: {addr_str}");
                    let _ = bootstrap_cmd_tx.send(P2PCommand::Dial {
                        addr: addr_str,
                        reply: oneshot::channel().0,
                    });
                }
            });
        }

        let our_peer_id = peer_id;
        let swarm_cmd_tx = cmd_tx.clone();        let auto_kx = config.auto_key_exchange;
        let agent_identity = config.agent_identity.clone();

        // ── Swarm event loop (owns CryptoLayer) ──
        tokio::spawn(async move {
            let mut crypto = crypto;
            let mut mdns_peer_addrs: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();

            loop {
                tokio::select! {
                    event = swarm.select_next_some() => {
                        match event {
                            // ── Connection lifecycle ──
                            SwarmEvent::ConnectionEstablished {
                                peer_id, endpoint, num_established, ..
                            } => {
                                tracing::info!(
                                    target: "p2p",
                                    "✓ connected to {peer_id} ({} conns, via {:?})",
                                    num_established,
                                    endpoint.get_remote_address(),
                                );
                                let _ = event_tx.send(P2PEvent::PeerConnected { peer_id });

                                // Auto key exchange with delayed retry.
                                // Gossipsub mesh needs a heartbeat cycle (~1s) before
                                // messages are reliably delivered between new peers.
                                if auto_kx {
                                    send_key_offer(&mut swarm, &my_keys, &peer_id);
                                    // Retry after mesh settles
                                    let cmd_tx_retry = swarm_cmd_tx.clone();
                                    let peer_retry = peer_id;
                                    tokio::spawn(async move {
                                        tokio::time::sleep(Duration::from_millis(800)).await;
                                        let _ = cmd_tx_retry.send(P2PCommand::InitKeyExchange {
                                            peer_id: peer_retry,
                                            reply: oneshot::channel().0,
                                        });
                                    });
                                }
                            }
                            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                                tracing::info!(target: "p2p", "✗ disconnected from {peer_id}: {cause:?}");
                                let _ = event_tx.send(P2PEvent::PeerDisconnected { peer_id });
                            }
                            SwarmEvent::NewListenAddr { address, .. } => {
                                tracing::info!(target: "p2p", "🎧 listening on {address}");
                                let _ = event_tx.send(P2PEvent::Listening { address });
                            }
                            SwarmEvent::ExpiredListenAddr { .. } => {}
                            SwarmEvent::OutgoingConnectionError {
                                peer_id: Some(peer_id), error, ..
                            } => {
                                tracing::warn!(target: "p2p", "dial error to {peer_id}: {error}");
                            }
                            SwarmEvent::IncomingConnectionError { error, .. } => {
                                tracing::warn!(target: "p2p", "incoming error: {error}");
                            }

                            // ── Gossipsub ──
                            SwarmEvent::Behaviour(WalkieBehaviourEvent::Gossipsub(
                                gossipsub::Event::Message {
                                    propagation_source, message, ..
                                },
                            )) => {
                                let from = message.source.unwrap_or(propagation_source);
                                if from == our_peer_id { return; }

                                // Try to parse as CryptoEnvelope
                                tracing::trace!(
                                    target: "crypto",
                                    "📨 gossipsub msg from {from}, {} bytes",
                                    message.data.len()
                                );
                                if let Ok(envelope) = serde_json::from_slice::<CryptoEnvelope>(&message.data) {
                                    handle_crypto_envelope(
                                        from,
                                        envelope,
                                        &mut crypto,
                                        &my_keys,
                                        &mut swarm,
                                        &event_tx,
                                        &agent_identity,
                                    );
                                } else {
                                    // Not a crypto envelope → raw message
                                    let _ = event_tx.send(P2PEvent::RawMessage {
                                        from,
                                        data: message.data,
                                    });
                                }
                            }
                            SwarmEvent::Behaviour(WalkieBehaviourEvent::Gossipsub(
                                gossipsub::Event::Subscribed { peer_id, topic },
                            )) => {
                                tracing::debug!(target: "p2p", "{peer_id} subscribed {topic}");
                            }
                            SwarmEvent::Behaviour(WalkieBehaviourEvent::Gossipsub(
                                gossipsub::Event::Unsubscribed { peer_id, topic },
                            )) => {
                                tracing::debug!(target: "p2p", "{peer_id} unsubscribed {topic}");
                            }

                            // ── Identify ──
                            SwarmEvent::Behaviour(WalkieBehaviourEvent::Identify(
                                identify::Event::Received { peer_id, info, .. },
                            )) => {
                                tracing::info!(
                                    target: "p2p",
                                    "🔐 identified {peer_id}: agent={}",
                                    info.agent_version,
                                );
                                let _ = event_tx.send(P2PEvent::Identify {
                                    peer_id, info: Box::new(info),
                                });
                            }
                            SwarmEvent::Behaviour(WalkieBehaviourEvent::Identify(
                                identify::Event::Pushed { .. },
                            )) | SwarmEvent::Behaviour(WalkieBehaviourEvent::Identify(
                                identify::Event::Sent { .. },
                            )) => {}

                            // ── Ping ──
                            SwarmEvent::Behaviour(WalkieBehaviourEvent::Ping(
                                ping::Event { peer, result: Ok(rtt), .. },
                            )) => {
                                tracing::trace!(target: "p2p", "🏓 ping {peer}: {rtt:?}");
                                let _ = event_tx.send(P2PEvent::PingSuccess { peer_id: peer, rtt });
                            }
                            SwarmEvent::Behaviour(WalkieBehaviourEvent::Ping(
                                ping::Event { peer, result: Err(error), .. },
                            )) => {
                                tracing::warn!(target: "p2p", "🏓 ping FAIL {peer}: {error}");
                                let _ = event_tx.send(P2PEvent::PingFailure {
                                    peer_id: peer, error: error.to_string(),
                                });
                            }

                            // ── mDNS ──
                            SwarmEvent::Behaviour(WalkieBehaviourEvent::Mdns(
                                mdns::Event::Discovered(list),
                            )) => {
                                for (pid, addr) in list {
                                    mdns_peer_addrs.entry(pid).or_default().push(addr.clone());
                                    let addrs = mdns_peer_addrs.get(&pid).cloned().unwrap_or_default();
                                    let _ = event_tx.send(P2PEvent::PeerDiscovered { peer_id: pid, addresses: addrs });
                                }
                            }
                            SwarmEvent::Behaviour(WalkieBehaviourEvent::Mdns(
                                mdns::Event::Expired(list),
                            )) => {
                                for (pid, _addr) in list {
                                    mdns_peer_addrs.remove(&pid);
                                    let _ = event_tx.send(P2PEvent::PeerExpired { peer_id: pid });
                                }
                            }

                            _ => {}
                        }
                    }

                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(P2PCommand::Listen { addr, reply }) => {
                                let result = match addr.parse::<Multiaddr>() {
                                    Ok(a) => swarm.listen_on(a).map_err(|e| anyhow::anyhow!("{e}")),
                                    Err(e) => Err(anyhow::anyhow!("parse: {e}")),
                                };
                                let _ = reply.send(result.map(|_| ()));
                            }
                            Some(P2PCommand::Dial { addr, reply }) => {
                                let result = match addr.parse::<Multiaddr>() {
                                    Ok(a) => swarm.dial(a).map_err(|e| anyhow::anyhow!("{e}")),
                                    Err(e) => Err(anyhow::anyhow!("parse: {e}")),
                                };
                                let _ = reply.send(result);
                            }
                            Some(P2PCommand::DialPeer { peer_id: target, reply }) => {
                                let result = mdns_peer_addrs.get(&target)
                                    .and_then(|addrs| addrs.first())
                                    .ok_or_else(|| anyhow::anyhow!("no mdns addr for {target}"))
                                    .and_then(|addr| swarm.dial(addr.clone()).map_err(|e| anyhow::anyhow!("{e}")));
                                let _ = reply.send(result);
                            }
                            Some(P2PCommand::Broadcast { data, reply }) => {
                                let result = swarm.behaviour_mut().gossipsub.publish(wt_topic(), data);
                                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
                            }
                            Some(P2PCommand::SendEncrypted { peer_id: target, plaintext, reply }) => {
                                let peer_str = target.to_string();
                                let result = crypto.encrypt_for(&peer_str, &plaintext)
                                    .map_err(|e| anyhow::anyhow!("{e}"))
                                    .and_then(|ciphertext| {
                                        let envelope = CryptoEnvelope::Encrypted { ciphertext };
                                        serde_json::to_vec(&envelope)
                                            .map_err(|e| anyhow::anyhow!("serialize: {e}"))
                                    })
                                    .and_then(|bytes| {
                                        swarm.behaviour_mut().gossipsub.publish(wt_topic(), bytes)
                                            .map_err(|e| anyhow::anyhow!("{e}"))
                                    });
                                let _ = reply.send(result.map(|_| ()));
                            }
                            Some(P2PCommand::InitKeyExchange { peer_id: _target, reply }) => {
                                let envelope = CryptoEnvelope::KeyOffer {
                                    public_key: my_keys.public.clone(),
                                };
                                let result = serde_json::to_vec(&envelope)
                                    .map_err(|e| anyhow::anyhow!("serialize: {e}"))
                                    .and_then(|bytes| {
                                        swarm.behaviour_mut().gossipsub.publish(wt_topic(), bytes)
                                            .map_err(|e| anyhow::anyhow!("{e}"))
                                    });
                                let _ = reply.send(result.map(|_| ()));
                            }
    #[allow(dead_code)]                            Some(P2PCommand::SendStructured { peer_id: target, message, reply }) => {
                                let result = (|| -> anyhow::Result<()> {
                                    let plaintext = message.to_json_bytes()?;
                                    let peer_str = target.to_string();
                                    let ciphertext = crypto.encrypt_for(&peer_str, &plaintext)
                                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                                    let envelope = CryptoEnvelope::Encrypted { ciphertext };
                                    let bytes = serde_json::to_vec(&envelope)?;
                                    swarm.behaviour_mut().gossipsub.publish(wt_topic(), bytes)
                                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                                    Ok(())
                                })();
                                let _ = reply.send(result);
                            }
    #[allow(dead_code)]                            Some(P2PCommand::BroadcastStructured { message, reply }) => {
                                let result = (|| -> anyhow::Result<()> {
                                    let plaintext = message.to_json_bytes()?;
                                    let peers: Vec<PeerId> = swarm.connected_peers().copied().collect();
                                    for peer in &peers {
                                        if peer == &our_peer_id { continue; }
                                        let peer_str = peer.to_string();
                                        if crypto.has_session(&peer_str) {
                                            if let Ok(ciphertext) = crypto.encrypt_for(&peer_str, &plaintext) {
                                                let envelope = CryptoEnvelope::Encrypted { ciphertext };
                                                if let Ok(bytes) = serde_json::to_vec(&envelope) {
                                                    let _ = swarm.behaviour_mut().gossipsub.publish(wt_topic(), bytes);
                                                }
                                            }
                                        }
                                    }
                                    Ok(())
                                })();
                                let _ = reply.send(result);
                            }
                            Some(P2PCommand::HasSession { peer_id: target, reply }) => {
                                let _ = reply.send(crypto.has_session(&target.to_string()));
                            }
                            Some(P2PCommand::ListPeers { reply }) => {
                                let peers: Vec<PeerId> = swarm.connected_peers().copied().collect();
                                let _ = reply.send(peers);
                            }
                            Some(P2PCommand::ExternalAddresses { reply }) => {
                                let addrs: Vec<Multiaddr> = swarm.external_addresses().cloned().collect();
                                let _ = reply.send(addrs);
                            }
                            Some(P2PCommand::Shutdown) | None => {
                                tracing::info!(target: "p2p", "swarm shutdown");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok((Self { peer_id, cmd_tx }, event_rx))
    }

    /// Create with default config.
    pub fn new_default() -> anyhow::Result<(Self, mpsc::UnboundedReceiver<P2PEvent>)> {
        Self::new(P2PConfig::default())
    }

    // ── Public async API ──

    pub async fn listen(&self, addr: &str) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::Listen { addr: addr.to_string(), reply })?;
        rx.await?
    }

    pub async fn dial(&self, addr: &str) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::Dial { addr: addr.to_string(), reply })?;
        rx.await?
    }

    pub async fn dial_peer(&self, peer_id: PeerId) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::DialPeer { peer_id, reply })?;
        rx.await?
    }

    /// Broadcast raw bytes (no encryption).
    pub async fn broadcast(&self, data: Vec<u8>) -> anyhow::Result<gossipsub::MessageId> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::Broadcast { data, reply })?;
        rx.await?
    }

    /// Encrypt and send a plaintext message to a specific peer.
    /// Requires an established E2EE session (auto via auto_key_exchange).
    pub async fn send_encrypted(&self, peer_id: PeerId, plaintext: Vec<u8>) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::SendEncrypted { peer_id, plaintext, reply })?;
        rx.await?
    }

    /// Manually trigger key exchange with a peer.
    pub async fn init_key_exchange(&self, peer_id: PeerId) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::InitKeyExchange { peer_id, reply })?;
        rx.await?
    }

    /// Check if an encrypted session exists with a peer.
    pub async fn has_session(&self, peer_id: &PeerId) -> anyhow::Result<bool> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::HasSession { peer_id: *peer_id, reply })?;
        Ok(rx.await?)
    }

    pub async fn list_peers(&self) -> anyhow::Result<Vec<PeerId>> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::ListPeers { reply })?;
        Ok(rx.await?)
    }

    pub async fn external_addresses(&self) -> anyhow::Result<Vec<Multiaddr>> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::ExternalAddresses { reply })?;
        Ok(rx.await?)
    }

    pub fn shutdown(&self) -> anyhow::Result<()> {
        self.cmd_tx.send(P2PCommand::Shutdown)?;
        Ok(())
    }

    pub fn local_peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}


// Send a KeyOffer to a peer via Gossipsub.
fn send_key_offer(
    swarm: &mut libp2p::Swarm<WalkieBehaviour>,
    my_keys: &crate::crypto::KeyPair,
    peer_id: &PeerId,
) {
    if let Ok(envelope_bytes) = serde_json::to_vec(
        &CryptoEnvelope::KeyOffer {
            public_key: my_keys.public.clone(),
        },
    ) {
        if swarm.behaviour_mut().gossipsub.publish(wt_topic(), envelope_bytes).is_ok() {
            tracing::info!(target: "crypto", "🔑 sent KeyOffer to {peer_id}");
        }
    }
}

// ─── Crypto Envelope Handler ────────────────────────────────────
// Runs inside the swarm loop. Handles key exchange and decryption.

fn handle_crypto_envelope(
    from: PeerId,
    envelope: CryptoEnvelope,
    crypto: &mut CryptoLayer,
    my_keys: &crate::crypto::KeyPair,
    swarm: &mut libp2p::Swarm<WalkieBehaviour>,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    agent_identity: &Option<AgentIdentity>,
) {
    let peer_str = from.to_string();

    match envelope {
        CryptoEnvelope::KeyOffer { public_key } => {
            tracing::info!(target: "crypto", "🔑 KeyOffer from {from}");
            match CryptoLayer::diffie_hellman(my_keys.private_key(), &public_key) {
                Ok(shared) => {
                    let already = crypto.has_session(&peer_str);
                    crypto.create_session(&peer_str, &shared);
                    tracing::info!(target: "crypto", "🔒 session with {from} {}", if already { "refreshed" } else { "created" });
                    let _ = event_tx.send(P2PEvent::SessionEstablished { peer_id: from });

                    // Send our AgentIdentity if configured
                    if let Some(ref our_identity) = agent_identity {
                        if let Ok(id_json) = serde_json::to_vec(our_identity) {
                            let claim = CryptoEnvelope::Encrypted { ciphertext: id_json };
                            if let Ok(bytes) = serde_json::to_vec(&claim) {
                                let _ = swarm.behaviour_mut().gossipsub.publish(wt_topic(), bytes);
                                tracing::info!(target: "identity", "🪪 sent our identity to {from}");
                            }
                        }
                    }

                    // Send KeyAccept (our public key back) to establish bidirectional session
                    let accept = CryptoEnvelope::KeyAccept {
                        public_key: my_keys.public.clone(),
                    };
                    if let Ok(bytes) = serde_json::to_vec(&accept) {
                        let _ = swarm.behaviour_mut().gossipsub.publish(wt_topic(), bytes);
                    }
                }
                Err(e) => {
                    tracing::error!(target: "crypto", "DH failed with {from}: {e}");
                    let _ = event_tx.send(P2PEvent::SessionFailed {
                        peer_id: from,
                        reason: format!("DH failed: {e}"),
                    });
                }
            }
        }

        CryptoEnvelope::KeyAccept { public_key } => {
            tracing::info!(target: "crypto", "🔑 KeyAccept from {from}");
            match CryptoLayer::diffie_hellman(my_keys.private_key(), &public_key) {
                Ok(shared) => {
                    let already = crypto.has_session(&peer_str);
                    crypto.create_session(&peer_str, &shared);
                    tracing::info!(target: "crypto", "🔒 session with {from} {}", if already { "refreshed" } else { "established" });
                    let _ = event_tx.send(P2PEvent::SessionEstablished { peer_id: from });
                }
                Err(e) => {
                    tracing::error!(target: "crypto", "DH failed with {from}: {e}");
                    let _ = event_tx.send(P2PEvent::SessionFailed {
                        peer_id: from,
                        reason: format!("DH failed: {e}"),
                    });
                }
            }
        }

        CryptoEnvelope::Encrypted { ciphertext } => {
            match crypto.decrypt_from(&peer_str, &ciphertext) {
                Ok(plaintext) => {
                    tracing::trace!(target: "crypto", "🔓 decrypted {} bytes from {from}", plaintext.len());
                    // Check if plaintext is an identity claim
                    if let Ok(identity) = serde_json::from_slice::<AgentIdentity>(&plaintext) {
                        match identity.verify() {
                            Ok(()) => {
                                tracing::info!(target: "identity", "🪪 verified agent '{}' from {from}", identity.display_name);
                                let _ = event_tx.send(P2PEvent::AgentIdentified {
                                    peer_id: from,
                                    identity,
                                });
                            }
                            Err(e) => {
                                tracing::warn!(target: "identity", "🪪 identity verification failed from {from}: {e}");
                                let _ = event_tx.send(P2PEvent::IdentityVerificationFailed {
                                    peer_id: from,
                                    reason: e.to_string(),
                                });
                            }
                        }
                    } else if let Ok(agent_msg) = serde_json::from_slice::<AgentMessage>(&plaintext) {
                        tracing::info!(target: "protocol", "📋 structured [{}] from {}", agent_msg.protocol.tag(), agent_msg.from_agent.display_name);
                        let _ = event_tx.send(P2PEvent::StructuredMessage {
                            from,
                            message: agent_msg,
                        });
                    } else {
                        let _ = event_tx.send(P2PEvent::EncryptedMessage { from, plaintext });
                    }
                }
                Err(e) => {
                    tracing::warn!(target: "crypto", "🔓 decrypt failed from {from}: {e}");
                    let _ = event_tx.send(P2PEvent::SessionFailed {
                        peer_id: from,
                        reason: format!("decrypt: {e}"),
                    });
                }
            }
        }

        CryptoEnvelope::IdentityClaim { identity_json } => {
            // Standalone identity claim (not encrypted — for future use when
            // identity exchange happens before E2EE is established).
            match serde_json::from_slice::<AgentIdentity>(&identity_json) {
                Ok(identity) => match identity.verify() {
                    Ok(()) => {
                        tracing::info!(target: "identity", "🪪 verified agent '{}' from {from}", identity.display_name);
                        let _ = event_tx.send(P2PEvent::AgentIdentified {
                            peer_id: from,
                            identity,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(target: "identity", "🪪 identity verification failed from {from}: {e}");
                        let _ = event_tx.send(P2PEvent::IdentityVerificationFailed {
                            peer_id: from,
                            reason: e.to_string(),
                        });
                    }
                },
                Err(e) => {
                    tracing::warn!(target: "identity", "🪪 invalid identity JSON from {from}: {e}");
                }
            }
        }
    }
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

    #[test]
    fn test_crypto_envelope_serialization() {
        let offer = CryptoEnvelope::KeyOffer {
            public_key: vec![1u8; 32],
        };
        let bytes = serde_json::to_vec(&offer).unwrap();
        let decoded: CryptoEnvelope = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            CryptoEnvelope::KeyOffer { public_key } => assert_eq!(public_key.len(), 32),
            _ => panic!("wrong variant"),
        }

        let enc = CryptoEnvelope::Encrypted {
            ciphertext: vec![0u8; 28], // nonce(12) + tag(16)
        };
        let bytes = serde_json::to_vec(&enc).unwrap();
        let decoded: CryptoEnvelope = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            CryptoEnvelope::Encrypted { ciphertext } => assert_eq!(ciphertext.len(), 28),
            _ => panic!("wrong variant"),
        }
    }
}
