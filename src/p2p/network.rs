//! P2PNetwork — public API and swarm event loop.
//!
//! This is the main entry point for P2P networking. `P2PNetwork::new()`
//! spawns the swarm loop in a background tokio task and returns a handle
//! (`P2PNetwork`) for sending commands and an event receiver.

use libp2p::{gossipsub, identify, mdns, ping, request_response, Multiaddr, PeerId};
use std::{collections::HashMap, time::Duration};
use tokio::sync::{mpsc, oneshot};

use futures::StreamExt;

use crate::crypto::CryptoLayer;

use super::behaviour::WalkieBehaviour;
use super::config::{P2PCommand, P2PConfig};
use super::direct::{self, PendingMessageStore};
use super::envelope::{CryptoEnvelope, WT_TOPIC};
use super::event::P2PEvent;
use super::handler;

fn wt_topic() -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(WT_TOPIC)
}

// ─── P2PNetwork Handle ──────────────────────────────────────────

#[derive(Clone)]
pub struct P2PNetwork {
    peer_id: PeerId,
    cmd_tx: mpsc::UnboundedSender<P2PCommand>,
}

impl P2PNetwork {
    /// Create a new P2P network node with integrated E2EE.
    pub fn new(
        config: P2PConfig,
    ) -> anyhow::Result<(Self, mpsc::UnboundedReceiver<P2PEvent>)> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<P2PCommand>();

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
                    .unwrap_or_else(|| "walkie-talkie-core/0.3.0".into());
                let identify = identify::Behaviour::new(
                    identify::Config::new("/walkie-talkie/id/1.0.0".into(), key.public())
                        .with_agent_version(agent_version),
                );

                let ping_behaviour = ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(Duration::from_secs(config.ping_interval_secs))
                        .with_timeout(Duration::from_secs(config.ping_timeout_secs)),
                );

                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    local_peer_id,
                )?;

                let direct = direct::new_direct_behaviour();

                Ok(WalkieBehaviour { gossipsub, identify, ping: ping_behaviour, mdns, direct })
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

        // Bootstrap dial
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
        let swarm_cmd_tx = cmd_tx.clone();
        let auto_kx = config.auto_key_exchange;
        let agent_identity = config.agent_identity.clone();

        // ── Swarm event loop ──
        tokio::spawn(async move {
            let mut crypto = crypto;
            let pending_store = PendingMessageStore::new();
            let mut mdns_peer_addrs: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();

            loop {
                tokio::select! {
                    event = swarm.select_next_some() => {
                        match event {
                            // ── Connection lifecycle ──
                            libp2p::swarm::SwarmEvent::ConnectionEstablished {
                                peer_id, endpoint, num_established, ..
                            } => {
                                tracing::info!(
                                    target: "p2p",
                                    "✓ connected to {peer_id} ({} conns, via {:?})",
                                    num_established, endpoint.get_remote_address(),
                                );
                                let _ = event_tx.send(P2PEvent::PeerConnected { peer_id });

                                // P0-3: Drain pending messages
                                if let Some(messages) = pending_store.drain(&peer_id) {
                                    let count = messages.len();
                                    tracing::info!(target: "p2p", "📤 draining {count} pending messages for {peer_id}");
                                    for msg in messages {
                                        swarm.behaviour_mut().direct.send_request(&peer_id, msg);
                                    }
                                    let _ = event_tx.send(P2PEvent::PendingMessagesSent { peer_id, count });
                                }

                                // Auto key exchange via Direct channel
                                if auto_kx {
                                    handler::send_key_offer(&mut swarm, &my_keys, &peer_id);
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
                            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                                tracing::info!(target: "p2p", "✗ disconnected from {peer_id}: {cause:?}");
                                let _ = event_tx.send(P2PEvent::PeerDisconnected { peer_id });
                            }
                            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                                tracing::info!(target: "p2p", "🎧 listening on {address}");
                                let _ = event_tx.send(P2PEvent::Listening { address });
                            }
                            libp2p::swarm::SwarmEvent::ExpiredListenAddr { .. } => {}
                            libp2p::swarm::SwarmEvent::OutgoingConnectionError {
                                peer_id: Some(peer_id), error, ..
                            } => {
                                tracing::warn!(target: "p2p", "dial error to {peer_id}: {error}");
                            }
                            libp2p::swarm::SwarmEvent::IncomingConnectionError { error, .. } => {
                                tracing::warn!(target: "p2p", "incoming error: {error}");
                            }

                            // ── Gossipsub (broadcast + legacy) ──
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Gossipsub(
                                    gossipsub::Event::Message {
                                        propagation_source, message, ..
                                    },
                                ),
                            ) => {
                                let from = message.source.unwrap_or(propagation_source);
                                if from == our_peer_id { continue; }
                                tracing::trace!(target: "crypto", "📨 gossipsub msg from {from}, {} bytes", message.data.len());
                                if let Ok(envelope) = serde_json::from_slice::<CryptoEnvelope>(&message.data) {
                                    handler::handle_crypto_envelope(
                                        from, envelope, &mut crypto, &my_keys,
                                        &mut swarm, &event_tx, &agent_identity,
                                    );
                                } else {
                                    let _ = event_tx.send(P2PEvent::RawMessage { from, data: message.data });
                                }
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Gossipsub(
                                    gossipsub::Event::Subscribed { peer_id, topic },
                                ),
                            ) => { tracing::debug!(target: "p2p", "{peer_id} subscribed {topic}"); }
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Gossipsub(
                                    gossipsub::Event::Unsubscribed { peer_id, topic },
                                ),
                            ) => { tracing::debug!(target: "p2p", "{peer_id} unsubscribed {topic}"); }

                            // ── Direct channel (P0-3) ──
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Direct(
                                    request_response::Event::Message {
                                        peer,
                                        message: request_response::Message::Request { request, channel, .. },
                                        ..
                                    },
                                ),
                            ) => {
                                tracing::trace!(target: "p2p", "📨 direct request from {peer}: request_id={}", request.request_id);
                                let response = handler::handle_direct_request(
                                    peer, request, &mut crypto, &my_keys,
                                    &mut swarm, &event_tx, &agent_identity,
                                );
                                let _ = swarm.behaviour_mut().direct.send_response(channel, response);
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Direct(
                                    request_response::Event::Message {
                                        peer,
                                        message: request_response::Message::Response { request_id, response, .. },
                                        ..
                                    },
                                ),
                            ) => {
                                tracing::trace!(target: "p2p", "📨 direct response from {peer}: request_id={request_id}, status={:?}", response.status);
                                let _ = event_tx.send(P2PEvent::DirectResponse { from: peer, response });
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Direct(
                                    request_response::Event::OutboundFailure { peer, request_id, error, .. },
                                ),
                            ) => {
                                tracing::warn!(target: "p2p", "📤 direct send failed to {peer}: request_id={request_id}, error={error}");
                                let _ = event_tx.send(P2PEvent::DirectSendFailed {
                                    peer_id: peer,
                                    reason: format!("outbound failure: {error}"),
                                });
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Direct(
                                    request_response::Event::InboundFailure { peer, error, .. },
                                ),
                            ) => {
                                tracing::warn!(target: "p2p", "📥 direct inbound failure from {peer}: {error}");
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Direct(
                                    request_response::Event::ResponseSent { peer, .. },
                                ),
                            ) => {
                                tracing::trace!(target: "p2p", "📨 direct response sent to {peer}");
                            }

                            // ── Identify ──
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Identify(
                                    identify::Event::Received { peer_id, info, .. },
                                ),
                            ) => {
                                tracing::info!(target: "p2p", "🔐 identified {peer_id}: agent={}", info.agent_version);
                                let _ = event_tx.send(P2PEvent::Identify { peer_id, info: Box::new(info) });
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Identify(identify::Event::Pushed { .. })
                            ) | libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Identify(identify::Event::Sent { .. })
                            ) => {}

                            // ── Ping ──
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Ping(ping::Event { peer, result: Ok(rtt), .. }),
                            ) => {
                                tracing::trace!(target: "p2p", "🏓 ping {peer}: {rtt:?}");
                                let _ = event_tx.send(P2PEvent::PingSuccess { peer_id: peer, rtt });
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Ping(ping::Event { peer, result: Err(error), .. }),
                            ) => {
                                let err_str = error.to_string();
                                tracing::warn!(target: "p2p", "🏓 ping FAIL {peer}: {err_str}");
                                let _ = event_tx.send(P2PEvent::PingFailure { peer_id: peer, error: err_str });
                            }

                            // ── mDNS ──
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Mdns(mdns::Event::Discovered(list)),
                            ) => {
                                for (pid, addr) in list {
                                    mdns_peer_addrs.entry(pid).or_default().push(addr.clone());
                                    let addrs = mdns_peer_addrs.get(&pid).cloned().unwrap_or_default();
                                    let _ = event_tx.send(P2PEvent::PeerDiscovered { peer_id: pid, addresses: addrs });
                                }
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(
                                super::WalkieBehaviourEvent::Mdns(mdns::Event::Expired(list)),
                            ) => {
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

                            // Broadcast: stays on Gossipsub
                            Some(P2PCommand::Broadcast { data, reply }) => {
                                let result = swarm.behaviour_mut().gossipsub.publish(wt_topic(), data);
                                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
                            }

                            // P0-3: SendEncrypted → Direct channel
                            Some(P2PCommand::SendEncrypted { peer_id: target, plaintext, reply }) => {
                                let result = (|| -> anyhow::Result<()> {
                                    let peer_str = target.to_string();
                                    let ciphertext = crypto.encrypt_for(&peer_str, &plaintext)
                                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                                    let request = direct::encrypted_request(ciphertext);
                                    if swarm.is_connected(&target) {
                                        swarm.behaviour_mut().direct.send_request(&target, request);
                                    } else {
                                        if !pending_store.store(target, request) {
                                            return Err(anyhow::anyhow!("pending queue full for {target}"));
                                        }
                                    }
                                    Ok(())
                                })();
                                let _ = reply.send(result);
                            }

                            // P0-3: InitKeyExchange → Direct channel
                            Some(P2PCommand::InitKeyExchange { peer_id: target, reply }) => {
                                let request = direct::key_offer_request(my_keys.public.clone());
                                let result = (|| -> anyhow::Result<()> {
                                    if swarm.is_connected(&target) {
                                        swarm.behaviour_mut().direct.send_request(&target, request);
                                    } else {
                                        if !pending_store.store(target, request) {
                                            return Err(anyhow::anyhow!("pending queue full for {target}"));
                                        }
                                    }
                                    Ok(())
                                })();
                                let _ = reply.send(result);
                            }

                            // P0-3: SendStructured → Direct channel
                            Some(P2PCommand::SendStructured { peer_id: target, message, reply }) => {
                                let result = (|| -> anyhow::Result<()> {
                                    let plaintext = message.to_json_bytes()?;
                                    let peer_str = target.to_string();
                                    let ciphertext = crypto.encrypt_for(&peer_str, &plaintext)
                                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                                    let request = direct::encrypted_request(ciphertext);
                                    if swarm.is_connected(&target) {
                                        swarm.behaviour_mut().direct.send_request(&target, request);
                                    } else {
                                        if !pending_store.store(target, request) {
                                            return Err(anyhow::anyhow!("pending queue full for {target}"));
                                        }
                                    }
                                    Ok(())
                                })();
                                let _ = reply.send(result);
                            }

                            // BroadcastStructured: stays on Gossipsub
                            Some(P2PCommand::BroadcastStructured { message, reply }) => {
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

                            // P0-3: SendDirect (pre-built request)
                            Some(P2PCommand::SendDirect { peer_id: target, request, reply }) => {
                                let result = (|| -> anyhow::Result<()> {
                                    if swarm.is_connected(&target) {
                                        swarm.behaviour_mut().direct.send_request(&target, request);
                                    } else {
                                        if !pending_store.store(target, request) {
                                            return Err(anyhow::anyhow!("pending queue full for {target}"));
                                        }
                                    }
                                    Ok(())
                                })();
                                let _ = reply.send(result);
                            }

                            Some(P2PCommand::HasSession { peer_id: target, reply }) => {
                                let _ = reply.send(crypto.has_session(&target.to_string()));
                            }
                            Some(P2PCommand::IsConnected { peer_id: target, reply }) => {
                                let _ = reply.send(swarm.is_connected(&target));
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

    /// Broadcast raw bytes (no encryption) via Gossipsub.
    pub async fn broadcast(&self, data: Vec<u8>) -> anyhow::Result<gossipsub::MessageId> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::Broadcast { data, reply })?;
        rx.await?
    }

    /// Encrypt and send a plaintext message to a specific peer via Direct channel.
    /// If peer is offline, message is stored for delivery on reconnect.
    pub async fn send_encrypted(&self, peer_id: PeerId, plaintext: Vec<u8>) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::SendEncrypted { peer_id, plaintext, reply })?;
        rx.await?
    }

    /// Manually trigger key exchange with a peer via Direct channel.
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

    /// Check if a peer is currently connected.
    pub async fn is_connected(&self, peer_id: &PeerId) -> anyhow::Result<bool> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(P2PCommand::IsConnected { peer_id: *peer_id, reply })?;
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
