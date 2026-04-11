//! Crypto envelope handler — key exchange, decryption, identity verification.
//!
//! Functions here run inside the swarm event loop. They are `pub(crate)` so
//! that `network.rs` can call them directly.

use libp2p::{
    gossipsub, swarm::Swarm, PeerId,
};
use tokio::sync::mpsc;

use crate::crypto::{CryptoLayer, KeyPair};
use crate::identity::AgentIdentity;
use crate::protocol::AgentMessage;

use super::behaviour::WalkieBehaviour;
use super::envelope::{CryptoEnvelope, WT_TOPIC};
use super::event::P2PEvent;

fn wt_topic() -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(WT_TOPIC)
}

/// Send a KeyOffer to a peer via Gossipsub.
pub(crate) fn send_key_offer(
    swarm: &mut Swarm<WalkieBehaviour>,
    my_keys: &KeyPair,
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

/// Handle an incoming crypto envelope.
///
/// Dispatches key exchange (KeyOffer/KeyAccept), decrypts encrypted
/// payloads, and verifies identity claims.
pub(crate) fn handle_crypto_envelope(
    from: PeerId,
    envelope: CryptoEnvelope,
    crypto: &mut CryptoLayer,
    my_keys: &KeyPair,
    swarm: &mut Swarm<WalkieBehaviour>,
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
