#![allow(clippy::too_many_arguments)]

//! Crypto envelope handler — key exchange, decryption, identity verification.
//!
//! Functions here run inside the swarm event loop. They are `pub(crate)` so
//! that `network.rs` can call them directly.

use libp2p::{gossipsub, swarm::Swarm, PeerId};
use tokio::sync::mpsc;

use crate::crypto::{CryptoLayer, KeyPair};
use crate::identity::AgentIdentity;
use crate::protocol::AgentMessage;

use super::behaviour::WalkieBehaviour;
use super::direct::{self, DirectPayload, DirectRequest, DirectResponse, DirectResponseStatus};
use super::envelope::{CryptoEnvelope, WT_TOPIC};
use super::event::P2PEvent;

pub fn wt_topic() -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(WT_TOPIC)
}

// ═══════════════════════════════════════════════════════════════
// Shared helper functions — used by both Direct & Gossipsub
// ═══════════════════════════════════════════════════════════════

/// Perform X25519 DH and create/update an E2EE session for a peer.
///
/// Returns `Ok(())` on success, `Err(reason)` on DH failure.
/// Emits `SessionEstablished` or `SessionFailed` events.
fn establish_session(
    peer_id: PeerId,
    public_key: &[u8],
    crypto: &mut CryptoLayer,
    my_keys: &KeyPair,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
) -> Result<(), String> {
    match CryptoLayer::diffie_hellman(my_keys.private_key(), public_key) {
        Ok(shared) => {
            let peer_str = peer_id.to_string();
            let already = crypto.has_session(&peer_str);
            crypto.create_session(&peer_str, &shared);
            tracing::info!(
                target: "crypto",
                "🔒 session with {peer_id} {}",
                if already { "refreshed" } else { "created" },
            );
            let _ = event_tx.send(P2PEvent::SessionEstablished { peer_id });
            Ok(())
        }
        Err(e) => {
            tracing::error!(target: "crypto", "DH failed with {peer_id}: {e}");
            let _ = event_tx.send(P2PEvent::SessionFailed {
                peer_id,
                reason: format!("DH failed: {e}"),
            });
            Err(format!("DH failed: {e}"))
        }
    }
}

/// Dispatch a decrypted plaintext payload to the appropriate P2P event.
///
/// Tries to parse as `AgentIdentity`, then `AgentMessage`, then falls back
/// to raw `EncryptedMessage`.
fn process_decrypted_payload(
    from: PeerId,
    plaintext: Vec<u8>,
    channel: &str,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
) {
    tracing::trace!(target: "crypto", "🔓 decrypted {} bytes from {from} ({channel})", plaintext.len());

    if let Ok(identity) = serde_json::from_slice::<AgentIdentity>(&plaintext) {
        match identity.verify() {
            Ok(()) => {
                tracing::info!(target: "identity", "🪪 verified agent '{}' from {from}", identity.display_name);
                let _ = event_tx.send(P2PEvent::AgentIdentified { peer_id: from, identity });
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
        tracing::info!(
            target: "protocol",
            "📋 structured [{}] from {}",
            agent_msg.protocol.tag(),
            agent_msg.from_agent.display_name,
        );
        let _ = event_tx.send(P2PEvent::StructuredMessage { from, message: agent_msg });
    } else {
        let _ = event_tx.send(P2PEvent::EncryptedMessage { from, plaintext });
    }
}

/// Parse and verify an `AgentIdentity` from raw JSON bytes.
///
/// Returns `Ok(identity)` on success, `Err(reason)` on parse or verify failure.
fn verify_identity_claim(identity_json: &[u8]) -> Result<AgentIdentity, String> {
    let identity: AgentIdentity =
        serde_json::from_slice(identity_json).map_err(|e| format!("invalid identity JSON: {e}"))?;
    identity.verify().map_err(|e| format!("identity verification: {e}"))?;
    tracing::info!(target: "identity", "🪪 verified agent '{}'", identity.display_name);
    Ok(identity)
}

// ═══════════════════════════════════════════════════════════════
// Direct channel send helpers
// ═══════════════════════════════════════════════════════════════

/// Send a KeyOffer to a peer via the Direct channel.
pub(crate) fn send_key_offer(
    swarm: &mut Swarm<WalkieBehaviour>,
    my_keys: &KeyPair,
    peer_id: &PeerId,
) {
    let request = direct::key_offer_request(my_keys.public.clone());
    let _req_id = swarm.behaviour_mut().direct.send_request(peer_id, request);
    tracing::info!(target: "crypto", "🔑 sent KeyOffer to {peer_id} (direct)");
}

/// Send a KeyAccept to a peer via Direct channel.
pub(crate) fn send_key_accept(
    swarm: &mut Swarm<WalkieBehaviour>,
    my_keys: &KeyPair,
    peer_id: &PeerId,
) {
    let request = direct::key_accept_request(my_keys.public.clone());
    let _req_id = swarm.behaviour_mut().direct.send_request(peer_id, request);
    tracing::info!(target: "crypto", "🔑 sent KeyAccept to {peer_id} (direct)");
}

// ═══════════════════════════════════════════════════════════════
// Direct channel request handler
// ═══════════════════════════════════════════════════════════════

/// Handle an incoming direct channel request.
///
/// Dispatches:
/// - KeyOffer/KeyAccept → E2EE session (via `establish_session`)
/// - Encrypted → decrypt → dispatch (via `process_decrypted_payload`)
/// - IdentityClaim → verify (via `verify_identity_claim`)
///
/// Returns a response for the response channel.
pub(crate) fn handle_direct_request(
    from: PeerId,
    request: DirectRequest,
    crypto: &mut CryptoLayer,
    my_keys: &KeyPair,
    swarm: &mut Swarm<WalkieBehaviour>,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    agent_identity: &Option<AgentIdentity>,
    identity_registry: &mut Option<crate::identity::IdentityRegistry>,
) -> DirectResponse {
    let peer_str = from.to_string();
    let request_id = request.request_id;

    match request.payload {
        // ── Key exchange ──

        DirectPayload::KeyOffer { public_key } => {
            tracing::info!(target: "crypto", "🔑 KeyOffer from {from} (direct)");
            if let Err(reason) = establish_session(from, &public_key, crypto, my_keys, event_tx) {
                return DirectResponse { request_id, status: DirectResponseStatus::Error(reason) };
            }

            // Send our AgentIdentity if configured
            if let Some(ref our_identity) = agent_identity {
                if let Ok(id_json) = serde_json::to_vec(our_identity) {
                    let claim_req = direct::identity_claim_request(id_json);
                    let _ = swarm.behaviour_mut().direct.send_request(&from, claim_req);
                    tracing::info!(target: "identity", "🪪 sent our identity to {from} (direct)");
                }
            }

            send_key_accept(swarm, my_keys, &from);
            direct::ok_response(request_id)
        }

        DirectPayload::KeyAccept { public_key } => {
            tracing::info!(target: "crypto", "🔑 KeyAccept from {from} (direct)");
            if let Err(reason) = establish_session(from, &public_key, crypto, my_keys, event_tx) {
                return DirectResponse { request_id, status: DirectResponseStatus::Error(reason) };
            }
            direct::ok_response(request_id)
        }

        // ── Encrypted payload ──

        DirectPayload::Encrypted { ciphertext } => {
            match crypto.decrypt_from(&peer_str, &ciphertext) {
                Ok(plaintext) => {
                    process_decrypted_payload(from, plaintext, "direct", event_tx);
                    direct::ok_response(request_id)
                }
                Err(e) => {
                    tracing::warn!(target: "crypto", "🔓 decrypt failed from {from}: {e}");
                    let _ = event_tx.send(P2PEvent::SessionFailed {
                        peer_id: from,
                        reason: format!("decrypt: {e}"),
                    });
                    DirectResponse {
                        request_id,
                        status: DirectResponseStatus::Error(format!("decrypt failed: {e}")),
                    }
                }
            }
        }

        // ── Identity claim ──

        DirectPayload::IdentityClaim { identity_json } => {
            match verify_identity_claim(&identity_json) {
                Ok(identity) => {
                    // Record in identity registry if available
                    if let Some(ref mut registry) = identity_registry {
                        registry.bind(
                            &from.to_string(),
                            &identity.agent_id,
                            identity.public_key.clone(),
                        );
                    }
                    let _ = event_tx.send(P2PEvent::AgentIdentified { peer_id: from, identity });
                    direct::ok_response(request_id)
                }
                Err(reason) => {
                    tracing::warn!(target: "identity", "🪪 {reason} from {from}");
                    DirectResponse { request_id, status: DirectResponseStatus::Error(reason) }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Gossipsub envelope handler (legacy / backward compat)
// ═══════════════════════════════════════════════════════════════

/// Handle a CryptoEnvelope received via Gossipsub.
///
/// Processes KeyOffer, KeyAccept, Encrypted, and IdentityClaim variants.
/// Other variants are logged and ignored.
pub(crate) fn handle_crypto_envelope(
    from: PeerId,
    envelope: CryptoEnvelope,
    crypto: &mut CryptoLayer,
    my_keys: &KeyPair,
    swarm: &mut Swarm<WalkieBehaviour>,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    agent_identity: &Option<AgentIdentity>,
    identity_registry: &mut Option<crate::identity::IdentityRegistry>,
) {
    match envelope {
        CryptoEnvelope::KeyOffer { public_key } => {
            if let Err(reason) = establish_session(from, &public_key, crypto, my_keys, event_tx) {
                tracing::warn!(target: "crypto", "gossipsub KeyOffer failed: {reason}");
                return;
            }

            if let Some(ref our_identity) = agent_identity {
                if let Ok(id_json) = serde_json::to_vec(our_identity) {
                    let claim_req = direct::identity_claim_request(id_json);
                    let _ = swarm.behaviour_mut().direct.send_request(&from, claim_req);
                }
            }

            send_key_accept(swarm, my_keys, &from);
        }

        CryptoEnvelope::KeyAccept { public_key } => {
            if let Err(reason) = establish_session(from, &public_key, crypto, my_keys, event_tx) {
                tracing::warn!(target: "crypto", "gossipsub KeyAccept failed: {reason}");
            }
        }

        CryptoEnvelope::Encrypted { ciphertext } => {
            let peer_str = from.to_string();
            match crypto.decrypt_from(&peer_str, &ciphertext) {
                Ok(plaintext) => {
                    process_decrypted_payload(from, plaintext, "gossipsub", event_tx);
                }
                Err(e) => {
                    tracing::debug!(target: "crypto", "gossipsub decrypt from {from}: {e}");
                }
            }
        }

        CryptoEnvelope::IdentityClaim { identity_json } => {
            match verify_identity_claim(&identity_json) {
                Ok(identity) => {
                    if let Some(ref mut registry) = identity_registry {
                        registry.bind(
                            &from.to_string(),
                            &identity.agent_id,
                            identity.public_key.clone(),
                        );
                    }
                    let _ = event_tx.send(P2PEvent::AgentIdentified { peer_id: from, identity });
                }
                Err(reason) => {
                    tracing::warn!(target: "identity", "🪪 {reason} from {from}");
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityBuilder;

    #[test]
    fn test_verify_identity_claim_valid() {
        let (identity, _) = IdentityBuilder::new("TestAgent")
            .capabilities(&["test"])
            .build()
            .unwrap();
        let json = serde_json::to_vec(&identity).unwrap();
        let result = verify_identity_claim(&json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().display_name, "TestAgent");
    }

    #[test]
    fn test_verify_identity_claim_invalid_json() {
        let result = verify_identity_claim(b"not json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid identity JSON"));
    }

    #[test]
    fn test_verify_identity_claim_tampered() {
        let (mut identity, _) = IdentityBuilder::new("Honest")
            .build()
            .unwrap();
        identity.display_name = "Impostor".to_string();
        let json = serde_json::to_vec(&identity).unwrap();
        let result = verify_identity_claim(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_decrypted_payload_identity() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (identity, _) = IdentityBuilder::new("PayloadTest")
            .build()
            .unwrap();
        let plaintext = serde_json::to_vec(&identity).unwrap();
        let peer = PeerId::random();

        process_decrypted_payload(peer, plaintext, "test", &tx);

        let event = rx.try_recv().expect("should have event");
        match event {
            P2PEvent::AgentIdentified { peer_id, identity } => {
                assert_eq!(peer_id, peer);
                assert_eq!(identity.display_name, "PayloadTest");
            }
            _ => panic!("expected AgentIdentified, got {event:?}"),
        }
    }

    #[test]
    fn test_process_decrypted_payload_raw() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let peer = PeerId::random();
        let plaintext = b"raw binary data".to_vec();

        // Should not panic, just emit EncryptedMessage
        process_decrypted_payload(peer, plaintext.clone(), "test", &tx);
    }
}
