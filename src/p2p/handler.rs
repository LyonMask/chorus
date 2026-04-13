//! Crypto envelope handler — key exchange, decryption, identity verification,
//! resource declaration and request processing.
//!
//! Functions here run inside the swarm event loop. They are `pub(crate)` so
//! that `network.rs` can call them directly.
//!
//! ## Architecture (refactored)
//!
//! Both the Direct channel handler and the legacy Gossipsub handler share:
//! - `establish_session()` — DH + session creation
//! - `process_decrypted_payload()` — identity/structured/raw dispatch
//! - `verify_identity_claim()` — identity parse + verify

use libp2p::{gossipsub, swarm::Swarm, PeerId};
use tokio::sync::mpsc;

use crate::crypto::{CryptoLayer, KeyPair};
use crate::identity::AgentIdentity;
use crate::protocol::AgentMessage;
use crate::resource::{
    ContributionEngine, RejectReason, ResourceOffer, ResourceRequest, WorkReceipt,
};
use crate::resource::now_ms;

use super::behaviour::WalkieBehaviour;
use super::direct::{self, DirectPayload, DirectRequest, DirectResponse, DirectResponseStatus};
use super::envelope::{CryptoEnvelope, WT_TOPIC};
use super::event::P2PEvent;

fn wt_topic() -> gossipsub::IdentTopic {
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
// Direct channel send helpers (P0-3)
// ═══════════════════════════════════════════════════════════════

/// Send a KeyOffer to a peer via the **Direct channel** (not Gossipsub).
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

/// Send our ResourceDeclaration to a peer via Direct channel.
pub(crate) fn send_resource_declaration(
    swarm: &mut Swarm<WalkieBehaviour>,
    engine: &ContributionEngine,
    peer_id: &PeerId,
) {
    if let Some(ref ad) = engine.my_ad {
        let request = direct::resource_declaration_request(ad.clone());
        swarm.behaviour_mut().direct.send_request(peer_id, request);
        tracing::info!(target: "resource", "📦 sent ResourceDeclaration to {peer_id} (direct)");
    }
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
/// - ResourceDeclaration → validate & store
/// - ResourceRequest → match & offer
/// - ResourceOffer → accept
/// - ResourceAccept → activate session
/// - ResourceSessionActivated → record
/// - ResourceRelease → validate & record
/// - ResourceReleaseAck → acknowledge
///
/// Returns a response for the response channel.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_direct_request(
    from: PeerId,
    request: DirectRequest,
    crypto: &mut CryptoLayer,
    my_keys: &KeyPair,
    swarm: &mut Swarm<WalkieBehaviour>,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    agent_identity: &Option<AgentIdentity>,
    resource_engine: &mut ContributionEngine,
    identity_registry: &mut Option<crate::identity::IdentityRegistry>,
    signing_key: &Option<std::sync::Arc<ed25519_dalek::SigningKey>>,
    nonce_store: &mut crate::trust::peer_binding::NonceStore,
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
            send_resource_declaration(swarm, resource_engine, &from);
            direct::ok_response(request_id)
        }

        DirectPayload::KeyAccept { public_key } => {
            tracing::info!(target: "crypto", "🔑 KeyAccept from {from} (direct)");
            if let Err(reason) = establish_session(from, &public_key, crypto, my_keys, event_tx) {
                return DirectResponse { request_id, status: DirectResponseStatus::Error(reason) };
            }
            send_resource_declaration(swarm, resource_engine, &from);
            // Auto-send IdentityAttestation after key exchange (Phase 4)
            send_identity_attestation(swarm, &from, signing_key, agent_identity);
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
                    let _ = event_tx.send(P2PEvent::AgentIdentified { peer_id: from, identity });
                    direct::ok_response(request_id)
                }
                Err(reason) => {
                    tracing::warn!(target: "identity", "🪪 {reason} from {from}");
                    DirectResponse { request_id, status: DirectResponseStatus::Error(reason) }
                }
            }
        }

        // ── Resource declaration ──

        DirectPayload::ResourceDeclaration { advertisement } => {
            handle_resource_declaration(from, advertisement, request_id, event_tx, resource_engine)
        }

        // ── Resource request flow (Phase 3) ──

        DirectPayload::ResourceRequest { request } => {
            let (response, offer_request) = handle_resource_request(from, request, request_id, event_tx, resource_engine);
            if let Some(req) = offer_request {
                swarm.behaviour_mut().direct.send_request(&from, req);
                tracing::info!(target: "resource", "📦 sent ResourceOffer request to {from}");
            }
            response
        }

        DirectPayload::ResourceOffer { offer } => {
            handle_resource_offer_incoming(from, offer, request_id, event_tx)
        }

        DirectPayload::ResourceAccept { session_id } => {
            handle_resource_accept(from, session_id, request_id, event_tx, resource_engine)
        }

        DirectPayload::ResourceSessionActivated { session_id, expires_at } => {
            handle_resource_session_activated(from, session_id, expires_at, request_id, event_tx)
        }

        DirectPayload::ResourceRelease { receipt } => {
            handle_resource_release(from, receipt, request_id, event_tx, resource_engine)
        }

        DirectPayload::ResourceReleaseAck { session_id, contribution_delta } => {
            tracing::info!(
                target: "resource",
                "👋 ResourceReleaseAck from {from}: session={session_id}, delta={contribution_delta:.4}",
            );
            let _ = event_tx.send(P2PEvent::ResourceReleased {
                peer_id: from,
                session_id,
                contribution_delta,
            });
            direct::ok_response(request_id)
        }


        DirectPayload::ResourceReject { request_id: rejected_req_id, reason } => {
            handle_resource_reject(from, rejected_req_id, reason, request_id, event_tx, resource_engine)
        }

        DirectPayload::IdentityAttestation { attestation_json } => {
            let (resp, _next) = handle_identity_attestation(from, &attestation_json, request_id, event_tx, identity_registry, nonce_store);
            resp
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Resource request flow handlers (Phase 3)
// ═══════════════════════════════════════════════════════════════

/// Provider side: handle a ResourceRequest from a consumer.
///
/// Checks if our advertisement satisfies the request. If so, creates a
/// pending session and returns an offer. Otherwise returns an error.
pub(crate) fn handle_resource_request(
    from: PeerId,
    request: ResourceRequest,
    request_id: u64,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    engine: &mut ContributionEngine,
) -> (DirectResponse, Option<DirectRequest>) {
    tracing::info!(
        target: "resource",
        "📦 ResourceRequest from {from}: consumer={}, cpu={:.1}, mem={}MB",
        request.consumer_id,
        request.min_cpu,
        request.min_memory_mb,
    );

    // Reject expired requests (A4: prevents processing stale forwarded requests)
    let now = crate::resource::now_ms();
    if request.expires_at > 0 && now >= request.expires_at {
        tracing::warn!(
            target: "resource",
            "📦 rejecting expired request from {from}: expires_at={}, now={}",
            request.expires_at, now
        );
        return (
            DirectResponse {
                request_id,
                status: DirectResponseStatus::Error("request expired".into()),
            },
            None,
        );
    }

    // Check if our ad satisfies the request
    let offer = if let Some(ref ad) = engine.my_ad {
        if !ad.satisfies(&request) {
            tracing::warn!(target: "resource", "📦 request not satisfied by our ad");
            let _ = event_tx.send(P2PEvent::ResourceRequestFailed {
                peer_id: from,
                reason: "no matching resources".into(),
            });
            return (
                DirectResponse {
                    request_id,
                    status: DirectResponseStatus::Error("no matching resources".into()),
                },
                None,
            );
        }

        let _session_id = engine.sessions.create_session(
            request.consumer_id.clone(),
            engine.agent_id.clone(),
            request.min_cpu,
            request.min_memory_mb,
            request.duration_ms,
        );
        let expires_at = now_ms() + request.duration_ms;

        ResourceOffer {
            provider_id: engine.agent_id.clone(),
            consumer_id: request.consumer_id.clone(),
            cpu_amount: ad.cpu_offer.min(request.min_cpu),
            memory_amount_mb: ad.memory_offer_mb.min(request.min_memory_mb),
            bandwidth_amount: ad.bandwidth_offer.min(request.min_bandwidth),
            storage_amount: ad.storage_offer.min(request.min_storage),
            expires_at,
            signature: Vec::new(),
        }
    } else {
        tracing::warn!(target: "resource", "📦 no resource ad configured");
        let _ = event_tx.send(P2PEvent::ResourceRequestFailed {
            peer_id: from,
            reason: "no resources available".into(),
        });
        return (
            DirectResponse {
                request_id,
                status: DirectResponseStatus::Error("no resources available".into()),
            },
            None,
        );
    };

    tracing::info!(
        target: "resource",
        "📦 sent ResourceOffer to {from}: cpu={:.1}, mem={}MB",
        offer.cpu_amount,
        offer.memory_amount_mb,
    );

    let _ = event_tx.send(P2PEvent::ResourceOfferSent {
        peer_id: from,
        session_id: offer.provider_id.clone(),
    });

    // Send offer as a separate DirectRequest (not in response Error field)
    let offer_request = direct::resource_offer_request(offer);
    (
        direct::ok_response(request_id),
        Some(offer_request),
    )
}

/// Consumer side: handle a ResourceOffer from a provider.
pub(crate) fn handle_resource_offer_incoming(
    from: PeerId,
    offer: ResourceOffer,
    request_id: u64,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
) -> DirectResponse {
    tracing::info!(
        target: "resource",
        "📦 ResourceOffer from {from}: provider={}, cpu={:.1}, mem={}MB",
        offer.provider_id,
        offer.cpu_amount,
        offer.memory_amount_mb,
    );

    let _ = event_tx.send(P2PEvent::ResourceOfferReceived {
        peer_id: from,
        offer: offer.clone(),
    });

    direct::ok_response(request_id)
}

/// Provider side: handle a ResourceAccept from a consumer.
///
/// Activates the pending session and emits `ResourceSessionStarted`.
pub(crate) fn handle_resource_accept(
    from: PeerId,
    session_id: String,
    request_id: u64,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    engine: &mut ContributionEngine,
) -> DirectResponse {
    tracing::info!(target: "resource", "✅ ResourceAccept from {from}: session={session_id}");

    // A5: Validate session_id format to prevent forged/malformed IDs
    if let Some((sid_consumer, sid_provider)) =
        crate::resource::ResourceSessionManager::validate_session_id(&session_id)
    {
        // Sanity check: the consumer in the session_id should match the sender
        if sid_consumer != from.to_string() {
            tracing::warn!(
                target: "resource",
                "✅ session_id consumer '{sid_consumer}' doesn't match sender {from}"
            );
            return DirectResponse {
                request_id,
                status: DirectResponseStatus::Error("session_id consumer mismatch".into()),
            };
        }
        // Provider should match our agent_id
        if sid_provider != engine.agent_id {
            tracing::warn!(
                target: "resource",
                "✅ session_id provider '{sid_provider}' doesn't match our agent_id"
            );
            return DirectResponse {
                request_id,
                status: DirectResponseStatus::Error("session_id provider mismatch".into()),
            };
        }
    } else {
        tracing::warn!(target: "resource", "✅ malformed session_id: {session_id}");
        return DirectResponse {
            request_id,
            status: DirectResponseStatus::Error("malformed session_id".into()),
        };
    }

    // Look up the pending session by session_id (not by consumer peer ID).
    // This fixes a bug where multi-session scenarios would pick the wrong one.
    let session = engine.sessions.get(&session_id);
    let (found_sid, expires_at) = if let Some(s) = session {
        if s.status != crate::resource::SessionStatus::Pending {
            tracing::warn!(target: "resource", "✅ session {session_id} is not pending (status={:?})", s.status);
            return DirectResponse {
                request_id,
                status: DirectResponseStatus::Error("session not pending".into()),
            };
        }
        if s.consumer != from.to_string() {
            tracing::warn!(target: "resource", "✅ session {session_id} belongs to {}, not {from}", s.consumer);
            return DirectResponse {
                request_id,
                status: DirectResponseStatus::Error("session belongs to different consumer".into()),
            };
        }
        (session_id.clone(), s.ends_at)
    } else {
        tracing::warn!(target: "resource", "✅ no pending session found for id={session_id}");
        return DirectResponse {
            request_id,
            status: DirectResponseStatus::Error("no pending session".into()),
        };
    };

    if !engine.accept_session(&found_sid) {
        tracing::warn!(target: "resource", "✅ failed to activate session {found_sid}");
        return DirectResponse {
            request_id,
            status: DirectResponseStatus::Error("failed to activate session".into()),
        };
    }

    let _ = event_tx.send(P2PEvent::ResourceSessionStarted {
        peer_id: from,
        session_id: found_sid.clone(),
        expires_at,
    });

    direct::ok_response(request_id)
}

/// Consumer side: handle a ResourceSessionActivated from the provider.
pub(crate) fn handle_resource_session_activated(
    from: PeerId,
    session_id: String,
    expires_at: u64,
    request_id: u64,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
) -> DirectResponse {
    tracing::info!(
        target: "resource",
        "✅ ResourceSessionActivated from {from}: session={session_id}, expires_at={expires_at}",
    );

    let _ = event_tx.send(P2PEvent::ResourceSessionStarted {
        peer_id: from,
        session_id,
        expires_at,
    });

    direct::ok_response(request_id)
}

/// Provider side: handle a ResourceRelease with WorkReceipt.
///
/// Validates, records consumption, releases the session.
pub(crate) fn handle_resource_release(
    from: PeerId,
    receipt: WorkReceipt,
    request_id: u64,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    engine: &mut ContributionEngine,
) -> DirectResponse {
    tracing::info!(
        target: "resource",
        "👋 ResourceRelease from {from}: session={}, cpu_ms={}, duration_ms={}",
        receipt.session_id,
        receipt.cpu_used_ms,
        receipt.duration_ms,
    );

    let contribution_delta =
        if let Some(_provider_receipt) = engine.release_and_prove(&receipt.session_id) {
            let delta = receipt.cpu_used_ms as f64 / 3_600_000.0;
            tracing::info!(target: "resource", "👋 contribution_delta={delta:.4}");
            engine.record_consumption(&receipt);
            delta
        } else {
            tracing::warn!(target: "resource", "👋 no active session found for {}", receipt.session_id);
            return DirectResponse {
                request_id,
                status: DirectResponseStatus::Error("no active session".into()),
            };
        };

    let _ = event_tx.send(P2PEvent::ResourceReleased {
        peer_id: from,
        session_id: receipt.session_id.clone(),
        contribution_delta,
    });

    direct::ok_response(request_id)
}
// Resource reject handler (Phase 3)
// ═══════════════════════════════════════════════════════════════

/// Provider side: handle a ResourceReject from a consumer.
///
/// Releases the reserved resources back to available. The session
/// is transitioned from Pending to Released.
pub(crate) fn handle_resource_reject(
    from: PeerId,
    _rejected_req_id: String,
    reason: RejectReason,
    request_id: u64,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    engine: &mut ContributionEngine,
) -> DirectResponse {
    tracing::info!(
        target: "resource",
        "🚫 ResourceReject from {from}: reason={reason}",
    );

    // Find and release the pending session for this consumer.
    let pending = engine.sessions.list_by_status(crate::resource::SessionStatus::Pending);
    let mut found_sid = String::new();
    for session in pending {
        if session.consumer == from.to_string() {
            found_sid = session.session_id.clone();
            break;
        }
    }

    if !found_sid.is_empty() {
        engine.sessions.release(&found_sid);
        tracing::info!(target: "resource", "🚫 released reserved session {found_sid} after reject");
    } else {
        tracing::debug!(target: "resource", "🚫 no pending session to release for {from}");
    }

    let _ = event_tx.send(P2PEvent::ResourceRequestFailed {
        peer_id: from,
        reason: format!("rejected: {reason}"),
    });

    direct::ok_response(request_id)
}

// ═══════════════════════════════════════════════════════════════
// Resource declaration handler
// ═══════════════════════════════════════════════════════════════

/// Handle an incoming resource declaration from a peer.
///
/// Validates the advertisement against spec consistency and economy params,
/// then stores it in the local ContributionEngine's ResourceTable.
pub(crate) fn handle_resource_declaration(
    from: PeerId,
    advertisement: crate::resource::ResourceAdvertisement,
    request_id: u64,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    engine: &mut ContributionEngine,
) -> DirectResponse {
    tracing::info!(
        target: "resource",
        "📦 ResourceDeclaration from {from}: agent={}, seq={}, cpu={:.1}%, mem={}MB",
        advertisement.agent_id,
        advertisement.sequence,
        advertisement.cpu_offer * 100.0,
        advertisement.memory_offer_mb,
    );

    if let Err(e) = advertisement.validate_with_signature() {
        tracing::warn!(target: "resource", "📦 ResourceDeclaration from {from} rejected: {e}");
        let _ = event_tx.send(P2PEvent::ResourceDeclarationRejected {
            peer_id: from,
            reason: e.clone(),
        });
        return DirectResponse {
            request_id,
            status: DirectResponseStatus::Error(format!("validation: {e}")),
        };
    }

    let _ = engine.on_resource_ad(advertisement.clone());

    let _ = event_tx.send(P2PEvent::ResourceDeclared {
        peer_id: from,
        advertisement,
    });

    direct::ok_response(request_id)
}

// ═══════════════════════════════════════════════════════════════
// Legacy Gossipsub handler (kept for BroadcastStructured & backward compat)
// ═══════════════════════════════════════════════════════════════

/// Handle a CryptoEnvelope received via Gossipsub.
///
/// Only used for broadcast messages. Point-to-point messages arrive via Direct channel.
/// Key exchange and encrypted payload handling delegates to the same shared helpers
/// as `handle_direct_request`, eliminating duplicate logic.
#[allow(clippy::too_many_arguments)]
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
            tracing::info!(target: "crypto", "🔑 KeyOffer from {from} (gossipsub — legacy)");
            if establish_session(from, &public_key, crypto, my_keys, event_tx).is_ok() {
                // Legacy: publish identity via encrypted Gossipsub envelope
                if let Some(ref our_identity) = agent_identity {
                    if let Ok(id_json) = serde_json::to_vec(our_identity) {
                        let claim = CryptoEnvelope::Encrypted { ciphertext: id_json };
                        if let Ok(bytes) = serde_json::to_vec(&claim) {
                            let _ = swarm.behaviour_mut().gossipsub.publish(wt_topic(), bytes);
                        }
                    }
                }

                // Legacy: publish KeyAccept via Gossipsub
                let accept = CryptoEnvelope::KeyAccept { public_key: my_keys.public.clone() };
                if let Ok(bytes) = serde_json::to_vec(&accept) {
                    let _ = swarm.behaviour_mut().gossipsub.publish(wt_topic(), bytes);
                }
            }
        }

        CryptoEnvelope::KeyAccept { public_key } => {
            tracing::info!(target: "crypto", "🔑 KeyAccept from {from} (gossipsub — legacy)");
            let _ = establish_session(from, &public_key, crypto, my_keys, event_tx);
        }

        CryptoEnvelope::Encrypted { ciphertext } => {
            match crypto.decrypt_from(&peer_str, &ciphertext) {
                Ok(plaintext) => {
                    process_decrypted_payload(from, plaintext, "gossipsub", event_tx);
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
            match verify_identity_claim(&identity_json) {
                Ok(identity) => {
                    let _ = event_tx.send(P2PEvent::AgentIdentified { peer_id: from, identity });
                }
                Err(reason) => {
                    tracing::warn!(target: "identity", "🪪 {reason} from {from}");
                    let _ = event_tx.send(P2PEvent::IdentityVerificationFailed {
                        peer_id: from,
                        reason,
                    });
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

// Identity attestation (Phase 4)



/// Send an IdentityAttestation over the Direct channel (Phase 4).
///
/// Called automatically after E2EE session establishment to prove
/// that our PeerId belongs to our claimed DID.
pub(crate) fn send_identity_attestation(
    swarm: &mut Swarm<WalkieBehaviour>,
    peer_id: &PeerId,
    signing_key: &Option<std::sync::Arc<ed25519_dalek::SigningKey>>,
    agent_identity: &Option<AgentIdentity>,
) {
    let (did, key) = match (agent_identity, signing_key) {
        (Some(ident), Some(key)) => (ident.agent_id.clone(), key.clone()),
        _ => return, // No identity or signing key configured — skip
    };

    let attestation = crate::trust::peer_binding::IdentityAttestation::sign(
        &did,
        &peer_id.to_string(),
        &key,
    );

    match serde_json::to_vec(&attestation) {
        Ok(json) => {
            let req = direct::DirectRequest {
                request_id: 0, // attestation is unsolicited (request_id unused)
                payload: direct::DirectPayload::IdentityAttestation { attestation_json: json },
            };
            let _ = swarm.behaviour_mut().direct.send_request(peer_id, req);
            tracing::info!(target: "trust", "🔐 sent IdentityAttestation to {peer_id}");
        }
        Err(e) => {
            tracing::warn!(target: "trust", "⚠️  failed to serialize attestation: {e}");
        }
    }
}

/// Handle an incoming IdentityAttestation over the Direct channel.
///
/// Verifies the Ed25519 signature, checks nonce uniqueness (replay defense),
/// and updates the IdentityRegistry to mark the binding as Cryptographic.
pub(crate) fn handle_identity_attestation(
    from: PeerId,
    attestation_json: &[u8],
    request_id: u64,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    identity_registry: &mut Option<crate::identity::IdentityRegistry>,
    nonce_store: &mut crate::trust::peer_binding::NonceStore,
) -> (DirectResponse, Option<DirectRequest>) {
    use crate::trust::peer_binding::IdentityAttestation;

    // Deserialize
    let attestation: IdentityAttestation = match serde_json::from_slice(attestation_json) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(target: "trust", "⚠️  Invalid attestation JSON from {from}: {e}");
            return (direct::error_response(request_id, "invalid attestation json"), None);
        }
    };


    let peer_id_str = from.to_string();

    // ── Replay defense: check nonce BEFORE signature verification ──
    let nonce_bytes = &attestation.nonce;
    if nonce_store.check_and_insert(nonce_bytes).is_err() {
        tracing::warn!(target: "trust", "🔒 Replay detected: attestation from {from} with duplicate nonce");
        return (direct::error_response(request_id, "replay detected"), None);
    }

    // Get expected DID and public key from the identity registry
    let registry = match identity_registry.as_mut() {
        Some(r) => r,
        None => {
            tracing::debug!(target: "trust", "No identity registry, skipping attestation from {from}");
            return (direct::ok_response(request_id), None);
        }
    };

    let expected_did = match registry.did_for_peer(&peer_id_str) {
        Some(did) => did.to_string(),
        None => {
            tracing::debug!(target: "trust", "No prior DID binding for peer {from}, skipping attestation");
            return (direct::ok_response(request_id), None);
        }
    };

    let expected_pubkey = match registry.get_binding(&peer_id_str) {
        Some(binding) => binding.pub_key.clone(),
        None => {
            return (direct::error_response(request_id, "no binding found"), None);
        }
    };

    // Verify attestation: signature + timestamp + DID/PeerId match
    match attestation.verify_with_identity(&expected_did, &peer_id_str, &expected_pubkey) {
        Ok(()) => {
            // Update trust level to Cryptographic
            match registry.bind_verified(&peer_id_str, expected_pubkey) {
                Ok(()) => {
                    tracing::info!(
                        target: "trust",
                        "🔐 PeerId↔DID verified: {from} ↔ did:{expected_did} (Cryptographic)",
                    );
                    let _ = event_tx.send(P2PEvent::IdentityAttestationVerified {
                        peer_id: from,
                        did: expected_did,
                    });
                }
                Err(e) => {
                    tracing::warn!(target: "trust", "⚠️  bind_verified failed for {from}: {e}");
                }
            }
            (direct::ok_response(request_id), None)
        }
        Err(e) => {
            tracing::warn!(target: "trust", "⚠️  Attestation verification failed for {from}: {e}");
            (direct::error_response(request_id, format!("attestation verification failed: {e}")), None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{ResourceAdvertisement, ResourceSpec};
    use tokio::sync::mpsc;

    fn make_provider_engine() -> ContributionEngine {
        let mut engine = ContributionEngine::new("did:walkie:provider".into());
        let ad = ResourceAdvertisement {
            agent_id: "did:walkie:provider".into(),
            sequence: 1,
            timestamp: now_ms(),
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 256 * 1024 * 1024 * 1024,
            },
            cpu_offer: 0.5,
            memory_offer_mb: 4096,
            bandwidth_offer: 10_000_000,
            storage_offer: 50 * 1024 * 1024 * 1024,
            features: vec!["always-on".into()],
            signing_pubkey: Vec::new(),
            signature: Vec::new(),
        };
        engine.declare_resources(ad);
        if let Some(ref our_ad) = engine.my_ad {
            let _ = engine.on_resource_ad(our_ad.clone());
        }
        engine
    }

    fn make_request() -> ResourceRequest {
        ResourceRequest {
            consumer_id: "did:walkie:consumer".into(),
            min_cpu: 0.2,
            min_memory_mb: 1024,
            min_bandwidth: 0,
            min_storage: 0,
            required_features: vec![],
            duration_ms: 60_000,
            priority: 75,
            request_id: String::new(),
            expires_at: 0,
        }
    }

    #[test]
    fn test_handle_resource_request_expired() {
        let mut engine = make_provider_engine();
        let mut request = make_request();
        let (tx, _rx) = mpsc::unbounded_channel();
        let from = PeerId::random();

        // Set expires_at in the past
        request.expires_at = crate::resource::now_ms() - 1000;
        request.consumer_id = from.to_string();

        let (response, offer_req) = handle_resource_request(from, request, 1, &tx, &mut engine);
        assert!(matches!(response.status, DirectResponseStatus::Error(_)));
        assert!(offer_req.is_none(), "expired request should not produce an offer");

        // Verify no session was created
        let pending = engine.sessions.list_by_status(crate::resource::SessionStatus::Pending);
        assert!(pending.is_empty());
    }

    #[test]
    fn test_handle_resource_request_no_expiry() {
        let mut engine = make_provider_engine();
        let mut request = make_request();
        let (tx, _rx) = mpsc::unbounded_channel();
        let from = PeerId::random();

        // expires_at = 0 means no expiry (should be accepted)
        request.expires_at = 0;
        request.consumer_id = from.to_string();

        let (_response, offer_req) = handle_resource_request(from, request, 1, &tx, &mut engine);
        // Should succeed (provider has ad configured)
        assert!(offer_req.is_some());
    }

    #[test]
    fn test_handle_resource_request_no_match() {
        let mut engine = ContributionEngine::new("did:walkie:provider".into());
        let request = make_request();
        let (tx, _rx) = mpsc::unbounded_channel();

        let (response, offer_req) = handle_resource_request(PeerId::random(), request, 42, &tx, &mut engine);
        assert!(matches!(response.status, DirectResponseStatus::Error(_)));
        assert!(offer_req.is_none());
    }

    #[test]
    fn test_handle_resource_request_with_match() {
        let mut engine = make_provider_engine();
        let request = make_request();
        let (tx, _rx) = mpsc::unbounded_channel();

        let (response, offer_req) = handle_resource_request(PeerId::random(), request, 42, &tx, &mut engine);
        // Now returns Ok response + separate offer request
        assert!(matches!(response.status, DirectResponseStatus::Ok));
        assert!(offer_req.is_some());
        match offer_req.unwrap().payload {
            DirectPayload::ResourceOffer { offer } => {
                assert_eq!(offer.provider_id, "did:walkie:provider");
                assert!(offer.cpu_amount >= 0.2);
                assert!(offer.memory_amount_mb >= 1024);
            }
            _ => panic!("expected ResourceOffer payload"),
        }

        let pending = engine.sessions.list_by_status(crate::resource::SessionStatus::Pending);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_handle_resource_accept() {
        let mut engine = make_provider_engine();
        let mut request = make_request();
        let (tx, _rx) = mpsc::unbounded_channel();
        let from = PeerId::random();
        request.consumer_id = from.to_string();

        let (_response, _offer_req) = handle_resource_request(from, request, 1, &tx, &mut engine);

        // Get the actual session_id created by the engine
        let pending = engine.sessions.list_by_status(crate::resource::SessionStatus::Pending);
        assert_eq!(pending.len(), 1);
        let real_sid = pending[0].session_id.clone();

        let response = handle_resource_accept(from, real_sid, 2, &tx, &mut engine);
        assert!(matches!(response.status, DirectResponseStatus::Ok));

        let active = engine.sessions.list_by_status(crate::resource::SessionStatus::Active);
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_handle_resource_accept_wrong_session_id() {
        let mut engine = make_provider_engine();
        let mut request = make_request();
        let (tx, _rx) = mpsc::unbounded_channel();
        let from = PeerId::random();
        request.consumer_id = from.to_string();

        let (_response, _offer_req) = handle_resource_request(from, request, 1, &tx, &mut engine);

        // Try to accept with a non-existent session_id (but valid format)
        let response = handle_resource_accept(
            from,
            format!("{}___provider_{}", from, crate::resource::now_ms()),
            2, &tx, &mut engine
        );
        assert!(matches!(response.status, DirectResponseStatus::Error(_)));
    }

    #[test]
    fn test_handle_resource_accept_malformed_session_id() {
        let mut engine = make_provider_engine();
        let (tx, _rx) = mpsc::unbounded_channel();
        let from = PeerId::random();

        // Completely malformed session_id
        let response = handle_resource_accept(from, "not-a-valid-session-id".into(), 2, &tx, &mut engine);
        assert!(matches!(response.status, DirectResponseStatus::Error(_)));

        // Missing random hex part
        let response = handle_resource_accept(
            from,
            format!("{}__provider_{}", from, crate::resource::now_ms()),
            3, &tx, &mut engine
        );
        assert!(matches!(response.status, DirectResponseStatus::Error(_)));
    }

    #[test]
    fn test_handle_resource_accept_consumer_mismatch() {
        let mut engine = make_provider_engine();
        let mut request = make_request();
        let (tx, _rx) = mpsc::unbounded_channel();
        let from = PeerId::random();
        request.consumer_id = from.to_string();

        let (_response, _offer_req) = handle_resource_request(from, request, 1, &tx, &mut engine);

        // Get real session_id but change the consumer prefix
        let real_sid = engine.sessions.list_by_status(crate::resource::SessionStatus::Pending)[0]
            .session_id.clone();
        let attacker = PeerId::random();
        // Replace the consumer part with the attacker's peer id
        let forged_sid = real_sid.replacen(&from.to_string(), &attacker.to_string(), 1);
        assert_ne!(forged_sid, real_sid, "should have changed the consumer");

        let response = handle_resource_accept(attacker, forged_sid, 2, &tx, &mut engine);
        assert!(matches!(response.status, DirectResponseStatus::Error(_)));
    }

    #[test]
    fn test_handle_resource_accept_multi_session() {
        // Two consumers each get a session, accept by specific session_id
        let mut engine = make_provider_engine();
        let (tx, _rx) = mpsc::unbounded_channel();
        let from_a = PeerId::random();
        let from_b = PeerId::random();

        let mut req_a = make_request();
        req_a.consumer_id = from_a.to_string();
        let mut req_b = make_request();
        req_b.consumer_id = from_b.to_string();

        handle_resource_request(from_a, req_a, 1, &tx, &mut engine);
        handle_resource_request(from_b, req_b, 2, &tx, &mut engine);

        let pending = engine.sessions.list_by_status(crate::resource::SessionStatus::Pending);
        assert_eq!(pending.len(), 2);

        // Accept only B's session
        let sid_b = pending.iter().find(|s| s.consumer == from_b.to_string()).unwrap().session_id.clone();
        let response = handle_resource_accept(from_b, sid_b, 3, &tx, &mut engine);
        assert!(matches!(response.status, DirectResponseStatus::Ok));

        // A's session should still be pending
        let still_pending = engine.sessions.list_by_status(crate::resource::SessionStatus::Pending);
        assert_eq!(still_pending.len(), 1);
        assert_eq!(still_pending[0].consumer, from_a.to_string());

        let active = engine.sessions.list_by_status(crate::resource::SessionStatus::Active);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].consumer, from_b.to_string());
    }

    #[test]
    fn test_handle_resource_release() {
        let mut engine = make_provider_engine();
        let mut request = make_request();
        let (tx, _rx) = mpsc::unbounded_channel();
        let from = PeerId::random();
        request.consumer_id = from.to_string();

        let (_response, _offer_req) = handle_resource_request(from, request.clone(), 1, &tx, &mut engine);
        // Get the actual session_id created by handle_resource_request
        let pending = engine.sessions.list_by_status(crate::resource::SessionStatus::Pending);
        assert_eq!(pending.len(), 1);
        let session_id = pending[0].session_id.clone();
        handle_resource_accept(from, session_id, 2, &tx, &mut engine);

        let active = engine.sessions.list_by_status(crate::resource::SessionStatus::Active);
        assert_eq!(active.len(), 1);
        let session_id = active[0].session_id.clone();

        let receipt = WorkReceipt::new(
            from.to_string(),
            "did:walkie:provider".into(),
            session_id.clone(),
            5000,
            1024 * 1024,
            10_000,
        );

        let response = handle_resource_release(from, receipt, 3, &tx, &mut engine);
        assert!(matches!(response.status, DirectResponseStatus::Ok));

        let released = engine.sessions.list_by_status(crate::resource::SessionStatus::Released);
        assert_eq!(released.len(), 1);
    }

    #[test]
    fn test_resource_request_roundtrip_serialization() {
        let payloads = vec![
            DirectPayload::ResourceRequest {
                request: ResourceRequest::new("consumer".into()),
            },
            DirectPayload::ResourceOffer {
                offer: ResourceOffer {
                    provider_id: "provider".into(),
                    consumer_id: "consumer".into(),
                    cpu_amount: 0.2,
                    memory_amount_mb: 1024,
                    bandwidth_amount: 0,
                    storage_amount: 0,
                    expires_at: now_ms() + 60_000,
                    signature: Vec::new(),
                },
            },
            DirectPayload::ResourceAccept { session_id: "sess-1".into() },
            DirectPayload::ResourceSessionActivated {
                session_id: "sess-1".into(),
                expires_at: now_ms() + 60_000,
            },
            DirectPayload::ResourceRelease {
                receipt: WorkReceipt::new("c".into(), "p".into(), "s1".into(), 1000, 1024, 5000),
            },
            DirectPayload::ResourceReleaseAck {
                session_id: "s1".into(),
                contribution_delta: 1.5,
            },
        ];

        for payload in payloads {
            let req = DirectRequest { request_id: 99, payload };
            let json = serde_json::to_vec(&req).unwrap();
            let decoded: DirectRequest = serde_json::from_slice(&json).unwrap();
            assert_eq!(req, decoded, "roundtrip failed for {:?}", req.payload);
        }
    }


// ═══════════════════════════════════════════════════════════════
}
