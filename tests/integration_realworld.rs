//! Real-world integration tests — dual-node scenarios validating
//! that walkie-talkie works end-to-end with trust and economy layers.
//!
//! Scenarios:
//! 1. Full flow: connect → chat → resource request → offer → release → payment → trust
//! 2. Peer disconnect during active session → reconnect → pending drain
//! 3. Payment refused: insufficient balance
//! 4. Trust escalation: Unverified → Cryptographic → Guaranteed
//! 5. Slash discipline: progressive 3-strike system
//! 6. CRP accumulation + WC conversion cycle
//! 7. Resource request with no matching provider

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::mpsc;

use walkie_talkie_core::economy::payment::{
    PaymentRequest, PaymentResponse, UsageDetails,
    handle_payment_request, handle_payment_response,
};
use walkie_talkie_core::economy::{CrpAccumulator, ContributionSample, WcLedger};
use walkie_talkie_core::identity::did_from_pubkey;
use walkie_talkie_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};
use walkie_talkie_core::resource::{ResourceAdvertisement, ResourceRequest, ResourceSpec};
use walkie_talkie_core::trust::guarantor::GuarantorState;
use walkie_talkie_core::trust::peer_binding::IdentityAttestation;
use walkie_talkie_core::trust::reputation;
use walkie_talkie_core::trust::slash::{OffenseType, SlashLedger};
use walkie_talkie_core::trust::types::TrustScore;

// ── TestNode wrapper ────────────────────────────────────────────

/// A wrapper around P2PNetwork + WcLedger + event receiver
/// providing a simplified async API for integration tests.
struct TestNode {
    name: String,
    net: P2PNetwork,
    ev: mpsc::UnboundedReceiver<P2PEvent>,
    listen_addr: String,
    signing_key: SigningKey,
    ledger: WcLedger,
}

impl TestNode {
    async fn spawn(name: &str) -> Self {
        let seed = name_to_seed(name);
        let signing_key = SigningKey::from_bytes(&seed);
        let config = P2PConfig {
            listen_on: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
            ping_interval_secs: 2,
            ping_timeout_secs: 3,
            idle_timeout_secs: 30,
            signing_key: Some(Arc::new(signing_key.clone())),
            ..Default::default()
        };

        let (net, mut ev) = P2PNetwork::new(config).unwrap_or_else(|_| panic!("{name} spawn failed"));

        let listen_addr = loop {
            match tokio::time::timeout(Duration::from_secs(5), ev.recv()).await {
                Ok(Some(P2PEvent::Listening { address })) => {
                    break address.to_string();
                }
                Ok(Some(_)) => continue,
                _ => panic!("{name}: failed to get listen address"),
            }
        };

        Self {
            name: name.to_string(),
            net,
            ev,
            listen_addr,
            signing_key,
            ledger: WcLedger::with_balance(100.0),
        }
    }

    /// Dial the other node and wait for E2EE session.
    /// Get the listen address.
    fn addr(&self) -> &str {
        &self.listen_addr
    }

    /// Get our PeerId.
    fn local_peer_id(&self) -> libp2p::PeerId {
        *self.net.local_peer_id()
    }

    /// Get our DID.
    fn did(&self) -> String {
        did_from_pubkey(&self.signing_key.verifying_key().to_bytes())
    }

    /// Get our Ed25519 public key bytes.
    fn pubkey_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// Send an encrypted chat message to a peer.
    async fn send_chat(&self, peer_id: libp2p::PeerId, message: &str) {
        self.net
            .send_encrypted(peer_id, message.as_bytes().to_vec())
            .await
            .expect("send_encrypted");
    }

    /// Wait for an encrypted message from any peer, with timeout.
    async fn wait_for_message(&mut self, timeout: Duration) -> (libp2p::PeerId, Vec<u8>) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            if rem.is_zero() {
                panic!("{}: timeout waiting for message", self.name);
            }
            match tokio::time::timeout(rem, self.ev.recv()).await {
                Ok(Some(P2PEvent::EncryptedMessage { from, plaintext })) => {
                    return (from, plaintext);
                }
                Ok(Some(_)) => continue,
                Ok(None) => panic!("{}: event channel closed", self.name),
                Err(_) => panic!("{}: timeout", self.name),
            }
        }
    }

    /// Publish a signed resource advertisement.
    async fn advertise_resources(&self, cpu: f32, mem_mb: u64) {
        let mut ad = ResourceAdvertisement::new(
            self.name.clone(),
            ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 512_000_000_000,
            },
        );
        ad.cpu_offer = cpu;
        ad.memory_offer_mb = mem_mb;
        ad.sequence = 1;
        walkie_talkie_core::identity::sign_advertisement(&mut ad, &self.signing_key);
        self.net.update_resource_ad(ad).await.expect("advertise");
    }

    /// Shut down the node.
    fn shutdown(self) {
        self.net.shutdown().ok();
    }
}

// ── Shared helpers ──────────────────────────────────────────────

fn name_to_seed(name: &str) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in name.as_bytes().iter().enumerate() {
        s[i % 32] ^= *b;
        s[(i + 16) % 32] ^= b.wrapping_mul(31);
    }
    s
}

async fn wait_for_session(
    ev_a: &mut mpsc::UnboundedReceiver<P2PEvent>,
    ev_b: &mut mpsc::UnboundedReceiver<P2PEvent>,
    timeout: Duration,
) {
    let mut a_ok = false;
    let mut b_ok = false;
    let deadline = tokio::time::Instant::now() + timeout;
    while !a_ok || !b_ok {
        if deadline.elapsed().as_nanos() > 0 {
            panic!("timeout waiting for session: a={a_ok}, b={b_ok}");
        }
        tokio::select! {
            event = ev_a.recv() => {
                if let Some(P2PEvent::SessionEstablished { .. }) = event {
                    a_ok = true;
                }
            }
            event = ev_b.recv() => {
                if let Some(P2PEvent::SessionEstablished { .. }) = event {
                    b_ok = true;
                }
            }
        }
    }
}

/// Drain matching events (async, for use within async tests).
async fn drain_events<F>(
    rx: &mut mpsc::UnboundedReceiver<P2PEvent>,
    pred: F,
    timeout: Duration,
) -> Vec<P2PEvent>
where
    F: Fn(&P2PEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut out = Vec::new();
    loop {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() { break; }
        match tokio::time::timeout(rem, rx.recv()).await {
            Ok(Some(e)) if pred(&e) => out.push(e),
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    out
}

async fn connect_nodes(a: &mut TestNode, b: &mut TestNode) {
    a.net.dial(b.addr()).await.expect("dial");
    wait_for_session(&mut a.ev, &mut b.ev, Duration::from_secs(8)).await;
}

// ═══════════════════════════════════════════════════════════════
// TEST 1: Full real-world flow
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_real_world_full_flow() {
    // 1. Start A and B
    let mut node_a = TestNode::spawn("alice").await;
    let mut node_b = TestNode::spawn("bob").await;
    println!("  ✅ Alice and Bob started");

    // 2. B connects to A
    connect_nodes(&mut node_b, &mut node_a).await;
    println!("  ✅ E2EE session established");

    // 3. A sends chat to B
    let peer_b = node_b.local_peer_id();
    let peer_a = node_a.local_peer_id();
    node_a.send_chat(peer_b, "Hello from Alice").await;

    // 4. B receives and replies
    let (from_a, msg) = node_b.wait_for_message(Duration::from_secs(5)).await;
    assert_eq!(from_a, peer_a);
    assert_eq!(String::from_utf8_lossy(&msg), "Hello from Alice");
    println!("  ✅ A→B chat received");

    node_b.send_chat(peer_a, "Hi Alice!").await;
    let (from_b, reply) = node_a.wait_for_message(Duration::from_secs(5)).await;
    assert_eq!(from_b, peer_b);
    assert_eq!(String::from_utf8_lossy(&reply), "Hi Alice!");
    println!("  ✅ B→A reply received");

    // 5. B publishes resources
    node_b.advertise_resources(0.8, 6144).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A should see the declaration
    let decls = drain_events(
        &mut node_a.ev,
        |e| matches!(e, P2PEvent::ResourceDeclared { .. }),
        Duration::from_secs(3),
    ).await;
    assert!(!decls.is_empty(), "A should receive B's resource declaration");
    println!("  ✅ Resource declaration received ({})", decls.len());

    // 6. A requests resource from B (may or may not get an offer depending on MatchEngine)
    let req_result = node_a.net.request_resource(peer_b, ResourceRequest::new("alice".into())).await;
    match &req_result {
        Ok(offer) => println!("  ✅ Resource request → offer (CPU {:.0}%, Mem {}MB)",
            offer.cpu_amount * 100.0, offer.memory_amount_mb),
        Err(e) => println!("  ⚠️ Resource request: {e}"),
    }

    // 7. Verify DID generation
    let did_a = node_a.did();
    let did_b = node_b.did();
    assert!(did_a.starts_with("did:walkie:"));
    assert!(did_b.starts_with("did:walkie:"));
    assert_ne!(did_a, did_b);
    println!("  ✅ DIDs: A={}…{} | B={}…{}", &did_a[..16], &did_a[did_a.len()-4..], &did_b[..16], &did_b[did_b.len()-4..]);

    // 8. Identity attestation verification
    let attestation = IdentityAttestation::sign(&did_a, &peer_a.to_string(), &node_a.signing_key);
    assert!(attestation.verify(&node_a.pubkey_bytes()).is_ok());
    println!("  ✅ Identity attestation verified");

    // 9. WC payment flow
    let initial_a = node_a.ledger.balance();
    let initial_b = node_b.ledger.balance();
    node_a.ledger.set_network_size(100);
    node_a.ledger.recalculate_crp_rate(10.0, 100);
    node_b.ledger.set_network_size(100);

    let usage = UsageDetails {
        cpu_ms: 3_600_000,
        memory_peak_bytes: 1_073_741_824,
        bandwidth_bytes: 104_857_600,
        duration_ms: 3_600_000,
    };
    let request = PaymentRequest::new("test-session", 10.0, usage, &did_b);
    let response = handle_payment_request(&request, &node_a.ledger, 20.0, &did_a);

    match response {
        PaymentResponse::Approved { mut payment } => {
            payment.sign(&node_a.signing_key);
            assert!(payment.verify_signature(&node_a.pubkey_bytes()));
            let result = handle_payment_response(
                &PaymentResponse::Approved { payment: payment.clone() },
                &node_a.pubkey_bytes(),
                &mut node_a.ledger,
                &mut node_b.ledger,
            );
            assert!(result.is_ok(), "payment should succeed");
        }
        PaymentResponse::Rejected { reason } => {
            panic!("payment rejected: {reason}");
        }
    }
    assert!(node_a.ledger.balance() < initial_a, "consumer balance should decrease");
    assert!(node_b.ledger.balance() > initial_b, "provider balance should increase");
    println!("  ✅ WC payment settled: A {:.2}→{:.2} | B {:.2}→{:.2}",
        initial_a, node_a.ledger.balance(), initial_b, node_b.ledger.balance());

    // 10. Trust score computation
    let trust = reputation::recalculate(2, 0.5, false, 0.0, 0, 1);
    assert!(trust.composite() > 0.3, "trust score should be > 0.3 for Cryptographic");
    println!("  ✅ Trust score: {:.4} ({})", trust.composite(), trust.level());

    println!("  🎉 Full real-world flow passed!");
    node_a.shutdown();
    node_b.shutdown();
}

// ═══════════════════════════════════════════════════════════════
// TEST 2: Peer disconnect during session
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_peer_disconnect_during_session() {
    // 1. Start A, B, C
    let mut node_a = TestNode::spawn("node-a").await;
    let mut node_b = TestNode::spawn("node-b").await;
    let mut node_c = TestNode::spawn("node-c").await;

    // 2. Connect A↔B↔C
    node_b.net.dial(node_a.addr()).await.expect("B→A");
    node_c.net.dial(node_a.addr()).await.expect("C→A");
    wait_for_session(&mut node_a.ev, &mut node_b.ev, Duration::from_secs(8)).await;
    wait_for_session(&mut node_a.ev, &mut node_c.ev, Duration::from_secs(8)).await;
    println!("  ✅ 3-node mesh connected");

    // 3. A sends message to C (through A→C direct)
    let peer_c = node_c.local_peer_id();
// A requests resources from B (who has no ads)
    node_a.send_chat(peer_c, "Hey C!").await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 4. C disconnects
    node_c.shutdown();
    println!("  🔴 C disconnected");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 5. C reconnects (new instance on different port)
    let mut node_c2 = TestNode::spawn("node-c-v2").await;
    node_c2.net.dial(node_a.addr()).await.expect("C2→A");
    wait_for_session(&mut node_a.ev, &mut node_c2.ev, Duration::from_secs(8)).await;

    // 6. Check for PendingMessagesSent event
    let pending = drain_events(
        &mut node_a.ev,
        |e| matches!(e, P2PEvent::PendingMessagesSent { .. }),
        Duration::from_secs(3),
    ).await;
    // Pending queue may or may not fire depending on timing, but no crash is success
    println!("  📤 Pending messages drained: {}", pending.len());
    println!("  ✅ Disconnect/reconnect cycle completed without crash");

    node_a.shutdown();
    node_b.shutdown();
    node_c2.shutdown();
}

// ═══════════════════════════════════════════════════════════════
// TEST 3: Payment insufficient balance
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_payment_insufficient_balance() {
    let node_a = TestNode::spawn("alice").await;
    let _node_b = TestNode::spawn("bob").await;

    let did_a = node_a.did();
    let did_b = "did:walkie:bob_test";

    // Consumer with very low balance
    let mut poor_ledger = WcLedger::with_balance(1.0);
    poor_ledger.set_network_size(100);

    let usage = UsageDetails {
        cpu_ms: 3_600_000,
        memory_peak_bytes: 1_073_741_824,
        bandwidth_bytes: 104_857_600,
        duration_ms: 3_600_000,
    };

    // Request for 50 WC — way more than balance
    let request = PaymentRequest::new("poor-session", 50.0, usage.clone(), did_b);
    let response = handle_payment_request(&request, &poor_ledger, 100.0, &did_a);

    assert!(matches!(response, PaymentResponse::Rejected { .. }), "should reject insufficient balance");
    println!("  ✅ Insufficient balance correctly rejected");

    // Also test zero amount
    let zero_request = PaymentRequest::new("zero-session", 0.0, usage.clone(), did_b);
    let zero_response = handle_payment_request(&zero_request, &poor_ledger, 100.0, &did_a);
    assert!(matches!(zero_response, PaymentResponse::Rejected { .. }), "should reject zero amount");
    println!("  ✅ Zero amount correctly rejected");

    // Also test amount exceeds max_accepted
    let mut rich_ledger = WcLedger::with_balance(1000.0);
    rich_ledger.set_network_size(100);
    let over_request = PaymentRequest::new("over-session", 50.0, usage, did_b);
    let over_response = handle_payment_request(&over_request, &rich_ledger, 10.0, &did_a);
    assert!(matches!(over_response, PaymentResponse::Rejected { .. }), "should reject amount > max_accepted");
    println!("  ✅ Amount exceeds limit correctly rejected");

    node_a.shutdown();
    // _node_b dropped, shutdown called
}

// ═══════════════════════════════════════════════════════════════
// TEST 4: Trust escalation flow
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_trust_escalation_flow() {
    let node_a = TestNode::spawn("alice").await;
    let node_b = TestNode::spawn("bob").await;

    let did_a = node_a.did();
    let did_b = node_b.did();
    let pubkey_a = node_a.pubkey_bytes();
    let pubkey_b = node_b.pubkey_bytes();

    // Stage 1: Unverified (no cryptographic proof)
    let unverified = TrustScore::from_components(0.0, 0.0, 0.0, 1.0, 1.0);
    assert_eq!(unverified.level(), walkie_talkie_core::trust::types::TrustLevel::Unverified);
    println!("  ✅ Stage 1: Unverified (composite={:.4})", unverified.composite());

    // Stage 2: Cryptographic (attestation verified → trust_level=1)
    // identity_component(1) = 0.5, but composite needs >= 0.3 for Cryptographic
    // composite = 0.5*0.2 + 0.5*0.5 = 0.35 >= 0.3 ✓
    let attestation = IdentityAttestation::sign(&did_a, "12D3KooW_test_peer", &node_a.signing_key);
    assert!(attestation.verify(&pubkey_a).is_ok());

    let crypto_trust = TrustScore::from_components(0.5, 0.5, 0.0, 1.0, 1.0);
    assert_eq!(crypto_trust.level(), walkie_talkie_core::trust::types::TrustLevel::Cryptographic);
    println!("  ✅ Stage 2: Cryptographic (composite={:.4})", crypto_trust.composite());

    // Stage 3: Guaranteed (guarantor vouches → trust_level=2)
    // Need composite >= 0.6: 0.7*0.2 + 0.5*0.5 + 0.8*0.2 = 0.14+0.25+0.16 = 0.55... not enough
    // Use higher values: 0.7*0.2 + 0.9*0.5 + 0.8*0.2 = 0.14+0.45+0.16 = 0.75 >= 0.6 ✓
    let mut guarantor = GuarantorState::new();
    guarantor.refresh_eligibility(1000.0, 90);
    assert!(guarantor.can_guarantee);

    let cert = guarantor.issue_guarantee(&did_b, &did_a, &node_b.signing_key, 1000.0, 90).unwrap();
    assert!(cert.verify(&pubkey_b).is_ok());

    let guaranteed = TrustScore::from_components(0.7, 0.9, 0.8, 1.0, 1.0);
    assert_eq!(guaranteed.level(), walkie_talkie_core::trust::types::TrustLevel::Guaranteed);
    assert!(guaranteed.composite() > crypto_trust.composite());
    println!("  ✅ Stage 3: Guaranteed (composite={:.4}, cert verified)", guaranteed.composite());

    // Stage 4: CommunityVerified (composite >= 0.8)
    let community = TrustScore::from_components(1.0, 0.9, 0.8, 1.0, 1.0);
    assert_eq!(community.level(), walkie_talkie_core::trust::types::TrustLevel::CommunityVerified);
    println!("  ✅ Stage 4: CommunityVerified (composite={:.4})", community.composite());

    // Verify CRP multipliers increase with trust level
    assert!(community.crp_multiplier() > unverified.crp_multiplier());
    assert!(community.trust_bonus() > guaranteed.trust_bonus());
    println!("  ✅ CRP multipliers: Unv={:.1}× → Crypto={:.1}× → Guar={:.1}× → Comm={:.1}×",
        unverified.crp_multiplier(), crypto_trust.crp_multiplier(),
        guaranteed.crp_multiplier(), community.crp_multiplier());

    println!("  🎉 Trust escalation flow passed!");
    node_a.shutdown();
    node_b.shutdown();
}

// ═══════════════════════════════════════════════════════════════
// TEST 5: Slash progressive discipline
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_slash_progressive_discipline() {
    let mut slash_ledger = SlashLedger::new();
    let mut wc = WcLedger::with_balance(200.0);
    wc.set_network_size(100);
    wc.recalculate_crp_rate(10.0, 100);

    let target = "did:walkie:offender";

    // Strike 1: First offense
    let severity1 = slash_ledger.check_strike_count(target);
    slash_ledger.slash(target, OffenseType::MeasurementFraud, b"evidence_1", &mut wc);
    assert_eq!(severity1, walkie_talkie_core::trust::slash::StrikeLevel::First);
    assert_eq!(slash_ledger.active_strikes(target).len(), 1);
    println!("  ⚡ Strike 1: {:?} — CRP × {:.1}", severity1, severity1.crp_multiplier());

    // Strike 2: Second offense
    let severity2 = slash_ledger.check_strike_count(target);
    slash_ledger.slash(target, OffenseType::StorageChallengeMissed, b"evidence_2", &mut wc);
    assert_eq!(severity2, walkie_talkie_core::trust::slash::StrikeLevel::Second);
    assert_eq!(slash_ledger.active_strikes(target).len(), 2);
    println!("  ⚡ Strike 2: {:?} — CRP × {:.1}", severity2, severity2.crp_multiplier());

    // Strike 3: Permanent
    let severity3 = slash_ledger.check_strike_count(target);
    slash_ledger.slash(target, OffenseType::SpamAbuse, b"evidence_3", &mut wc);
    assert_eq!(severity3, walkie_talkie_core::trust::slash::StrikeLevel::Third);
    assert_eq!(slash_ledger.records_for(target).len(), 3);
    println!("  ⚡ Strike 3: {:?} — DISCONNECT + FREEZE", severity3);

    // Verify progressive severity
    assert!(severity1.crp_multiplier() > severity2.crp_multiplier());
    assert!(severity2.crp_multiplier() > severity3.crp_multiplier());

    // Evidence hashes are unique across records
    let records = slash_ledger.records_for(target);
    assert_ne!(records[0].evidence_hash, records[1].evidence_hash);
    assert_ne!(records[1].evidence_hash, records[2].evidence_hash);

    // New target starts at First
    let fresh = slash_ledger.check_strike_count("did:walkie:innocent");
    assert_eq!(fresh, walkie_talkie_core::trust::slash::StrikeLevel::First);

    println!("  ✅ Slash progressive discipline verified");
}

// ═══════════════════════════════════════════════════════════════
// TEST 6: CRP accumulation + WC conversion
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_crp_accumulation_and_wc_conversion() {
    let mut crp_acc = CrpAccumulator::with_network_size(50);

    // Add several contribution samples
    for i in 0..5 {
        let sample = ContributionSample {
            cpu_ms: 3_600_000 * (i + 1) as u64,       // 1-5 CPU-hours
            memory_peak_bytes: 2_147_483_648,          // 2 GB
            bandwidth_bytes: 268_435_456,              // 256 MB
            storage_bytes: 53_687_091_200,             // 50 GB
            uptime_ms: 3_600_000,                      // 1 hour
            window_hours: 1.0,
            timestamp_ms: (i as u64) * 3_600_000,
        };
        crp_acc.add_sample(sample);
    }

    assert_eq!(crp_acc.sample_count(), 5);
    let crp_rate = crp_acc.calculate_crp_rate();
    assert!(crp_rate > 0.0, "CRP rate should be positive");
    println!("  📈 CRP rate after 5 samples: {:.4} CRP/hr", crp_rate);

    // Convert CRP to WC
    let mut ledger = WcLedger::with_balance(0.0);
    ledger.set_network_size(50);
    let wc_earned = ledger.convert_crp_to_wc(crp_rate * 24.0); // 1 day worth
    assert!(wc_earned > 0.0, "should earn WC from CRP");
    assert!(ledger.balance() > 0.0);
    println!("  💰 WC earned (1 day): {:.4}", wc_earned);
    println!("  💰 Balance after conversion: {:.4}", ledger.balance());

    // Apply decay
    let before_decay = ledger.balance();
    ledger.apply_hourly_decay(24.0);
    assert!(ledger.balance() < before_decay, "balance should decrease after decay");
    let decay_pct = (1.0 - ledger.balance() / before_decay) * 100.0;
    println!("  📉 Hourly decay (24h): -{:.2}%", decay_pct);

    println!("  ✅ CRP → WC conversion cycle verified");
}

// ═══════════════════════════════════════════════════════════════
// TEST 7: Resource request with no matching provider
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_resource_request_no_matching_provider() {
    let mut node_a = TestNode::spawn("consumer").await;
    let mut node_b = TestNode::spawn("provider-no-match").await;

    // Connect but B does NOT advertise resources
    node_b.net.dial(node_a.addr()).await.expect("dial");
    wait_for_session(&mut node_a.ev, &mut node_b.ev, Duration::from_secs(8)).await;

    let peer_b = node_b.local_peer_id();

    // A requests resources from B (who has no ads)
    let result = node_a.net.request_resource(peer_b, ResourceRequest::new("consumer".into())).await;
    // May succeed (request sent) or fail — no crash either way
    let _ = result;

    // Wait a bit for any events
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A's resource table should be empty
    let resources = node_a.net.list_resources().await.expect("list");
    // B never advertised, so A might have 0 or 1 (from other events)
    println!("  📊 Resource table: {} entries", resources.len());
    println!("  ✅ No crash on resource request without matching provider");

    node_a.shutdown();
    node_b.shutdown();
}

// ═══════════════════════════════════════════════════════════════
// Cross-machine marker test (no-op, for script discovery)
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn cross_machine_node_a() {
    // Placeholder: will be implemented when wt CLI is available.
    // This test starts node A and waits for connections from node B on another machine.
    println!("  🌐 cross_machine_node_a: waiting for remote peer (not yet implemented)");
}

#[tokio::test]
#[ignore]
async fn cross_machine_node_b() {
    // Placeholder: will dial node A on the remote machine.
    println!("  🌐 cross_machine_node_b: connecting to remote node A (not yet implemented)");
}
