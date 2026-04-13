//! Contribution engine: end-to-end proof of contribution flow (D4-3 PoC).
//!
//! Integrates the layered PoC types from proof.rs with the session manager
//! and contribution ledger to provide a complete contribution verification pipeline:
//!
//! 1. Provider starts a resource session
//! 2. During the session, either side can issue challenges (PoR-lite)
//! 3. On session release, provider generates a WorkReceipt
//! 4. Consumer countersigns the receipt
//! 5. Both parties record to their local ContributionLedger
//! 6. Periodic random audits verify storage contributions

use crate::resource::backoff::RequestBackoff;
use crate::resource::proof::*;
use crate::resource::session::{ResourceSession, ResourceSessionManager};
use crate::resource::table::ResourceTable;
use crate::resource::types::*;

/// The contribution engine ties together all Phase 2 resource components.
///
/// Each node runs one ContributionEngine instance. It manages:
/// - Resource discovery (via ResourceTable)
/// - Session lifecycle (via ResourceSessionManager)
/// - Proof generation and verification
/// - Local contribution ledger
#[derive(Debug)]
pub struct ContributionEngine {
    /// Our own DID.
    pub agent_id: String,

    /// Our own resource advertisement.
    pub my_ad: Option<ResourceAdvertisement>,

    /// Known resources from other nodes.
    pub table: ResourceTable,

    /// Session manager for allocations we provide or consume.
    pub sessions: ResourceSessionManager,

    /// Local contribution ledger.
    pub ledger: ContributionLedger,

    /// PoR verifier for storage audits.
    pub por_verifier: PoRVerifier,

    /// Backoff tracker for outbound requests.
    pub backoff: RequestBackoff,

    /// Pending storage challenges we've issued (challenge_id → StorageChallenge).
    pub pending_challenges: std::collections::HashMap<String, StorageChallenge>,
}

impl ContributionEngine {
    /// Create a new engine for the given agent.
    pub fn new(agent_id: String) -> Self {
        Self {
            agent_id,
            my_ad: None,
            table: ResourceTable::new(),
            sessions: ResourceSessionManager::new(),
            ledger: ContributionLedger::default(),
            por_verifier: PoRVerifier::new(),
            backoff: RequestBackoff::new(),
            pending_challenges: std::collections::HashMap::new(),
        }
    }

    // ── Resource Declaration ──

    /// Declare our own resources. Returns the advertisement for broadcasting.
    pub fn declare_resources(&mut self, ad: ResourceAdvertisement) -> ResourceAdvertisement {
        let mut ad = ad;
        ad.bump();
        self.my_ad = Some(ad.clone());
        ad
    }

    /// Process an incoming resource advertisement from another node.
    pub fn on_resource_ad(&mut self, ad: ResourceAdvertisement) -> bool {
        self.table.update(ad)
    }

    // ── Resource Request Flow ──

    /// Find best candidates for a resource request.
    pub fn find_providers(&self, req: &ResourceRequest) -> Vec<ResourceCandidate> {
        self.table.find_candidates(req)
    }

    /// Check if we can accept a resource allocation on our node.
    pub fn can_accept(&self, cpu: f32, memory_mb: u64) -> bool {
        match &self.my_ad {
            Some(ad) => self.sessions.can_allocate(&self.agent_id, ad, cpu, memory_mb),
            None => false,
        }
    }

    /// Start providing a resource session. Returns session_id.
    pub fn start_providing(
        &mut self,
        consumer: String,
        cpu: f32,
        memory_mb: u64,
        duration_ms: u64,
    ) -> String {
        self.sessions.create_session(
            consumer,
            self.agent_id.clone(),
            cpu,
            memory_mb,
            duration_ms,
        )
    }

    /// Activate a session we're consuming (accept an offer).
    pub fn accept_session(&mut self, session_id: &str) -> bool {
        self.sessions.activate(session_id)
    }

    /// Release a resource session and generate contribution proof.
    ///
    /// This is the key flow: provider releases → generates WorkReceipt →
    /// records to ledger. Returns the receipt for the consumer to countersign.
    pub fn release_and_prove(&mut self, session_id: &str) -> Option<WorkReceipt> {
        let session = self.sessions.release(session_id)?;

        let declared_duration = session.ends_at.saturating_sub(session.started_at).max(1);

        let receipt = WorkReceipt::new(
            session.consumer.clone(),
            session.provider.clone(),
            session.session_id.clone(),
            (session.cpu_amount * declared_duration as f32) as u64,
            session.memory_amount_mb * 1024 * 1024, // MB → bytes
            declared_duration,
        );

        // Record in our ledger as provider.
        let record = ContributionRecord {
            provider: session.provider.clone(),
            consumer: session.consumer.clone(),
            resource_type: ResourceType::Cpu,
            declared_amount: session.amount,
            actual_amount: session.amount, // In Phase 2, trust the provider's measurement
            duration_ms: declared_duration,
            proof_hash: Some(receipt.proof_hash()),
            timestamp: now_ms(),
        };
        self.ledger.provided.push(record);

        Some(receipt)
    }

    /// Consumer records a countersigned receipt in their ledger.
    pub fn record_consumption(&mut self, receipt: &WorkReceipt) {
        let record = ContributionRecord {
            provider: receipt.provider.clone(),
            consumer: receipt.consumer.clone(),
            resource_type: ResourceType::Cpu,
            declared_amount: receipt.cpu_used_ms as f64,
            actual_amount: receipt.cpu_used_ms as f64,
            duration_ms: receipt.duration_ms,
            proof_hash: Some(receipt.proof_hash()),
            timestamp: now_ms(),
        };
        self.ledger.consumed.push(record);
    }

    // ── Storage Challenge Flow (PoR-lite) ──

    /// Issue a random storage challenge to a provider.
    pub fn issue_storage_challenge(
        &mut self,
        provider: &str,
        session_id: &str,
        data_id: &str,
        offset: u64,
        length: u32,
    ) -> StorageChallenge {
        let challenge = StorageChallenge::new(
            self.agent_id.clone(),
            provider.to_string(),
            session_id.to_string(),
            data_id.to_string(),
            offset,
            length,
        );
        let challenge_id = format!("{}:{}:{}", session_id, data_id, offset);
        self.pending_challenges
            .insert(challenge_id, challenge.clone());
        challenge
    }

    /// Verify a response to our storage challenge.
    pub fn verify_storage_proof(
        &mut self,
        proof: &StorageProof,
        expected_hmac: &[u8],
    ) -> bool {
        // 1. Check that we issued this challenge.
        if !self.pending_challenges.contains_key(&proof.challenge_id) {
            return false;
        }

        // 2. Verify HMAC.
        if proof.hmac != expected_hmac {
            self.por_verifier.record_failure();
            return false;
        }

        // 3. Check data slice is non-empty.
        if proof.data_slice.is_empty() {
            self.por_verifier.record_failure();
            return false;
        }

        // 4. Remove the challenge and record success.
        self.pending_challenges.remove(&proof.challenge_id);
        self.por_verifier.record_success();
        true
    }

    /// Check if our PoR verifier has enough confidence in a provider's storage.
    pub fn storage_trust_level(&self) -> f64 {
        self.por_verifier.confidence()
    }

    // ── Bandwidth Receipt Flow ──

    /// Create a bandwidth receipt for a completed transfer.
    pub fn record_bandwidth(
        &mut self,
        direction: String,
        peer: String,
        bytes: u64,
        duration_ms: u64,
    ) -> BandwidthReceipt {
        let is_upload = direction == "upload";
        let sender = if is_upload {
            self.agent_id.clone()
        } else {
            peer.clone()
        };
        let receiver = if is_upload {
            peer.clone()
        } else {
            self.agent_id.clone()
        };

        let mut receipt = BandwidthReceipt::new(direction, sender, receiver, bytes);
        receipt.started_at = now_ms().saturating_sub(duration_ms);
        receipt.ended_at = now_ms();
        receipt
    }

    // ── Maintenance ──

    /// Periodic maintenance: evict stale ads, expire sessions.
    pub fn tick(&mut self) -> MaintenanceReport {
        let evicted = self.table.evict_expired();
        let expired_sessions = self.sessions.expire_timed_out();
        let expired_offers = self.sessions.expire_stale_offers();

        MaintenanceReport {
            ads_evicted: evicted,
            sessions_expired: expired_sessions,
            offers_expired: expired_offers,
            total_provided: self.ledger.provided.len(),
            total_consumed: self.ledger.consumed.len(),
            active_sessions: self.sessions.list_by_status(SessionStatus::Active).len(),
            pending_sessions: self.sessions.list_by_status(SessionStatus::Pending).len(),
        }
    }

    /// Get our total contribution score.
    pub fn my_contribution_score(&self) -> f64 {
        self.ledger.total_contribution()
    }
}

/// Report from periodic maintenance.
#[derive(Debug, Clone, PartialEq)]
pub struct MaintenanceReport {
    pub ads_evicted: usize,
    pub sessions_expired: usize,
    pub offers_expired: usize,
    pub total_provided: usize,
    pub total_consumed: usize,
    pub active_sessions: usize,
    pub pending_sessions: usize,
}

/// Helper: compute session duration in ms.
trait DurationMs {
    #[allow(dead_code)]
    fn duration_ms(&self) -> u64;
}

impl DurationMs for ResourceSession {
    fn duration_ms(&self) -> u64 {
        match self.actual_end {
            Some(end) => end.saturating_sub(self.started_at),
            None => now_ms().saturating_sub(self.started_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine(agent_id: &str) -> ContributionEngine {
        ContributionEngine::new(agent_id.to_string())
    }

    fn make_ad_for(agent_id: &str, cpu: f32, mem: u64) -> ResourceAdvertisement {
        ResourceAdvertisement {
            agent_id: agent_id.to_string(),
            sequence: 1,
            timestamp: now_ms(),
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 0,
            },
            cpu_offer: cpu,
            memory_offer_mb: mem,
            bandwidth_offer: 0,
            storage_offer: 0,
            features: vec![],
            signature: Vec::new(),
        }
    }

    #[test]
    fn test_end_to_end_cpu_contribution() {
        // Provider side.
        let mut provider = make_engine("did:walkie:provider");
        let ad = make_ad_for("did:walkie:provider", 0.5, 4096);
        provider.declare_resources(ad);

        // Provider starts a session for a consumer.
        let sid = provider.start_providing("did:walkie:consumer".into(), 0.2, 1024, 60_000);
        provider.accept_session(&sid);

        // ... resource is used ...

        // Provider releases and generates proof.
        let receipt = provider.release_and_prove(&sid).unwrap();
        assert!(receipt.is_valid());
        assert_eq!(receipt.provider, "did:walkie:provider");
        assert_eq!(receipt.consumer, "did:walkie:consumer");

        // Consumer records the receipt.
        let mut consumer = make_engine("did:walkie:consumer");
        consumer.record_consumption(&receipt);
        assert_eq!(consumer.ledger.consumed.len(), 1);
        assert_eq!(consumer.ledger.consumed[0].provider, "did:walkie:provider");
    }

    #[test]
    fn test_resource_discovery_flow() {
        let mut engine = make_engine("did:walkie:consumer");

        // Receive ads from network.
        let ad1 = make_ad_for("node-small", 0.1, 512);
        let ad2 = make_ad_for("node-big", 0.8, 8192);
        assert!(engine.on_resource_ad(ad1));
        assert!(engine.on_resource_ad(ad2));

        // Find providers.
        let req = ResourceRequest {
            request_id: String::new(),
            consumer_id: "did:walkie:consumer".into(),
            min_cpu: 0.05,
            min_memory_mb: 256,
            min_bandwidth: 0,
            min_storage: 0,
            required_features: vec![],
            duration_ms: 60_000,
            priority: 75,
            expires_at: 0,
        };

        let candidates = engine.find_providers(&req);
        assert_eq!(candidates.len(), 2);
        // node-big should rank first.
        assert_eq!(candidates[0].agent_id, "node-big");
    }

    #[test]
    fn test_storage_challenge_flow() {
        let mut challenger = make_engine("did:walkie:consumer");

        // Issue a challenge.
        let challenge = challenger.issue_storage_challenge(
            "did:walkie:provider",
            "session-1",
            "data-abc",
            1024,
            512,
        );
        assert!(!challenge.is_expired());
        assert_eq!(challenger.pending_challenges.len(), 1);

        // Provider responds with proof.
        let proof = StorageProof::new(
            "session-1:data-abc:1024".into(),
            vec![42u8; 512],
            vec![99u8; 32], // mock HMAC
        );

        // Challenger verifies.
        let expected_hmac = vec![99u8; 32];
        assert!(challenger.verify_storage_proof(&proof, &expected_hmac));
        assert_eq!(challenger.pending_challenges.len(), 0); // challenge consumed

        // Confidence should be > 0 after one success.
        assert!(challenger.storage_trust_level() > 0.0);
    }

    #[test]
    fn test_storage_challenge_hmac_mismatch() {
        let mut challenger = make_engine("did:walkie:consumer");
        challenger.issue_storage_challenge("provider", "s1", "d1", 0, 100);

        let proof = StorageProof::new("s1:d1:0".into(), vec![1u8; 100], vec![1u8; 32]);
        assert!(!challenger.verify_storage_proof(&proof, &[0u8; 32]));
    }

    #[test]
    fn test_bandwidth_receipt_flow() {
        let mut engine = make_engine("did:walkie:node-a");

        let receipt = engine.record_bandwidth(
            "upload".into(),
            "did:walkie:node-b".into(),
            1_048_576,
            5_000,
        );

        assert_eq!(receipt.direction, "upload");
        assert_eq!(receipt.sender, "did:walkie:node-a");
        assert_eq!(receipt.receiver, "did:walkie:node-b");
        assert_eq!(receipt.bytes_transferred, 1_048_576);
    }

    #[test]
    fn test_maintenance_tick() {
        let mut engine = make_engine("did:walkie:test");
        let report = engine.tick();

        assert_eq!(report.ads_evicted, 0);
        assert_eq!(report.active_sessions, 0);
        assert_eq!(report.total_provided, 0);
    }

    #[test]
    fn test_backoff_on_rejection() {
        let mut engine = make_engine("did:walkie:consumer");

        // Simulate rejections.
        engine.backoff.on_reject();
        assert_eq!(engine.backoff.delay_ms(), 2000);

        engine.backoff.on_reject();
        assert_eq!(engine.backoff.delay_ms(), 4000);

        // Simulate acceptance.
        engine.backoff.on_accept();
        assert_eq!(engine.backoff.delay_ms(), 1000);
    }

    #[test]
    fn test_contribution_score() {
        let mut engine = make_engine("did:walkie:provider");
        let ad = make_ad_for("did:walkie:provider", 0.5, 4096);
        engine.declare_resources(ad);

        // Simulate multiple sessions.
        let s1 = engine.start_providing("c1".into(), 0.2, 1024, 3_600_000); // 1 hour
        engine.accept_session(&s1);
        engine.release_and_prove(&s1);

        let s2 = engine.start_providing("c2".into(), 0.1, 512, 7_200_000); // 2 hours
        engine.accept_session(&s2);
        engine.release_and_prove(&s2);

        assert!(engine.my_contribution_score() > 0.0);
        assert_eq!(engine.ledger.provided.len(), 2);
    }

    #[test]
    fn test_declare_resources_bumps_sequence() {
        let mut engine = make_engine("did:walkie:test");
        let ad = make_ad_for("did:walkie:test", 0.2, 2048);

        let ad1 = engine.declare_resources(ad);
        assert_eq!(ad1.sequence, 2);

        let ad2 = engine.declare_resources(ad1);
        assert_eq!(ad2.sequence, 3);
    }

    #[test]
    fn test_can_accept_within_limits() {
        let mut engine = make_engine("did:walkie:provider");
        let ad = make_ad_for("did:walkie:provider", 0.5, 4096);
        engine.declare_resources(ad);

        assert!(engine.can_accept(0.3, 2048));
        assert!(!engine.can_accept(0.6, 2048)); // over CPU limit
    }
}
