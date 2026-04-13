//! Proof of Contribution types (D3 spec — layered PoC).
//!
//! Per 驚羽 review: PoR-lite (random sampling) instead of Merkle Tree.
//! Three proof types:
//! - WorkReceipt: CPU/memory contributions
//! - StorageProof: storage contributions (PoR-lite)
//! - BandwidthReceipt: bandwidth contributions (bilateral ack)

use crate::resource::types::now_ms;
use serde::{Deserialize, Serialize};

// ── CPU / Memory: Work Receipt ──────────────────────────────────

/// CPU/memory contribution proof: signed work receipt from provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkReceipt {
    /// Consumer's DID.
    pub consumer: String,
    /// Provider's DID.
    pub provider: String,
    /// Associated resource session ID.
    pub session_id: String,
    /// Cumulative CPU time used (core·ms).
    pub cpu_used_ms: u64,
    /// Peak memory usage in bytes.
    pub memory_peak_bytes: u64,
    /// Task duration in ms.
    pub duration_ms: u64,
    /// Measurement window start (ms).
    pub window_start: u64,
    /// Measurement window end (ms).
    pub window_end: u64,
    /// Provider's Ed25519 signature.
    #[serde(default)]
    pub provider_signature: Vec<u8>,

    /// Consumer's Ed25519 countersignature (Phase 4).
    #[serde(default)]
    pub consumer_signature: Vec<u8>,
}

impl WorkReceipt {
    pub fn new(
        consumer: String,
        provider: String,
        session_id: String,
        cpu_ms: u64,
        mem_peak: u64,
        duration_ms: u64,
    ) -> Self {
        let now = now_ms();
        Self {
            consumer,
            provider,
            session_id,
            cpu_used_ms: cpu_ms,
            memory_peak_bytes: mem_peak,
            duration_ms,
            window_start: now.saturating_sub(duration_ms),
            window_end: now,
            provider_signature: Vec::new(),
            consumer_signature: Vec::new(),
        }
    }

    /// Compute a proof hash for the contribution record.
    ///
    /// Uses blake3 for deterministic, cross-platform hashing. Unlike
    /// DefaultHasher, blake3 produces identical output across all
    /// platforms and Rust versions, which is required for multi-node
    /// verification of contribution proofs.
    pub fn proof_hash(&self) -> String {
        let data = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.consumer,
            self.provider,
            self.session_id,
            self.cpu_used_ms,
            self.memory_peak_bytes,
            self.window_start,
            self.window_end,
        );
        blake3::hash(data.as_bytes()).to_hex().to_string()
    }

    /// Check basic validity: non-negative values, sane time window.
    pub fn is_valid(&self) -> bool {
        self.window_end >= self.window_start
            && self.duration_ms > 0
            && !self.consumer.is_empty()
            && !self.provider.is_empty()
    }
}

// ── Storage: PoR-lite (random sampling) ─────────────────────────
// Per 驚羽意見2: No Merkle Tree. Random sampling is sufficient for Phase 2.

/// A storage challenge (consumer asks provider to prove data is still stored).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StorageChallenge {
    /// Challenger (consumer) DID.
    pub challenger: String,
    /// Responder (provider) DID.
    pub responder: String,
    /// Storage session ID.
    pub session_id: String,
    /// Random data ID to challenge.
    pub data_id: String,
    /// Random offset within the data.
    pub offset: u64,
    /// Number of bytes to return.
    pub length: u32,
    /// Challenge timestamp.
    pub timestamp: u64,
    /// Challenge expires after this many ms (default 30s).
    pub expires_in_ms: u64,
}

impl StorageChallenge {
    pub fn new(
        challenger: String,
        responder: String,
        session_id: String,
        data_id: String,
        offset: u64,
        length: u32,
    ) -> Self {
        Self {
            challenger,
            responder,
            session_id,
            data_id,
            offset,
            length,
            timestamp: now_ms(),
            expires_in_ms: 30_000,
        }
    }

    /// Check if the challenge has expired.
    pub fn is_expired(&self) -> bool {
        now_ms() > self.timestamp + self.expires_in_ms
    }
}

/// Response to a storage challenge (PoR-lite).
///
/// Instead of Merkle proof, the provider returns the actual data slice
/// + HMAC-SHA256 for integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StorageProof {
    /// The challenge being responded to.
    pub challenge_id: String, // composite: session_id:data_id:offset
    /// The requested data slice.
    pub data_slice: Vec<u8>,
    /// HMAC-SHA256(data_slice, session_key) for integrity.
    pub hmac: Vec<u8>,
    /// Response timestamp.
    pub responded_at: u64,
    /// Responder's Ed25519 signature.
    #[serde(default)]
    pub responder_signature: Vec<u8>,
}

impl StorageProof {
    pub fn new(challenge_id: String, data_slice: Vec<u8>, hmac: Vec<u8>) -> Self {
        Self {
            challenge_id,
            data_slice,
            hmac,
            responded_at: now_ms(),
            responder_signature: Vec::new(),
        }
    }
}

/// PoR-lite verifier: statistical validity check.
#[derive(Debug)]
pub struct PoRVerifier {
    /// Number of successful challenges.
    pub successes: u32,
    /// Number of failed challenges.
    pub failures: u32,
}

impl Default for PoRVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl PoRVerifier {
    pub fn new() -> Self {
        Self {
            successes: 0,
            failures: 0,
        }
    }

    /// Record a successful challenge.
    pub fn record_success(&mut self) {
        self.successes += 1;
    }

    /// Record a failed challenge.
    pub fn record_failure(&mut self) {
        self.failures += 1;
    }

    /// Probability that the data is actually stored, based on sampling.
    ///
    /// With n successful samples out of n total, confidence ≈ 1 - (1-p)^n
    /// where p is the fraction of data actually stored.
    /// For simplicity, if all passed: confidence = 1 - 0.5^n.
    pub fn confidence(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            return 0.0;
        }
        if self.failures > 0 {
            // If any failure, confidence drops proportionally.
            return self.successes as f64 / total as f64;
        }
        // All successes: 1 - (0.5)^n ≈ 99.9% for n=10.
        1.0 - (0.5_f64).powi(total as i32)
    }

    /// Is the confidence above the minimum threshold (default 0.9)?
    pub fn is_trusted(&self) -> bool {
        self.confidence() >= 0.9
    }
}

// ── Bandwidth: Bilateral Acknowledgment ─────────────────────────

/// Bandwidth contribution proof: dual-signed receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BandwidthReceipt {
    /// Transfer direction.
    pub direction: String, // "upload" | "download" | "relay"
    /// Sender's DID.
    pub sender: String,
    /// Receiver's DID.
    pub receiver: String,
    /// Bytes actually transferred.
    pub bytes_transferred: u64,
    /// Transfer start time (ms).
    pub started_at: u64,
    /// Transfer end time (ms).
    pub ended_at: u64,
    /// Sender's signature.
    #[serde(default)]
    pub sender_signature: Vec<u8>,
    /// Receiver's signature (confirms receipt).
    #[serde(default)]
    pub receiver_signature: Vec<u8>,
}

impl BandwidthReceipt {
    pub fn new(
        direction: String,
        sender: String,
        receiver: String,
        bytes: u64,
    ) -> Self {
        let now = now_ms();
        Self {
            direction,
            sender,
            receiver,
            bytes_transferred: bytes,
            started_at: now,
            ended_at: now,
            sender_signature: Vec::new(),
            receiver_signature: Vec::new(),
        }
    }

    /// Check that both parties have signed.
    pub fn is_fully_signed(&self) -> bool {
        !self.sender_signature.is_empty() && !self.receiver_signature.is_empty()
    }

    /// Compute throughput in bytes/sec.
    pub fn throughput_bps(&self) -> f64 {
        let duration_ms = self.ended_at.saturating_sub(self.started_at);
        if duration_ms == 0 {
            return 0.0;
        }
        self.bytes_transferred as f64 / (duration_ms as f64 / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_receipt_validity() {
        let receipt = WorkReceipt::new(
            "consumer".into(),
            "provider".into(),
            "session-1".into(),
            5000,
            1024 * 1024,
            10_000,
        );
        assert!(receipt.is_valid());
        assert!(!receipt.proof_hash().is_empty());
    }

    #[test]
    fn test_work_receipt_invalid_empty_fields() {
        let receipt = WorkReceipt {
            consumer: String::new(),
            provider: "p".into(),
            session_id: "s".into(),
            cpu_used_ms: 0,
            memory_peak_bytes: 0,
            duration_ms: 0,
            window_start: 0,
            window_end: 0,
            provider_signature: Vec::new(),
            consumer_signature: Vec::new(),
        };
        assert!(!receipt.is_valid());
    }

    #[test]
    fn test_storage_challenge_expiry() {
        let mut challenge = StorageChallenge::new(
            "challenger".into(),
            "responder".into(),
            "session-1".into(),
            "data-1".into(),
            0,
            1024,
        );
        assert!(!challenge.is_expired());

        // Backdate.
        challenge.timestamp = now_ms().saturating_sub(60_000);
        challenge.expires_in_ms = 30_000;
        assert!(challenge.is_expired());
    }

    #[test]
    fn test_por_verifier_confidence() {
        let mut verifier = PoRVerifier::new();

        // 0 samples → 0% confidence.
        assert_eq!(verifier.confidence(), 0.0);

        // 1 success → 50% confidence.
        verifier.record_success();
        assert!((verifier.confidence() - 0.5).abs() < 0.01);

        // 10 successes → 99.9% confidence.
        for _ in 0..9 {
            verifier.record_success();
        }
        assert!(verifier.confidence() > 0.999);
        assert!(verifier.is_trusted());
    }

    #[test]
    fn test_por_verifier_with_failure() {
        let mut verifier = PoRVerifier::new();
        verifier.record_success();
        verifier.record_success();
        verifier.record_failure();
        assert!((verifier.confidence() - 0.667).abs() < 0.01);
        assert!(!verifier.is_trusted());
    }

    #[test]
    fn test_bandwidth_receipt() {
        let receipt = BandwidthReceipt::new(
            "upload".into(),
            "sender".into(),
            "receiver".into(),
            1_048_576, // 1MB
        );
        assert!(!receipt.is_fully_signed());

        // With both signatures.
        let mut signed = receipt;
        signed.sender_signature = vec![1u8; 64];
        signed.receiver_signature = vec![2u8; 64];
        assert!(signed.is_fully_signed());
    }

    #[test]
    fn test_proof_hash_deterministic() {
        let r1 = WorkReceipt::new("c".into(), "p".into(), "s".into(), 100, 200, 300);
        // blake3 is deterministic: same input bytes → same hash every time.
        let h1 = r1.proof_hash();
        let h2 = r1.proof_hash();
        assert_eq!(h1, h2);
        // blake3 produces 64-char hex (256 bits).
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_proof_hash_different_inputs() {
        let r1 = WorkReceipt::new("c".into(), "p".into(), "s1".into(), 100, 200, 300);
        let r2 = WorkReceipt::new("c".into(), "p".into(), "s2".into(), 100, 200, 300);
        assert_ne!(r1.proof_hash(), r2.proof_hash());
    }

    #[test]
    fn test_proof_hash_known_value() {
        // Construct a receipt with controlled timestamp fields for known-value testing.
        let r = WorkReceipt {
            consumer: "alice".into(),
            provider: "bob".into(),
            session_id: "sess-42".into(),
            cpu_used_ms: 5000,
            memory_peak_bytes: 1048576,
            window_start: 1000000,
            window_end: 1005000,
            duration_ms: 5000,
            provider_signature: Vec::new(),
            consumer_signature: Vec::new(),
        };
        // blake3("alice:bob:sess-42:5000:1048576:1000000:1005000") → deterministic hex
        let expected = blake3::hash(b"alice:bob:sess-42:5000:1048576:1000000:1005000").to_hex().to_string();
        assert_eq!(r.proof_hash(), expected);
    }
}
