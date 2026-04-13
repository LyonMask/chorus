//! Consumer-side measurement and endorsement cross-validation.
//!
//! When a provider releases resources after use, the consumer independently
//! measures how much was actually consumed and compares it to the provider's
//! claimed amount.  Discrepancies beyond the tolerance threshold are flagged
//! as Suspicious or Fraud.
//!
//! # Flow
//!
//! ```text
//! Provider: release_and_prove(receipt)
//!   → sends WorkReceipt to consumer
//! Consumer: validate_measurement(provider_claimed, consumer_measured)
//!   → EndorsementResult::Honest / Suspicious / Fraud
//! Consumer: sends EndorsementResponse back
//! Provider: records endorsement history
//! ```

use super::types::{EndorsementResult, MEASUREMENT_TOLERANCE_PERCENT};

// ── ConsumerMeasurement ─────────────────────────────────────────

/// Independent measurement from the consumer side.
///
/// Tracks when a resource session started/ended and what was allocated,
/// so the consumer can verify the provider's claimed usage.
#[derive(Debug, Clone)]
pub struct ConsumerMeasurement {
    /// Unique session identifier.
    pub session_id: String,
    /// Consumer DID.
    pub consumer_did: String,
    /// Provider DID.
    pub provider_did: String,
    /// Unix timestamp (ms) when the session started.
    pub started_at: u64,
    /// Unix timestamp (ms) when the session ended (0 if still active).
    pub ended_at: u64,
    /// Allocated CPU cores (fractional, e.g. 0.8 = 80% of 1 core).
    pub allocated_cpu: f32,
    /// Allocated memory in MB.
    pub allocated_memory_mb: u64,
}

impl ConsumerMeasurement {
    /// Create a new measurement at session start.
    pub fn new(
        session_id: String,
        consumer_did: String,
        provider_did: String,
        allocated_cpu: f32,
        allocated_memory_mb: u64,
    ) -> Self {
        Self {
            session_id,
            consumer_did,
            provider_did,
            started_at: now_ms(),
            ended_at: 0,
            allocated_cpu,
            allocated_memory_mb,
        }
    }

    /// Mark the session as ended.
    pub fn end(&mut self) {
        if self.ended_at == 0 {
            self.ended_at = now_ms();
        }
    }

    /// Duration in milliseconds (0 if session hasn't ended).
    pub fn duration_ms(&self) -> u64 {
        self.ended_at.saturating_sub(self.started_at)
    }

    /// Expected CPU consumption in CPU·ms.
    ///
    /// `duration × allocated_cpu` — e.g. 2000ms × 0.5 core = 1000 CPU·ms.
    pub fn expected_cpu_ms(&self) -> u64 {
        (self.allocated_cpu * self.duration_ms() as f32) as u64
    }

    /// Expected memory consumption in MB·ms (duration × allocated memory).
    pub fn expected_memory_mb_ms(&self) -> u64 {
        self.allocated_memory_mb * self.duration_ms()
    }

    /// Whether the session is still active.
    pub fn is_active(&self) -> bool {
        self.ended_at == 0
    }
}

// ── validate_measurement ────────────────────────────────────────

/// Compare the provider's claimed usage against the consumer's independent measurement.
///
/// Returns:
/// - `Honest` if within `MEASUREMENT_TOLERANCE_PERCENT` (10%)
/// - `Suspicious` if 10%–50% discrepancy
/// - `Fraud` if >50% discrepancy
pub fn validate_measurement(provider_claimed: u64, consumer_measured: u64) -> EndorsementResult {
    if consumer_measured == 0 {
        // Consumer measured nothing — provider is definitely lying
        if provider_claimed > 0 {
            let discrepancy = 100.0;
            return EndorsementResult::Fraud { discrepancy_percent: discrepancy };
        }
        return EndorsementResult::Honest;
    }

    let ratio = provider_claimed as f64 / consumer_measured as f64;
    let tolerance = MEASUREMENT_TOLERANCE_PERCENT / 100.0; // 0.10

    if (ratio - 1.0).abs() <= tolerance {
        EndorsementResult::Honest
    } else {
        let discrepancy = (ratio - 1.0).abs() * 100.0;
        if discrepancy < 50.0 {
            EndorsementResult::Suspicious { discrepancy_percent: discrepancy }
        } else {
            EndorsementResult::Fraud { discrepancy_percent: discrepancy }
        }
    }
}

// ── EndorsementRecord ───────────────────────────────────────────

/// A permanent record of an endorsement (or fraud detection).
#[derive(Debug, Clone)]
pub struct EndorsementRecord {
    /// Provider DID being endorsed.
    pub provider: String,
    /// Session ID that was evaluated.
    pub session_id: String,
    /// CPU·ms claimed by provider.
    pub provider_claimed: u64,
    /// CPU·ms measured by consumer.
    pub consumer_measured: u64,
    /// Consumer DID that issued this endorsement.
    pub consumer_did: String,
    /// Unix timestamp (ms).
    pub timestamp: u64,
    /// Outcome of the validation.
    pub result: EndorsementResult,
}

impl EndorsementRecord {
    /// Create a new endorsement record.
    pub fn new(
        provider: String,
        session_id: String,
        provider_claimed: u64,
        consumer_measured: u64,
        consumer_did: String,
    ) -> Self {
        let result = validate_measurement(provider_claimed, consumer_measured);
        Self {
            provider,
            session_id,
            provider_claimed,
            consumer_measured,
            consumer_did,
            timestamp: now_ms(),
            result,
        }
    }
}

// ── EndorsementHistory ──────────────────────────────────────────

/// Tracks endorsement history for a provider.
///
/// Computes V_endorsement = sum(endorsed) / sum(claimed) for reputation scoring.
#[derive(Debug, Clone, Default)]
pub struct EndorsementHistory {
    records: Vec<EndorsementRecord>,
}

impl EndorsementHistory {
    pub fn new() -> Self {
        Self { records: Vec::new() }
    }

    /// Record a new endorsement.
    pub fn record(&mut self, entry: EndorsementRecord) {
        self.records.push(entry);
    }

    /// Compute V_endorsement = sum(endorsed_cpu) / sum(claimed_cpu).
    ///
    /// - 1.0 = perfect honesty
    /// - 0.8+ = HONEST (normal CRP)
    /// - 0.5–0.8 = WARNING (CRP × 0.5)
    /// - <0.5 = FRAUD (slash)
    pub fn endorsement_score(&self) -> f64 {
        let total_claimed: u64 = self.records.iter().map(|r| r.provider_claimed).sum();
        let total_endorsed: u64 = self.records.iter().map(|r| r.consumer_measured).sum();
        if total_claimed == 0 {
            return 1.0; // no claims = perfect score by default
        }
        total_endorsed as f64 / total_claimed as f64
    }

    /// Count of endorsements by result type.
    pub fn count_by_result(&self, result: EndorsementResult) -> usize {
        self.records.iter().filter(|r| r.result == result).count()
    }

    /// Total number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ── Helper ──────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consumer_measurement_normal() {
        let m = ConsumerMeasurement::new(
            "sess-1".into(), "did:c".into(), "did:p".into(), 0.8, 4096,
        );
        assert!(m.is_active());
        assert_eq!(m.duration_ms(), 0);
        assert_eq!(m.expected_cpu_ms(), 0);
    }

    #[test]
    fn test_consumer_measurement_after_end() {
        let mut m = ConsumerMeasurement::new(
            "sess-2".into(), "did:c".into(), "did:p".into(), 0.5, 2048,
        );
        // Simulate 2 seconds of usage
        m.started_at = now_ms() - 2000;
        m.end();
        assert!(!m.is_active());
        assert!(m.duration_ms() >= 1990); // allow 10ms slack
        // expected = 0.5 × 2000ms = 1000 CPU·ms
        let expected = m.expected_cpu_ms();
        assert!(expected >= 990 && expected <= 1010, "expected ~1000, got {expected}");
    }

    #[test]
    fn test_zero_duration() {
        let mut m = ConsumerMeasurement::new(
            "sess-3".into(), "did:c".into(), "did:p".into(), 1.0, 8192,
        );
        m.end(); // ended immediately (duration ≈ 0)
        assert_eq!(m.expected_cpu_ms(), 0);
        assert_eq!(m.expected_memory_mb_ms(), 0);
    }

    #[test]
    fn test_validate_honest_within_tolerance() {
        // Provider claims 1000, consumer measured 950 (5% off) → Honest
        let r = validate_measurement(1000, 950);
        assert_eq!(r, EndorsementResult::Honest);

        // Provider claims 1000, consumer measured 1050 (5% off) → Honest
        let r = validate_measurement(1000, 1050);
        assert_eq!(r, EndorsementResult::Honest);
    }

    #[test]
    fn test_validate_exact_match() {
        let r = validate_measurement(1000, 1000);
        assert_eq!(r, EndorsementResult::Honest);
    }

    #[test]
    fn test_validate_suspicious() {
        // Provider claims 1000, consumer measured 800 (25% off) → Suspicious
        let r = validate_measurement(1000, 800);
        assert!(matches!(r, EndorsementResult::Suspicious { .. }));
        if let EndorsementResult::Suspicious { discrepancy_percent } = r {
            assert!((discrepancy_percent - 25.0).abs() < 0.1);
        }
    }

    #[test]
    fn test_validate_fraud() {
        // Provider claims 1000, consumer measured 400 (150% off) → Fraud
        let r = validate_measurement(1000, 400);
        assert!(matches!(r, EndorsementResult::Fraud { .. }));
    }

    #[test]
    fn test_validate_zero_consumer_measurement() {
        // Consumer measured 0 but provider claims something → Fraud
        let r = validate_measurement(1000, 0);
        assert!(matches!(r, EndorsementResult::Fraud { .. }));

        // Both zero → Honest (trivial case)
        let r = validate_measurement(0, 0);
        assert_eq!(r, EndorsementResult::Honest);
    }

    #[test]
    fn test_tolerance_boundary() {
        // 9.9% off → should be Honest (within 10% tolerance)
        let r = validate_measurement(1099, 1000);
        assert_eq!(r, EndorsementResult::Honest);

        // 11% off → Suspicious
        let r = validate_measurement(1110, 1000);
        assert!(matches!(r, EndorsementResult::Suspicious { .. }));
    }

    #[test]
    fn test_endorsement_record_creation() {
        let rec = EndorsementRecord::new(
            "did:p".into(), "sess-1".into(), 1000, 950, "did:c".into(),
        );
        assert_eq!(rec.provider, "did:p");
        assert_eq!(rec.result, EndorsementResult::Honest);
        assert!(rec.timestamp > 0);
    }

    #[test]
    fn test_endorsement_history_score() {
        let mut history = EndorsementHistory::new();

        // Two honest endorsements
        history.record(EndorsementRecord::new("p".into(), "s1".into(), 1000, 950, "c1".into()));
        history.record(EndorsementRecord::new("p".into(), "s2".into(), 2000, 1900, "c2".into()));

        let score = history.endorsement_score();
        // V = (950 + 1900) / (1000 + 2000) = 2850 / 3000 = 0.95
        assert!((score - 0.95).abs() < 0.01, "expected ~0.95, got {score}");
    }

    #[test]
    fn test_endorsement_history_fraud_score() {
        let mut history = EndorsementHistory::new();

        // One fraud
        history.record(EndorsementRecord::new("p".into(), "s1".into(), 5000, 1000, "c1".into()));

        let score = history.endorsement_score();
        // V = 1000 / 5000 = 0.2 → FRAUD threshold
        assert!((score - 0.2).abs() < 0.01);
        let fraud_count = history.records.iter().filter(|r| matches!(r.result, EndorsementResult::Fraud { .. })).count();
        assert_eq!(fraud_count, 1);
    }

    #[test]
    fn test_endorsement_history_empty() {
        let history = EndorsementHistory::new();
        assert_eq!(history.endorsement_score(), 1.0);
        assert!(history.is_empty());
    }
}
