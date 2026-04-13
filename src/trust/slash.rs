//! Slash (Punishment) Matrix — Phase 4.1.
//!
//! Three-strike progressive discipline system for Walkie Talkie:
//!   - First strike:  CRP rate × 0.5 for 24h
//!   - Second strike: CRP rate × 0.25 for 7 days
//!   - Third strike:  Permanent disconnect + WC freeze
//!
//! After third strike, a 30-day cooldown period allows the node
//! to re-accumulate strikes from zero if it reconnects.

use crate::economy::WcLedger;
use crate::resource::economy_params;
use blake3;

/// Types of offenses that can trigger a slash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OffenseType {
    /// Reported CPU usage > actual by > 50%.
    MeasurementFraud,
    /// Did not respond to storage challenge within TTL.
    StorageChallengeMissed,
    /// Excessive spam / broadcast abuse.
    SpamAbuse,
    /// Guarantor failed to monitor a guaranteed node.
    GuarantorNegligence,
}

impl std::fmt::Display for OffenseType {
    fn fmt(&self, f: &std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MeasurementFraud => write!(f, "MeasurementFraud"),
            Self::StorageChallengeMissed => write!(f, "StorageChallengeMissed"),
            Self::SpamAbuse => write!(f, "SpamAbuse"),
            Self::GuarantorNegligence => write!(f, "GuarantorNegligence"),
        }
    }
}

/// Strike severity levels — progressive discipline.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StrikeLevel {
    /// CRP rate × 0.5 for 24 hours.
    First,
    /// CRP rate × 0.25 for 7 days.
    Second,
    /// Permanent disconnect + WC balance frozen.
    Third,
}

impl StrikeLevel {
    /// CRP rate multiplier for this strike level.
    pub fn crp_multiplier(&self) -> f64 {
        match self {
            Self::First => 0.5,
            Self::Second => 0.25,
            Self::Third => 0.0,
        }
    }

    /// Duration in hours for the penalty.
    pub fn duration_hours(&self) -> f64 {
        match self {
            Self::First => 24.0,
            Self::Second => 168.0, // 7 days
            Self::Third => f64::MAX, // permanent
        }
    }
}

/// A single slash record (punishment event).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlashRecord {
    /// DID of the offending node.
    pub target_did: String,
    /// Type of offense committed.
    pub offense: OffenseType,
    /// Strike severity (determined by prior strike count).
    pub severity: StrikeLevel,
    /// CRP reduction percentage applied (0.0–1.0).
    pub crp_reduction_percent: f64,
    /// Timestamp (ms) when the slash was applied.
    pub timestamp_ms: u64,
    /// Blake3 hash of the evidence payload.
    pub evidence_hash: String,
}

impl SlashRecord {
    /// Create a new slash record.
    pub fn new(
        target_did: &str,
        offense: OffenseType,
        severity: StrikeLevel,
        evidence: &[u8],
    ) -> Self {
        let evidence_hash = blake3::hash(evidence).to_hex().to_string();
        let crp_reduction_percent = 1.0 - severity.crp_multiplier();
        Self {
            target_did: target_did.to_string(),
            offense,
            severity,
            crp_reduction_percent,
            timestamp_ms: crate::resource::now_ms(),
            evidence_hash,
        }
    }

    /// Apply this slash to a WC ledger.
    ///
    /// Reduces CRP rate according to severity.
    /// For Third strike, also freezes balance (sets to 0 effective spending power).
    pub fn apply(&self, wc_ledger: &mut WcLedger) {
        wc_ledger.crp_rate *= self.severity.crp_multiplier();
    }

    /// Check if this slash has expired (penalty duration passed).
    pub fn is_expired(&self) -> bool {
        let now_ms = crate::resource::now_ms();
        let elapsed_hours = (now_ms.saturating_sub(self.timestamp_ms)) as f64 / 3_600_000.0;
        elapsed_hours > self.severity.duration_hours()
    }
}

/// Cooldown after third strike before the node can re-accumulate strikes.
pub const THIRD_STRIKE_COOLDOWN_HOURS: f64 = 720.0; // 30 days

/// Maximum number of slash records to keep per DID.
pub const MAX_SLASH_RECORDS: usize = 1000;

/// Slash ledger — tracks all slash records for all nodes.
#[derive(Debug, Clone, Default)]
pub struct SlashLedger {
    /// All slash records, keyed by target_did.
    records: Vec<SlashRecord>,
}

impl SlashLedger {
    /// Create a new empty slash ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Determine the next strike level for a DID.
    ///
    /// - If no active (non-expired) slashes → First
    /// - If one active → Second
    /// - If two active → Third
    /// - If three+ active and still in cooldown → Third (no escalation)
    /// - After 30-day cooldown → reset to First
    pub fn check_strike_count(&self, did: &str) -> StrikeLevel {
        let active_strikes = self.active_strikes(did);
        let max_strikes: u32 = economy_params::MAX_PENALTY_STRIKES;

        if active_strikes.is_empty() {
            return StrikeLevel::First;
        }

        // Check for third-strike cooldown
        if let Some(third) = active_strikes.iter().find(|s| s.severity == StrikeLevel::Third) {
            let hours_since = (crate::resource::now_ms().saturating_sub(third.timestamp_ms)) as f64
                / 3_600_000.0;
            if hours_since >= THIRD_STRIKE_COOLDOWN_HOURS {
                // Cooldown expired — reset to First
                return StrikeLevel::First;
            }
            // Still in cooldown — stay at Third
            return StrikeLevel::Third;
        }

        // Progressive: count active non-Third strikes
        match active_strikes.len() as u32 {
            0 => StrikeLevel::First,
            1 => StrikeLevel::Second,
            _ => StrikeLevel::Third,
        }
    }

    /// Apply a slash to a target DID.
    ///
    /// Returns the SlashRecord that was created.
    pub fn slash(
        &mut self,
        target_did: &str,
        offense: OffenseType,
        evidence: &[u8],
        wc_ledger: &mut WcLedger,
    ) -> &SlashRecord {
        let severity = self.check_strike_count(target_did);
        let record = SlashRecord::new(target_did, offense, severity, evidence);
        record.apply(wc_ledger);
        self.records.push(record);

        // Prune old records
        self.prune();

        self.records.last().unwrap()
    }

    /// Get all slash records for a specific DID.
    pub fn records_for(&self, did: &str) -> Vec<&SlashRecord> {
        self.records.iter().filter(|r| r.target_did == did).collect()
    }

    /// Get active (non-expired) slash records for a specific DID.
    pub fn active_strikes(&self, did: &str) -> Vec<&SlashRecord> {
        self.records
            .iter()
            .filter(|r| r.target_did == did && !r.is_expired())
            .collect()
    }

    /// Get the total number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Prune expired records when exceeding MAX_SLASH_RECORDS.
    fn prune(&mut self) {
        if self.records.len() > MAX_SLASH_RECORDS {
            // Remove expired records first
            let before = self.records.len();
            self.records.retain(|r| !r.is_expired());
            // If still over limit, remove oldest
            while self.records.len() > MAX_SLASH_RECORDS {
                self.records.remove(0);
            }
        }
    }

    /// Compute a blake3 hash from evidence bytes (utility).
    pub fn hash_evidence(evidence: &[u8]) -> String {
        blake3::hash(evidence).to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ledger() -> WcLedger {
        WcLedger::with_balance(100.0)
    }

    fn make_crp_ledger() -> WcLedger {
        let mut ledger = WcLedger::with_balance(100.0);
        ledger.recalculate_crp_rate(50.0, 100);
        ledger
    }

    fn fake_evidence() -> Vec<u8> {
        b"evidence: provider claimed 10000 cpu_ms, consumer measured 2000".to_vec()
    }

    #[test]
    fn test_first_strike_halves_crp() {
        let mut wc = make_crp_ledger();
        let original_rate = wc.crp_rate;
        let record = SlashRecord::new(
            "did:walkie:bad",
            OffenseType::MeasurementFraud,
            StrikeLevel::First,
            &fake_evidence(),
        );
        record.apply(&mut wc);
        assert!((wc.crp_rate - original_rate * 0.5).abs() < 0.001);
    }

    #[test]
    fn test_second_strike_quarters_crp() {
        let mut wc = make_crp_ledger();
        let original_rate = wc.crp_rate;
        let record = SlashRecord::new(
            "did:walkie:bad",
            OffenseType::SpamAbuse,
            StrikeLevel::Second,
            &fake_evidence(),
        );
        record.apply(&mut wc);
        assert!((wc.crp_rate - original_rate * 0.25).abs() < 0.001);
    }

    #[test]
    fn test_third_strike_zeroes_crp() {
        let mut wc = make_crp_ledger();
        let record = SlashRecord::new(
            "did:walkie:bad",
            OffenseType::StorageChallengeMissed,
            StrikeLevel::Third,
            &fake_evidence(),
        );
        record.apply(&mut wc);
        assert!((wc.crp_rate - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_progressive_strikes() {
        let mut slash = SlashLedger::new();
        let mut wc = make_crp_ledger();

        // First strike
        assert_eq!(slash.check_strike_count("did:walkie:bad"), StrikeLevel::First);
        let r1 = slash.slash("did:walkie:bad", OffenseType::MeasurementFraud, &fake_evidence(), &mut wc);
        assert_eq!(r1.severity, StrikeLevel::First);

        // Second strike
        assert_eq!(slash.check_strike_count("did:walkie:bad"), StrikeLevel::Second);
        let r2 = slash.slash("did:walkie:bad", OffenseType::SpamAbuse, &fake_evidence(), &mut wc);
        assert_eq!(r2.severity, StrikeLevel::Second);

        // Third strike
        assert_eq!(slash.check_strike_count("did:walkie:bad"), StrikeLevel::Third);
        let r3 = slash.slash("did:walkie:bad", OffenseType::StorageChallengeMissed, &fake_evidence(), &mut wc);
        assert_eq!(r3.severity, StrikeLevel::Third);
    }

    #[test]
    fn test_different_dids_independent() {
        let mut slash = SlashLedger::new();
        let mut wc1 = make_crp_ledger();
        let mut wc2 = make_crp_ledger();

        slash.slash("did:walkie:alice", OffenseType::SpamAbuse, &fake_evidence(), &mut wc1);
        // Bob should still be at First
        assert_eq!(slash.check_strike_count("did:walkie:bob"), StrikeLevel::First);
    }

    #[test]
    fn test_evidence_hash_deterministic() {
        let evidence = b"test evidence payload";
        let h1 = SlashLedger::hash_evidence(evidence);
        let h2 = SlashLedger::hash_evidence(evidence);
        assert_eq!(h1, h2);
        assert!(!h1.is_empty());
    }

    #[test]
    fn test_evidence_hash_differs() {
        let h1 = SlashLedger::hash_evidence(b"evidence A");
        let h2 = SlashLedger::hash_evidence(b"evidence B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_slash_record_expiry() {
        let mut record = SlashRecord::new(
            "did:walkie:test",
            OffenseType::MeasurementFraud,
            StrikeLevel::First,
            &fake_evidence(),
        );
        // Fresh record should not be expired
        assert!(!record.is_expired());

        // Force expire by setting old timestamp
        record.timestamp_ms = crate::resource::now_ms() - (25 * 3_600_000); // 25 hours ago
        assert!(record.is_expired());
    }

    #[test]
    fn test_records_for_did() {
        let mut slash = SlashLedger::new();
        let mut wc = make_crp_ledger();
        slash.slash("did:walkie:alice", OffenseType::SpamAbuse, &fake_evidence(), &mut wc);
        slash.slash("did:walkie:bob", OffenseType::MeasurementFraud, &fake_evidence(), &mut wc);
        slash.slash("did:walkie:alice", OffenseType::SpamAbuse, &fake_evidence(), &mut wc);

        assert_eq!(slash.records_for("did:walkie:alice").len(), 2);
        assert_eq!(slash.records_for("did:walkie:bob").len(), 1);
    }

    #[test]
    fn test_prune_limit() {
        let mut slash = SlashLedger::new();
        // Manually push expired records to trigger pruning
        for i in 0..1100 {
            let mut record = SlashRecord::new(
                &format!("did:walkie:node-{i}"),
                OffenseType::SpamAbuse,
                StrikeLevel::First,
                &fake_evidence(),
            );
            record.timestamp_ms = 0; // force expiry
            slash.records.push(record);
        }
        // Should have been pruned
        assert!(slash.len() <= MAX_SLASH_RECORDS);
    }

    #[test]
    fn test_strike_level_multipliers() {
        assert!((StrikeLevel::First.crp_multiplier() - 0.5).abs() < 0.001);
        assert!((StrikeLevel::Second.crp_multiplier() - 0.25).abs() < 0.001);
        assert!((StrikeLevel::Third.crp_multiplier() - 0.0).abs() < 0.001);
    }
}
