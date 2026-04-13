//! Reputation Engine — Phase 4.1
//!
//! Calculates composite [`TrustScore`] from multiple signal sources:
//! - Identity verification (cryptographic binding)
//! - Endorsement cross-validation scores
//! - Guarantor backing
//! - Slash/penalty records
//! - Recency weighting (recent signals count more)

use super::types::TrustScore;

/// Compute the identity component score (0.0–1.0).
///
/// Based on whether the peer has completed IdentityAttestation:
/// - No binding → 0.0
/// - Cryptographic binding → 0.5
/// - Guaranteed (has guarantor) → 0.7
/// - CommunityVerified → 1.0
pub fn identity_component(trust_level_i: u8) -> f64 {
    // trust_level_i: 0=Unverified, 1=Cryptographic, 2=Guaranteed, 3=CommunityVerified
    match trust_level_i {
        0 => 0.0,
        1 => 0.5,
        2 => 0.7,
        3 => 1.0,
        _ => 0.0,
    }
}

/// Compute the endorsement component score (0.0–1.0).
///
/// Derived from `EndorsementHistory::endorsement_score()`:
/// - No endorsements → 0.0
/// - V < 0.5 → V (suspicious)
/// - V 0.5–0.8 → V
/// - V >= 0.8 → V
pub fn endorsement_component(v_endorsement: f64) -> f64 {
    v_endorsement.clamp(0.0, 1.0)
}

/// Compute the guarantor boost component (0.0 or fixed values).
///
/// - No guarantor → 0.0
/// - Has guarantor with clean record → 0.5
/// - Has guarantor with high endorsement avg → 0.8
/// - Community verified guarantor → 1.0
pub fn guarantor_component(has_guarantor: bool, guarantor_endorsement_avg: f64) -> f64 {
    if !has_guarantor {
        return 0.0;
    }
    if guarantor_endorsement_avg >= 0.9 {
        return 1.0;
    }
    if guarantor_endorsement_avg >= 0.7 {
        return 0.8;
    }
    0.5
}

/// Compute the slash penalty decay factor (1.0 = no penalty, 0.0 = max penalty).
///
/// Used as a multiplicative decay on the composite score:
/// - 0 active strikes → 1.0 (no reduction)
/// - 1 strike → 0.7 (30% reduction)
/// - 2 strikes → 0.4 (60% reduction)
/// - 3+ strikes → 0.0 (complete slash)
pub fn slash_component(active_strike_count: u32) -> f64 {
    match active_strike_count {
        0 => 1.0,
        1 => 0.7,
        2 => 0.4,
        _ => 0.0,
    }
}

/// Compute recency weight based on days since last activity.
///
/// - Activity within last 7 days → 1.0
/// - 7–30 days → 0.8
/// - 30–90 days → 0.5
/// - 90+ days → 0.2
pub fn recency_weight(days_since_activity: u64) -> f64 {
    match days_since_activity {
        0..=7 => 1.0,
        8..=30 => 0.8,
        31..=90 => 0.5,
        _ => 0.2,
    }
}

/// Recalculate a full TrustScore from all signal sources.
///
/// This is the main entry point for the reputation engine.
pub fn recalculate(
    trust_level_i: u8,
    v_endorsement: f64,
    has_guarantor: bool,
    guarantor_endorsement_avg: f64,
    active_strike_count: u32,
    days_since_activity: u64,
) -> TrustScore {
    let identity = identity_component(trust_level_i);
    let endorsement = endorsement_component(v_endorsement);
    let guarantor = guarantor_component(has_guarantor, guarantor_endorsement_avg);
    let slash = slash_component(active_strike_count);
    let recency = recency_weight(days_since_activity);

    TrustScore::from_components(identity, endorsement, guarantor, slash, recency)
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_component_levels() {
        assert!((identity_component(0) - 0.0).abs() < 0.01);
        assert!((identity_component(1) - 0.5).abs() < 0.01);
        assert!((identity_component(2) - 0.7).abs() < 0.01);
        assert!((identity_component(3) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_endorsement_component_clamp() {
        assert!((endorsement_component(-0.5) - 0.0).abs() < 0.01);
        assert!((endorsement_component(0.6) - 0.6).abs() < 0.01);
        assert!((endorsement_component(1.5) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_guarantor_component_no_guarantor() {
        assert!((guarantor_component(false, 0.0) - 0.0).abs() < 0.01);
        assert!((guarantor_component(false, 1.0) - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_guarantor_component_tiers() {
        assert!((guarantor_component(true, 0.5) - 0.5).abs() < 0.01);
        assert!((guarantor_component(true, 0.7) - 0.8).abs() < 0.01);
        assert!((guarantor_component(true, 0.9) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_slash_component_levels() {
        // slash_component returns decay factor: 1.0 = no penalty, 0.0 = max penalty
        assert!((slash_component(0) - 1.0).abs() < 0.01);
        assert!((slash_component(1) - 0.7).abs() < 0.01);
        assert!((slash_component(2) - 0.4).abs() < 0.01);
        assert!((slash_component(3) - 0.0).abs() < 0.01);
        assert!((slash_component(99) - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_recency_weight_tiers() {
        assert!((recency_weight(0) - 1.0).abs() < 0.01);
        assert!((recency_weight(5) - 1.0).abs() < 0.01);
        assert!((recency_weight(7) - 1.0).abs() < 0.01);
        assert!((recency_weight(8) - 0.8).abs() < 0.01);
        assert!((recency_weight(30) - 0.8).abs() < 0.01);
        assert!((recency_weight(31) - 0.5).abs() < 0.01);
        assert!((recency_weight(90) - 0.5).abs() < 0.01);
        assert!((recency_weight(91) - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_recalculate_new_node() {
        let score = recalculate(0, 0.0, false, 0.0, 0, 1);
        assert!((score.composite() - 0.0).abs() < 0.01);
        assert_eq!(score.level(), super::super::types::TrustLevel::Unverified);
        assert!((score.crp_multiplier() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_recalculate_cryptographic_node() {
        let score = recalculate(1, 0.8, false, 0.0, 0, 1);
        // base=0.5*0.2+0.8*0.5+0*0.2=0.5, slash=1.0, recency=1.0
        assert!((score.composite() - 0.5).abs() < 0.01);
        assert_eq!(score.level(), super::super::types::TrustLevel::Cryptographic);
    }

    #[test]
    fn test_recalculate_guaranteed_node() {
        let score = recalculate(2, 0.9, true, 0.5, 0, 1);
        // base=0.7*0.2+0.9*0.5+0.5*0.2=0.69, slash=1.0
        assert!((score.composite() - 0.69).abs() < 0.01);
        assert_eq!(score.level(), super::super::types::TrustLevel::Guaranteed);
    }

    #[test]
    fn test_recalculate_community_verified() {
        let score = recalculate(3, 0.95, true, 0.95, 0, 1);
        // base=1.0*0.2+0.95*0.5+1.0*0.2=0.875, slash=1.0
        assert!((score.composite() - 0.875).abs() < 0.01);
        assert_eq!(score.level(), super::super::types::TrustLevel::CommunityVerified);
    }

    #[test]
    fn test_slash_reduces_score() {
        let clean = recalculate(2, 0.9, true, 0.8, 0, 1);
        let slashed = recalculate(2, 0.9, true, 0.8, 2, 1);
        // clean: base=0.75, slash_decay=1.0 → 0.75
        // slashed: base=0.75, slash_decay=0.4 → 0.30
        assert!(slashed.composite() < clean.composite());
        assert!((clean.composite() - 0.75).abs() < 0.01);
        assert!((slashed.composite() - 0.30).abs() < 0.01);
    }

    #[test]
    fn test_recency_affects_score() {
        let recent = recalculate(1, 0.8, false, 0.0, 0, 1);
        let stale = recalculate(1, 0.8, false, 0.0, 0, 100);
        // recent: base=0.5 * slash=1.0 * recency=1.0 = 0.5
        // stale: base=0.5 * slash=1.0 * recency=0.2 = 0.1
        assert!(recent.composite() > stale.composite());
        assert!((recent.composite() - 0.5).abs() < 0.01);
        assert!((stale.composite() - 0.1).abs() < 0.01);
    }

    #[test]
    fn test_crp_multiplier_per_level() {
        let unverified = recalculate(0, 0.0, false, 0.0, 0, 1);
        let crypto = recalculate(1, 0.8, false, 0.0, 0, 1);
        let guaranteed = recalculate(2, 0.9, true, 0.8, 0, 1);
        let community = recalculate(3, 0.95, true, 0.95, 0, 1);

        assert!((unverified.crp_multiplier() - 0.5).abs() < 0.01);
        assert!((crypto.crp_multiplier() - 1.0).abs() < 0.01);
        assert!((guaranteed.crp_multiplier() - 1.2).abs() < 0.01);
        assert!((community.crp_multiplier() - 1.5).abs() < 0.01);
    }

    #[test]
    fn test_trust_bonus_per_level() {
        use super::super::types::TrustLevel;

        let score_unverified = TrustScore::from_components(0.0, 0.0, 0.0, 1.0, 1.0);
        assert_eq!(score_unverified.level(), TrustLevel::Unverified);
        assert!((score_unverified.trust_bonus() - 0.0).abs() < 0.01);

        let score_crypto = TrustScore::from_components(0.5, 0.8, 0.0, 1.0, 1.0);
        assert_eq!(score_crypto.level(), TrustLevel::Cryptographic);
        assert!((score_crypto.trust_bonus() - 0.0).abs() < 0.01);

        let score_guaranteed = TrustScore::from_components(0.7, 0.9, 0.5, 1.0, 1.0);
        assert_eq!(score_guaranteed.level(), TrustLevel::Guaranteed);
        assert!((score_guaranteed.trust_bonus() - 0.10).abs() < 0.01);

        let score_community = TrustScore::from_components(1.0, 0.95, 1.0, 1.0, 1.0);
        assert_eq!(score_community.level(), TrustLevel::CommunityVerified);
        assert!((score_community.trust_bonus() - 0.25).abs() < 0.01);
    }
}
