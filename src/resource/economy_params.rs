//! Economy parameter constants — Walkie Talkie v1.1 (frozen).
//!
//! All values verified by 弈淵 🎲 (game-theory equilibrium analysis).
//! Source: 雪琪 ❄️ v1.1 frozen parameter set, 2026-04-11.
//!
//! # Phase 3 thaw conditions (100+ nodes)
//!
//! - CRP weights (#0-#4): may be adjusted ±0.05 based on bottleneck analysis.
//! - Conversion efficiency (#5): may be tuned based on WC supply/demand.
//! - WC decay rate (#7): may be adjusted via governance vote.
//!
//! Do NOT modify these values without CFO + game-theorist sign-off.

// ── CRP Weight Parameters (#1-#5) ──────────────────────────────────────────

/// CPU weight in CRP rate formula (α).
///
/// Messages encryption/decryption and routing computation core.
/// Verified: game-theory robust (弈淵 Task B2).
pub const CRP_WEIGHT_CPU: f64 = 0.30;

/// Memory weight in CRP rate formula (β).
///
/// DHT tables and message buffers.
pub const CRP_WEIGHT_MEMORY: f64 = 0.15;

/// Bandwidth weight in CRP rate formula (γ).
///
/// The lifeblood of a communication network — direct measure of relay contribution.
/// Tied with CPU as the highest-weight resource.
pub const CRP_WEIGHT_BANDWIDTH: f64 = 0.30;

/// Storage weight in CRP rate formula (δ).
///
/// DHT data and channel history cache.
pub const CRP_WEIGHT_STORAGE: f64 = 0.15;

/// Uptime weight in CRP rate formula (ε).
///
/// Foundation of network stability. Acts as a multiplier — contributing resources
/// while online is what matters.
pub const CRP_WEIGHT_UPTIME: f64 = 0.10;

// ── Conversion & Decay Parameters (#6-#8) ──────────────────────────────────

/// WC conversion efficiency (η).
///
/// 80% of CRP earned becomes WC; the remaining 20% is "network tax" that
/// subsidises Free Tier users and network maintenance.
pub const WC_CONVERSION_EFFICIENCY: f64 = 0.80;

/// CRP cumulative decay half-life in hours.
///
/// 30 days = 720 hours. Historical contributions decay with half-life of 30 days.
/// This affects **contribution history** weight, not account balance.
pub const CRP_HALF_LIFE_HOURS: f64 = 720.0;

/// WC balance decay rate per hour (λ).
///
/// Each hour, balance is multiplied by 0.998 (0.2% decay).
/// Daily retention: ~95.3%. 30-day retention: ~23.7%.
///
/// This affects **account balance**, independent of CRP decay.
/// Design intent:
/// - Continuous contributors: earn >> decay → balance grows.
/// - Intermittent contributors: 7 days idle → still retain ~72%.
/// - Hoarders: 30 days idle → 76% decay → cannot accumulate indefinitely.
pub const WC_BALANCE_DECAY_RATE_PER_HOUR: f64 = 0.998;

// ── Identity & Guarantor Parameters (#9, #11-#13) ─────────────────────────

/// Initial WC granted to a new node identity.
///
/// 10 WC ≈ 100 direct messages or 1 broadcast.
/// Provides ~10 hours of light usage at Free Tier (10 msg/hr).
///
/// Previously 50 WC (v1.0), reduced to disincentivise wash-walking attacks.
/// Combined with guarantor mechanism, wash-walking ROI < 0 (弈淵 Task A1).
pub const INITIAL_WC_GRANT: f64 = 10.0;

/// Minimum WC balance required to act as a guarantor.
///
/// Increased from 200 (v1.0) to 500. At 9.6 WC/hr earning rate (M4 Pro),
/// reaching 500 WC requires ~52 hours of continuous contribution plus
/// the 30-day cooling period — raising the cost of grooming guarantor accounts.
pub const GUARANTOR_MIN_WC: f64 = 500.0;

/// Maximum number of simultaneous guarantees per guarantor node.
///
/// Limits the blast radius if a guarantor is compromised or turns malicious.
pub const GUARANTOR_MAX_GUARANTEES: u32 = 5;

/// Minimum age (days) before a node can act as guarantor.
///
/// Prevents "grooming" attacks where an adversary creates identities
/// and immediately uses them to guarantee more identities.
pub const GUARANTOR_COOLDOWN_DAYS: u32 = 30;

// ── Broadcast & Budget Parameters (#10, #15-#16) ──────────────────────────

/// Maximum WC cost for a single broadcast message.
///
/// Prevents unbounded broadcast costs in large networks.
/// v1.0 formula was `N × 0.1` with no cap, which could reach 100+ WC
/// in a 1000-node network — punishing honest broadcasters.
///
/// Channel message cost: `min(0.1 + 0.02 × N_subscribers, BROADCAST_COST_CAP)`.
/// When N_subscribers > 495, cost caps at 10 WC.
pub const BROADCAST_COST_CAP: f64 = 10.0;

/// Maximum number of penalty escalation steps before permanent ban.
///
/// Three-strikes principle: first offence → reduced CRP; second → further
/// reduction; third → disconnect. Gives room for false-positive corrections.
pub const MAX_PENALTY_STRIKES: u32 = 3;

/// Daily WC budget multiplier.
///
/// DailyBudget = max(CRP_rate × 24 × DAILY_BUDGET_MULTIPLIER, 50).
/// A multiplier of 2× means daily spending is capped at 48 hours of earning.
/// Minimum floor of 50 WC/day ensures low-contribution nodes can still operate.
pub const DAILY_BUDGET_MULTIPLIER: f64 = 2.0;

/// Minimum daily WC budget floor.
///
/// Even the lowest contributor gets at least this much daily spending allowance.
pub const DAILY_BUDGET_FLOOR: f64 = 50.0;

// ── Free Tier Parameter (#17) ─────────────────────────────────────────────

/// Maximum messages per hour for Free Tier (un-guaranteed) nodes.
///
/// Free Tier users can receive unlimited messages (receiving is always free)
/// but are limited in sending.
pub const FREE_TIER_MSG_PER_HOUR: u32 = 10;

// ── CRP Anti-Inflation Cap Parameters (#18-#19) ───────────────────────────

/// Base CRP cumulative cap.
///
/// `CRP_effective = min(CRP_cum, CRP_CAP_BASE + CRP_CAP_COEFF × log2(N + 1))`
///
/// Prevents early contributors from accumulating disproportionately large CRP.
pub const CRP_CAP_BASE: f64 = 100_000.0;

/// CRP cap growth coefficient.
///
/// As the network grows, the cap naturally increases — more nodes = more
/// resource demand = more accumulation allowed.
///
/// At 100 nodes: cap ≈ 166,000. At 10,000 nodes: cap ≈ 233,000.
pub const CRP_CAP_COEFF: f64 = 10_000.0;

// ── Pioneer Multiplier (#20) ──────────────────────────────────────────────

/// Pioneer multiplier numerator.
///
/// `M_pioneer = 1 + PIONEER_NUMERATOR / log2(N_network + 2)`
///
/// At 5 nodes: 3.0×. At 100 nodes: 1.21×. At 10,000 nodes: ~1.0×.
/// Rewards early contributors who bear disproportionate risk.
/// The multiplier fades naturally as the network grows.
pub const PIONEER_NUMERATOR: f64 = 2.0;

// ── Balance Thresholds ─────────────────────────────────────────────────────

/// Balance threshold for downgrade to Free Tier.
pub const BALANCE_THRESHOLD_FREE_TIER: f64 = 0.0;

/// Balance threshold for isolation (receive-only mode).
pub const BALANCE_THRESHOLD_ISOLATION: f64 = -100.0;

/// Balance threshold for disconnect.
pub const BALANCE_THRESHOLD_DISCONNECT: f64 = -1000.0;

// ── Operation Costs (WC) ───────────────────────────────────────────────────

/// WC cost to send a 1:1 (direct) message.
pub const COST_DIRECT_MESSAGE: f64 = 0.1;

/// WC cost per subscriber for channel messages (added to base cost).
///
/// Channel message cost = `COST_DIRECT_MESSAGE + COST_PER_SUBSCRIBER × N_subs`.
pub const COST_PER_SUBSCRIBER: f64 = 0.02;

/// WC cost to store 1 KB for 1 day.
pub const COST_STORAGE_KB_DAY: f64 = 0.001;

/// WC cost for a DHT query.
pub const COST_DHT_QUERY: f64 = 0.01;

/// WC cost to create a public channel (one-time).
pub const COST_CHANNEL_CREATE: f64 = 10.0;

/// WC cost to create a private channel (one-time).
pub const COST_PRIVATE_CHANNEL_CREATE: f64 = 20.0;

/// WC cost to join a channel (one-time).
pub const COST_CHANNEL_JOIN: f64 = 1.0;

// ── Endorsement & Audit Parameters ─────────────────────────────────────────

/// Minimum endorsement score to be considered honest.
///
/// V_endorsement = observed / claimed. Above this threshold → honest.
pub const ENDORSEMENT_HONEST_THRESHOLD: f64 = 0.8;

/// Endorsement score below which fraud is suspected.
///
/// Triggers penalty matrix activation.
pub const ENDORSEMENT_FRAUD_THRESHOLD: f64 = 0.5;

/// Guarantor reward when guarantee turns out honest (WC).
pub const GUARANTOR_REWARD_WC: f64 = 5.0;

/// Guarantor penalty when guarantee commits fraud (WC).
pub const GUARANTOR_PENALTY_WC: f64 = 50.0;

// ── Governance Parameter ───────────────────────────────────────────────────

/// Maximum voting power per node (votes are log2-scaled).
///
/// Prevents large nodes from monopolising governance decisions.
pub const MAX_VOTING_POWER: u32 = 5;

// ── Helper Functions ───────────────────────────────────────────────────────

/// Compute the pioneer multiplier for a given network size.
///
/// `M = 1 + 2.0 / log2(N + 2)`
///
/// At N=5: 3.0×, N=100: 1.21×, N=10000: ~1.0×.
pub fn pioneer_multiplier(network_size: u32) -> f64 {
    1.0 + PIONEER_NUMERATOR / (network_size as f64 + 2.0).log2()
}

/// Compute the CRP effective cap for a given network size.
///
/// `cap = 100_000 + 10_000 × log2(N + 1)`
pub fn crp_cap(network_size: u32) -> f64 {
    CRP_CAP_BASE + CRP_CAP_COEFF * (network_size as f64 + 1.0).log2()
}

/// Compute the daily WC budget for a given CRP rate (CRP/hr).
///
/// `budget = max(CRP_rate × 24 × 2, 50)`
pub fn daily_budget(crp_rate_per_hour: f64) -> f64 {
    (crp_rate_per_hour * 24.0 * DAILY_BUDGET_MULTIPLIER).max(DAILY_BUDGET_FLOOR)
}

/// Compute channel message cost, capped at broadcast maximum.
///
/// `cost = min(0.1 + 0.02 × N_subs, 10.0)`
pub fn channel_message_cost(subscriber_count: u32) -> f64 {
    let raw = COST_DIRECT_MESSAGE + COST_PER_SUBSCRIBER * subscriber_count as f64;
    raw.min(BROADCAST_COST_CAP)
}

/// Compute CRP decay factor (λ_crp) per hour from the half-life.
///
/// `λ_crp = ln(2) / T_half = 0.693 / 720 ≈ 0.000963`
pub fn crp_decay_factor_per_hour() -> f64 {
    std::f64::consts::LN_2 / CRP_HALF_LIFE_HOURS
}

/// Apply WC balance decay for a given number of hours elapsed.
///
/// `balance × 0.998^hours`
pub fn apply_wc_decay(balance: f64, hours_elapsed: f64) -> f64 {
    balance * WC_BALANCE_DECAY_RATE_PER_HOUR.powf(hours_elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weights_sum_to_one() {
        let sum =
            CRP_WEIGHT_CPU + CRP_WEIGHT_MEMORY + CRP_WEIGHT_BANDWIDTH + CRP_WEIGHT_STORAGE + CRP_WEIGHT_UPTIME;
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "CRP weights must sum to 1.0, got {sum}"
        );
    }

    #[test]
    fn test_pioneer_multiplier_bootstrap() {
        // 5 nodes → 1 + 2.0/log2(7) ≈ 1.71×
        let m5 = pioneer_multiplier(5);
        assert!((m5 - 1.712).abs() < 0.01, "5-node pioneer = {m5}");
    }

    #[test]
    fn test_pioneer_multiplier_large_network() {
        // 10,000 nodes → ~1.15× (mostly faded)
        let m10k = pioneer_multiplier(10_000);
        assert!((m10k - 1.15).abs() < 0.01, "10K-node pioneer should be ~1.15, got {m10k}");
        // Still above 1.0 — pioneer bonus never fully vanishes
        assert!(m10k > 1.0);
    }

    #[test]
    fn test_pioneer_multiplier_decreasing() {
        assert!(pioneer_multiplier(5) > pioneer_multiplier(100));
        assert!(pioneer_multiplier(100) > pioneer_multiplier(10_000));
    }

    #[test]
    fn test_crp_cap_scales() {
        let cap5 = crp_cap(5);
        let cap100 = crp_cap(100);
        let cap10k = crp_cap(10_000);
        assert!(cap5 < cap100);
        assert!(cap100 < cap10k);
        // 100 nodes: ~166,000
        assert!((cap100 - 166_000.0).abs() < 1_000.0, "cap100 = {cap100}");
    }

    #[test]
    fn test_daily_budget() {
        // M4 Pro: CRP_rate = 12.0/hr → 576/day
        let budget_m4 = daily_budget(12.0);
        assert!((budget_m4 - 576.0).abs() < 0.1, "M4 budget = {budget_m4}");

        // Very low contributor → floor of 50
        let budget_low = daily_budget(0.5);
        assert!((budget_low - 50.0).abs() < 0.1, "low budget = {budget_low}");
    }

    #[test]
    fn test_channel_message_cost_capped() {
        // Small channel: linear
        let cost10 = channel_message_cost(10);
        assert!((cost10 - 0.3).abs() < 0.001, "cost10 = {cost10}");

        // Large channel: capped at 10
        let cost10k = channel_message_cost(10_000);
        assert!((cost10k - 10.0).abs() < 0.001, "cost10k = {cost10k}");

        // Exact cap boundary: 0.1 + 0.02 × 495 = 10.0
        let cost495 = channel_message_cost(495);
        assert!((cost495 - 10.0).abs() < 0.001, "cost495 = {cost495}");
    }

    #[test]
    fn test_crp_decay_factor() {
        let lambda = crp_decay_factor_per_hour();
        // λ ≈ 0.000963/h
        assert!((lambda - 0.000963).abs() < 0.00001, "λ = {lambda}");
    }

    #[test]
    fn test_wc_decay_daily() {
        let balance = 1000.0;
        let after_24h = apply_wc_decay(balance, 24.0);
        // Should retain ~95.3%
        let retention = after_24h / balance;
        assert!((retention - 0.953).abs() < 0.005, "24h retention = {retention}");
    }

    #[test]
    fn test_wc_decay_monthly() {
        let balance = 1000.0;
        let after_30d = apply_wc_decay(balance, 720.0);
        // Should retain ~23.7%
        let retention = after_30d / balance;
        assert!((retention - 0.237).abs() < 0.02, "30d retention = {retention}");
    }

    #[test]
    fn test_balance_thresholds_ordering() {
        const { assert!(BALANCE_THRESHOLD_FREE_TIER > BALANCE_THRESHOLD_ISOLATION) };
        const { assert!(BALANCE_THRESHOLD_ISOLATION > BALANCE_THRESHOLD_DISCONNECT) };
    }

    #[test]
    fn test_all_params_positive() {
        const { assert!(CRP_WEIGHT_CPU > 0.0) };
        const { assert!(WC_CONVERSION_EFFICIENCY > 0.0) };
        const { assert!(WC_BALANCE_DECAY_RATE_PER_HOUR > 0.0) };
        const { assert!(INITIAL_WC_GRANT > 0.0) };
        const { assert!(GUARANTOR_MIN_WC > 0.0) };
        const { assert!(GUARANTOR_MAX_GUARANTEES > 0) };
        const { assert!(GUARANTOR_COOLDOWN_DAYS > 0) };
        const { assert!(BROADCAST_COST_CAP > 0.0) };
        const { assert!(CRP_CAP_BASE > 0.0) };
        const { assert!(CRP_CAP_COEFF > 0.0) };
        const { assert!(PIONEER_NUMERATOR > 0.0) };
    }

    #[test]
    fn test_conversion_efficiency_range() {
        const { assert!(WC_CONVERSION_EFFICIENCY > 0.0 && WC_CONVERSION_EFFICIENCY < 1.0) };
    }

    #[test]
    fn test_decay_rate_range() {
        const {
            assert!(
                WC_BALANCE_DECAY_RATE_PER_HOUR > 0.0 && WC_BALANCE_DECAY_RATE_PER_HOUR < 1.0,
                "Decay rate must be in (0, 1)"
            )
        };
    }
}
