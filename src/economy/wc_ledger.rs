//! WC (WalkieCoin) local ledger — Phase 4 economy module.
//!
//! Each node maintains a local ledger for:
//!   - WC balance (with hourly decay)
//!   - CRP accumulation rate
//!   - Daily spending budget
//!
//! Design decisions:
//!   - No blockchain — local ledger + dual-signed receipts prevent double-spend.
//!   - Balance decays hourly (0.998×) to incentivize continuous contribution.
//!   - Daily budget caps spending to prevent runaway consumption.

use crate::resource::economy_params;

/// Errors that can occur during ledger operations.
#[derive(Debug, Clone, PartialEq)]
pub enum LedgerError {
    /// Insufficient WC balance.
    InsufficientFunds { balance: f64, cost: f64 },
    /// Daily budget exceeded.
    DailyBudgetExceeded { spent: f64, budget: f64 },
    /// Invalid amount (negative or NaN).
    InvalidAmount(f64),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientFunds { balance, cost } => {
                write!(f, "insufficient funds: balance={balance}, cost={cost}")
            }
            Self::DailyBudgetExceeded { spent, budget } => {
                write!(f, "daily budget exceeded: spent={spent}, budget={budget}")
            }
            Self::InvalidAmount(amount) => {
                write!(f, "invalid amount: {amount}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

/// A single CRP earning record for history tracking.
#[derive(Debug, Clone)]
pub struct CrpRecord {
    /// CRP earned in this period.
    pub amount: f64,
    /// Timestamp (ms) when this CRP was earned.
    pub timestamp_ms: u64,
    /// Contribution weight that produced this CRP.
    pub weight: f64,
}

/// Local WC (WalkieCoin) ledger for a single node.
///
/// Manages balance, CRP accumulation, and spending limits.
#[derive(Debug, Clone)]
pub struct WcLedger {
    /// Current WC balance.
    pub(crate) balance: f64,

    /// CRP accumulation rate (CRP/hr).
    pub(crate) crp_rate: f64,

    /// Known network size (for pioneer multiplier / cap).
    pub(crate) network_size: u32,

    /// Total CRP earned (cumulative, subject to cap).
    pub(crate) crp_cumulative: f64,

    /// CRP history for decay calculation.
    pub crp_history: Vec<CrpRecord>,

    /// WC spent today.
    pub(crate) daily_spent: f64,

    /// Timestamp (ms) when daily spending was last reset.
    pub(crate) daily_spent_reset_at: u64,
}

impl Default for WcLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl WcLedger {
    /// Create a new ledger with initial WC grant.
    /// Create a new ledger with default network_size=10.
    pub fn new() -> Self {
        Self {
            balance: economy_params::INITIAL_WC_GRANT,
            crp_rate: 0.0,
            crp_cumulative: 0.0,
            crp_history: Vec::new(),
            daily_spent: 0.0,
            daily_spent_reset_at: crate::resource::now_ms(),
            network_size: 10,
        }
    }

    /// Create a ledger with a specific initial balance and network size (for testing).
    pub fn with_balance(initial_balance: f64) -> Self {
        Self {
            balance: initial_balance,
            ..Self::new()
        }
    }

    /// Update network size (e.g., after mDNS discovery).
    pub fn set_network_size(&mut self, size: u32) {
        self.network_size = size.max(1);
    }

    /// Calculate current CRP rate from resource contributions.
    ///
    /// CRP_rate = Σ(weight_i × contribution_i / hour)
    /// Applies pioneer multiplier and CRP cap.
    ///
    /// Note: In production, this pulls from ContributionEngine's ledger.
    /// Here we accept a pre-calculated total_contribution_score.
    pub fn recalculate_crp_rate(
        &mut self,
        total_contribution_score: f64,
        network_size: u32,
    ) {
        let pioneer = economy_params::pioneer_multiplier(network_size);
        let raw_rate = total_contribution_score;

        self.crp_rate = raw_rate * pioneer;

        // Apply cap: crp_rate cannot exceed cap / hours_in_30_days
        let cap = economy_params::crp_cap(network_size);
        let max_hourly = cap / economy_params::CRP_HALF_LIFE_HOURS;
        self.crp_rate = self.crp_rate.min(max_hourly);
    }

    /// Convert earned CRP to WC (with network tax).
    ///
    /// Returns the WC amount actually credited.
    /// Network keeps (1 - WC_CONVERSION_EFFICIENCY) as tax.
    pub fn convert_crp_to_wc(&mut self, crp_amount: f64) -> f64 {
        let wc = crp_amount * economy_params::WC_CONVERSION_EFFICIENCY;

        // Enforce CRP cap
        self.crp_cumulative += crp_amount;
        let effective_cap = economy_params::crp_cap(self.network_size);
        if self.crp_cumulative > effective_cap {
            self.crp_cumulative = effective_cap;
        }

        self.balance += wc;

        self.crp_history.push(CrpRecord {
            amount: crp_amount,
            timestamp_ms: crate::resource::now_ms(),
            weight: 1.0,
        });

        wc
    }

    /// Apply hourly WC decay.
    ///
    /// balance = balance × 0.998^hours
    pub fn apply_hourly_decay(&mut self, hours: f64) {
        self.balance = economy_params::apply_wc_decay(self.balance, hours);
    }

    /// Calculate the daily WC budget.
    ///
    /// budget = max(CRP_rate × 24 × DAILY_BUDGET_MULTIPLIER, DAILY_BUDGET_FLOOR)
    pub fn daily_budget(&self) -> f64 {
        economy_params::daily_budget(self.crp_rate)
    }

    /// Check if a transaction can be afforded.
    ///
    /// Both balance and daily budget must be sufficient.
    pub fn can_afford(&self, cost: f64) -> bool {
        if cost < 0.0 || cost.is_nan() {
            return false;
        }
        self.balance >= cost && self.daily_spent + cost <= self.daily_budget()
    }

    /// Record a spending transaction.
    ///
    /// Deducts from balance and daily_spent.
    /// Returns error if insufficient funds or daily budget exceeded.
    pub fn spend(&mut self, cost: f64, _description: &str) -> Result<(), LedgerError> {
        if cost < 0.0 || cost.is_nan() {
            return Err(LedgerError::InvalidAmount(cost));
        }
        if self.daily_spent + cost > self.daily_budget() {
            return Err(LedgerError::DailyBudgetExceeded {
                spent: self.daily_spent,
                budget: self.daily_budget(),
            });
        }
        if self.balance < cost {
            return Err(LedgerError::InsufficientFunds {
                balance: self.balance,
                cost,
            });
        }
        self.balance -= cost;
        self.daily_spent += cost;
        Ok(())
    }

    /// Reset daily spending counter (typically called at midnight UTC).
    pub fn reset_daily_spent(&mut self) {
        self.daily_spent = 0.0;
        self.daily_spent_reset_at = crate::resource::now_ms();
    }

    /// Check if daily spending should be reset (>24h since last reset).
    pub fn should_reset_daily(&self) -> bool {
        let now = crate::resource::now_ms();
        now.saturating_sub(self.daily_spent_reset_at) > 24 * 3600 * 1000
    }

    /// Add WC to balance (e.g., from receiving payment).
    pub fn deposit(&mut self, amount: f64) {
        if amount > 0.0 {
            self.balance += amount;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_ledger_initial_balance() {
        let ledger = WcLedger::new();
        assert!((ledger.balance - economy_params::INITIAL_WC_GRANT).abs() < 0.001);
        assert_eq!(ledger.crp_rate, 0.0);
        assert_eq!(ledger.crp_cumulative, 0.0);
        assert_eq!(ledger.daily_spent, 0.0);
    }

    #[test]
    fn test_spend_success() {
        let mut ledger = WcLedger::with_balance(100.0);
        assert!(ledger.can_afford(50.0));
        assert!(ledger.spend(50.0, "test").is_ok());
        assert!((ledger.balance - 50.0).abs() < 0.001);
        assert!((ledger.daily_spent - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_spend_insufficient_funds() {
        let mut ledger = WcLedger::with_balance(10.0);
        let result = ledger.spend(50.0, "too much");
        assert_eq!(result, Err(LedgerError::InsufficientFunds { balance: 10.0, cost: 50.0 }));
        assert!((ledger.balance - 10.0).abs() < 0.001); // unchanged
    }

    #[test]
    fn test_convert_crp_to_wc() {
        let mut ledger = WcLedger::with_balance(0.0);
        let wc = ledger.convert_crp_to_wc(100.0);
        assert!((wc - 80.0).abs() < 0.001); // 100 × 0.8
        assert!((ledger.balance - 80.0).abs() < 0.001);
        assert!((ledger.crp_cumulative - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_hourly_decay() {
        let mut ledger = WcLedger::with_balance(1000.0);
        ledger.apply_hourly_decay(24.0);
        // 1000 × 0.998^24 ≈ 953.0
        assert!(ledger.balance > 950.0 && ledger.balance < 956.0);
    }

    #[test]
    fn test_hourly_decay_monthly() {
        let mut ledger = WcLedger::with_balance(1000.0);
        ledger.apply_hourly_decay(720.0); // 30 days
        // 1000 × 0.998^720 ≈ 237.0
        assert!(ledger.balance > 230.0 && ledger.balance < 245.0);
    }

    #[test]
    fn test_daily_budget() {
        let mut ledger = WcLedger::new();
        ledger.crp_rate = 12.0; // M4 Pro: 12 CRP/hr
        let budget = ledger.daily_budget();
        assert!((budget - 576.0).abs() < 0.1); // 12 × 24 × 2 = 576
    }

    #[test]
    fn test_daily_budget_floor() {
        let mut ledger = WcLedger::new();
        ledger.crp_rate = 0.1; // very low
        let budget = ledger.daily_budget();
        assert!((budget - 50.0).abs() < 0.1); // floor = 50
    }

    #[test]
    fn test_daily_spending_limit() {
        let mut ledger = WcLedger::with_balance(1000.0);
        ledger.crp_rate = 12.0; // budget = 576/day

        // Spend up to budget
        assert!(ledger.spend(576.0, "max").is_ok());
        // One more should fail (daily budget exceeded)
        assert!(ledger.spend(1.0, "over").is_err());
    }

    #[test]
    fn test_reset_daily_spending() {
        let mut ledger = WcLedger::with_balance(1000.0);
        ledger.daily_spent = 500.0;
        ledger.reset_daily_spent();
        assert!((ledger.daily_spent - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_crp_rate_calculation() {
        let mut ledger = WcLedger::new();
        ledger.recalculate_crp_rate(50.0, 100); // 100 nodes
        // pioneer(100) = 1 + 2/log2(102) ≈ 1.30
        // rate = 50 × 1.30 = 65.0
        assert!(ledger.crp_rate > 60.0 && ledger.crp_rate < 70.0);
    }

    #[test]
    fn test_crp_rate_cap() {
        let mut ledger = WcLedger::new();
        // Very high contribution — should be capped
        ledger.recalculate_crp_rate(1_000_000.0, 5);
        // cap(5) = 100000 + 10000 * log2(6) ≈ 125849
        // max_hourly = 125849 / 720 ≈ 174.8
        assert!(ledger.crp_rate < 200.0);
    }

    #[test]
    fn test_deposit() {
        let mut ledger = WcLedger::with_balance(10.0);
        ledger.deposit(90.0);
        assert!((ledger.balance - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_deposit_negative_ignored() {
        let mut ledger = WcLedger::with_balance(10.0);
        ledger.deposit(-50.0);
        assert!((ledger.balance - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_spend_invalid_amount() {
        let mut ledger = WcLedger::with_balance(100.0);
        assert_eq!(ledger.spend(-1.0, "negative"), Err(LedgerError::InvalidAmount(-1.0)));
        assert!(matches!(ledger.spend(f64::NAN, "nan"), Err(LedgerError::InvalidAmount(_))));
    }

    #[test]
    fn test_can_afford_edge_cases() {
        let ledger = WcLedger::with_balance(0.0);
        // Zero cost: 0 >= 0 is true, 0 + 0 <= 50 (daily floor) is true
        assert!(ledger.can_afford(0.0));
        assert!(!ledger.can_afford(-1.0));
        assert!(!ledger.can_afford(f64::NAN));
        // Over budget but within balance
        assert!(!ledger.can_afford(1000.0)); // 1000 > 0 balance
    }

    #[test]
    fn test_initial_wc_grant() {
        let ledger = WcLedger::new();
        assert!((ledger.balance - 10.0).abs() < 0.001);
    }
}
