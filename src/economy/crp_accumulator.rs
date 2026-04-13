//! CRP (Contribution Rate Points) Accumulator — Phase 4.
//!
//! Calculates CRP rate from resource contributions using weighted formula:
//!
//!   CRP_rate = Σ(weight_i × contribution_i / hour) × pioneer_multiplier
//!
//! Applies:
//!   - Pioneer multiplier (early network bonus)
//!   - CRP cap (logarithmic growth limit)
//!   - CRP decay (exponential half-life for inactive contributions)
//!
//! All constants sourced from `resource::economy_params` (frozen v1.1).

use crate::resource::economy_params;

/// A single contribution sample used for CRP calculation.
#[derive(Debug, Clone)]
pub struct ContributionSample {
    /// CPU·ms contributed in this measurement window.
    pub cpu_ms: u64,
    /// Peak memory (bytes) allocated in this window.
    pub memory_peak_bytes: u64,
    /// Bandwidth used (bytes) in this window.
    pub bandwidth_bytes: u64,
    /// Storage provided (bytes) in this window.
    pub storage_bytes: u64,
    /// Uptime in this window (ms).
    pub uptime_ms: u64,
    /// Window duration in hours.
    pub window_hours: f64,
    /// Timestamp (ms) when this sample was recorded.
    pub timestamp_ms: u64,
}

impl Default for ContributionSample {
    fn default() -> Self {
        Self {
            cpu_ms: 0,
            memory_peak_bytes: 0,
            bandwidth_bytes: 0,
            storage_bytes: 0,
            uptime_ms: 0,
            window_hours: 1.0, // default 1-hour window
            timestamp_ms: crate::resource::now_ms(),
        }
    }
}

/// Historical CRP record for decay tracking.
#[derive(Debug, Clone)]
pub struct CrpEntry {
    /// CRP earned in this period.
    pub crp_amount: f64,
    /// Timestamp (ms) when earned.
    pub timestamp_ms: u64,
    /// How many hours this CRP represents.
    pub window_hours: f64,
}

/// CRP Accumulator — calculates and tracks CRP rate over time.
///
/// CRP rate is recalculated from recent contribution samples,
/// applying pioneer multiplier, cap, and decay.
#[derive(Debug, Clone)]
pub struct CrpAccumulator {
    /// Recent contribution samples (ring buffer with N entries).
    pub(crate) samples: Vec<ContributionSample>,

    /// CRP history for decay calculation.
    pub(crate) history: Vec<CrpEntry>,

    /// Network size (for pioneer multiplier and cap).
    pub(crate) network_size: u32,

    /// Maximum number of samples to keep.
    pub(crate) max_samples: usize,
}

impl Default for CrpAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl CrpAccumulator {
    /// Create a new accumulator with default settings.
    pub fn new() -> Self {
        Self {
            samples: Vec::with_capacity(168), // 1 week of hourly samples
            history: Vec::new(),
            network_size: 10, // default assumption
            max_samples: 168,
        }
    }

    /// Create with a specific network size (for testing).
    pub fn with_network_size(network_size: u32) -> Self {
        Self {
            network_size,
            ..Self::new()
        }
    }

    /// Add a contribution sample.
    ///
    /// If the buffer is full, the oldest sample is evicted (FIFO).
    pub fn add_sample(&mut self, sample: ContributionSample) {
        if self.samples.len() >= self.max_samples {
            self.samples.remove(0);
        }
        self.samples.push(sample);
    }

    /// Record CRP earned from a completed period.
    /// Maximum number of CRP history entries before auto-pruning.
    pub const MAX_CRP_RECORDS: usize = 10_000;

    /// Record CRP earned from a completed period.
    /// Auto-prunes oldest entries when exceeding MAX_CRP_RECORDS.
    pub fn record_crp(&mut self, crp_amount: f64, window_hours: f64) {
        self.history.push(CrpEntry {
            crp_amount,
            timestamp_ms: crate::resource::now_ms(),
            window_hours,
        });
        // Auto-prune when exceeding limit
        while self.history.len() > Self::MAX_CRP_RECORDS {
            self.history.remove(0);
        }
    }

    /// Calculate CRP rate from all current samples.
    ///
    /// Formula:
    ///   CRP_raw = Σ(sample_i.weighted_score / sample_i.window_hours)
    ///   CRP_rate = CRP_raw × pioneer_multiplier(network_size)
    ///   CRP_rate = min(CRP_rate, cap / half_life_hours)
    ///
    /// Weighted score per sample:
    ///   score = CRP_WEIGHT_CPU × cpu_hours
    ///        + CRP_WEIGHT_MEMORY × memory_gb_hours
    ///        + CRP_WEIGHT_BANDWIDTH × bandwidth_gb_hours
    ///        + CRP_WEIGHT_STORAGE × storage_gb_hours
    ///        + CRP_WEIGHT_UPTIME × uptime_hours
    pub fn calculate_crp_rate(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }

        let mut total_weighted_score = 0.0;
        let mut total_hours = 0.0;

        for sample in &self.samples {
            let hours = sample.window_hours.max(0.001); // avoid division by zero
            let cpu_hours = sample.cpu_ms as f64 / 3_600_000.0;
            let mem_gb_hours = (sample.memory_peak_bytes as f64 / (1024.0 * 1024.0 * 1024.0)) * hours;
            let bw_gb_hours = (sample.bandwidth_bytes as f64 / (1024.0 * 1024.0 * 1024.0)) * hours;
            let storage_gb_hours = (sample.storage_bytes as f64 / (1024.0 * 1024.0 * 1024.0)) * hours;
            let uptime_hours = sample.uptime_ms as f64 / 3_600_000.0;

            let score = economy_params::CRP_WEIGHT_CPU * cpu_hours
                + economy_params::CRP_WEIGHT_MEMORY * mem_gb_hours
                + economy_params::CRP_WEIGHT_BANDWIDTH * bw_gb_hours
                + economy_params::CRP_WEIGHT_STORAGE * storage_gb_hours
                + economy_params::CRP_WEIGHT_UPTIME * uptime_hours;

            total_weighted_score += score;
            total_hours += hours;
        }

        // Average weighted score per hour
        let raw_rate = if total_hours > 0.0 {
            total_weighted_score / total_hours
        } else {
            0.0
        };

        // Apply pioneer multiplier
        let pioneer = economy_params::pioneer_multiplier(self.network_size);
        let rate = raw_rate * pioneer;

        // Apply cap
        let cap = economy_params::crp_cap(self.network_size);
        let max_hourly = cap / economy_params::CRP_HALF_LIFE_HOURS;
        rate.min(max_hourly)
    }

    /// Calculate CRP rate with decay applied for inactive periods.
    ///
    /// Applies exponential decay based on time since last sample.
    /// Uses CRP half-life from economy_params.
    pub fn calculate_crp_rate_with_decay(&self) -> f64 {
        let base_rate = self.calculate_crp_rate();
        if base_rate <= 0.0 {
            return 0.0;
        }

        // Apply decay if last sample is old
        if let Some(last) = self.samples.last() {
            let now_ms = crate::resource::now_ms();
            let hours_since_last = (now_ms.saturating_sub(last.timestamp_ms)) as f64 / 3_600_000.0;
            if hours_since_last > 1.0 {
                let lambda = economy_params::crp_decay_factor_per_hour();
                // CRP decays as e^(-lambda * hours)
                let decay = (-lambda * hours_since_last).exp();
                return base_rate * decay;
            }
        }

        base_rate
    }

    /// Get total cumulative CRP (sum of all history entries).
    ///
    /// Does NOT apply decay — use `effective_cumulative_crp()` for that.
    pub fn cumulative_crp(&self) -> f64 {
        self.history.iter().map(|e| e.crp_amount).sum()
    }

    /// Get effective cumulative CRP with decay applied.
    ///
    /// Each history entry decays based on its age.
    pub fn effective_cumulative_crp(&self) -> f64 {
        let now_ms = crate::resource::now_ms();
        let lambda = economy_params::crp_decay_factor_per_hour();

        self.history
            .iter()
            .map(|entry| {
                let hours_old = (now_ms.saturating_sub(entry.timestamp_ms)) as f64 / 3_600_000.0;
                let decay = (-lambda * hours_old).exp();
                entry.crp_amount * decay
            })
            .sum()
    }

    /// Update network size (e.g., after mDNS discovery).
    pub fn set_network_size(&mut self, size: u32) {
        self.network_size = size.max(1);
    }

    /// Prune old history entries (older than max_age_hours).
    pub fn prune_history(&mut self, max_age_hours: f64) {
        let now_ms = crate::resource::now_ms();
        let max_age_ms = (max_age_hours * 3_600_000.0) as u64;
        self.history.retain(|e| now_ms.saturating_sub(e.timestamp_ms) < max_age_ms);
    }

    /// Number of active samples.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu_sample(cpu_ms: u64, window_hours: f64) -> ContributionSample {
        ContributionSample {
            cpu_ms,
            window_hours,
            ..Default::default()
        }
    }

    fn full_sample(
        cpu_ms: u64,
        memory_bytes: u64,
        bandwidth_bytes: u64,
        storage_bytes: u64,
        uptime_ms: u64,
        window_hours: f64,
    ) -> ContributionSample {
        ContributionSample {
            cpu_ms,
            memory_peak_bytes: memory_bytes,
            bandwidth_bytes,
            storage_bytes,
            uptime_ms,
            window_hours,
            ..Default::default()
        }
    }

    #[test]
    fn test_empty_accumulator() {
        let acc = CrpAccumulator::new();
        assert_eq!(acc.calculate_crp_rate(), 0.0);
        assert_eq!(acc.cumulative_crp(), 0.0);
    }

    #[test]
    fn test_single_cpu_sample() {
        let mut acc = CrpAccumulator::with_network_size(100);
        // 1 CPU core × 1 hour = 3600_000 ms
        acc.add_sample(cpu_sample(3_600_000, 1.0));

        let rate = acc.calculate_crp_rate();
        // cpu_hours = 1.0, score = 0.30 × 1.0 = 0.30
        // pioneer(100) ≈ 1.30
        // rate ≈ 0.30 × 1.30 = 0.39
        assert!(rate > 0.3 && rate < 0.5);
    }

    #[test]
    fn test_all_resource_weights() {
        let mut acc = CrpAccumulator::with_network_size(100);
        // 1 hour of each resource at reasonable amounts
        acc.add_sample(full_sample(
            3_600_000,     // 1 CPU·hr
            4 * 1024 * 1024 * 1024u64, // 4 GB memory
            100 * 1024 * 1024 * 1024u64, // 100 GB bandwidth
            256 * 1024 * 1024 * 1024u64, // 256 GB storage
            3_600_000,     // 1 hr uptime
            1.0,
        ));

        let rate = acc.calculate_crp_rate();
        // score = 0.30×1 + 0.15×4 + 0.30×100 + 0.15×256 + 0.10×1
        //       = 0.30 + 0.60 + 30.0 + 38.4 + 0.10 = 69.4
        // rate = 69.4 × 1.30 ≈ 90.2
        assert!(rate > 80.0 && rate < 100.0);
    }

    #[test]
    fn test_pioneer_multiplier() {
        let mut small = CrpAccumulator::with_network_size(5);
        let mut large = CrpAccumulator::with_network_size(1000);

        let sample = cpu_sample(3_600_000, 1.0);
        small.add_sample(sample.clone());
        large.add_sample(sample);

        // Small network has higher pioneer multiplier
        assert!(small.calculate_crp_rate() > large.calculate_crp_rate());
    }

    #[test]
    fn test_crp_cap() {
        let mut acc = CrpAccumulator::with_network_size(100);
        // Extreme contribution — should be capped
        acc.add_sample(full_sample(
            1_000_000_000_000, // absurd CPU
            1024 * 1024 * 1024 * 1024 * 1024u64, // 1 TB
            1024 * 1024 * 1024 * 1024 * 1024u64, // 1 TB
            1024 * 1024 * 1024 * 1024 * 1024u64, // 1 TB
            3_600_000 * 1000, // 1000 hrs uptime
            1.0,
        ));

        let rate = acc.calculate_crp_rate();
        let cap = economy_params::crp_cap(100);
        let max_hourly = cap / economy_params::CRP_HALF_LIFE_HOURS;
        assert!(rate <= max_hourly);
    }

    #[test]
    fn test_sample_eviction() {
        let mut acc = CrpAccumulator::new();
        acc.max_samples = 3;

        for _i in 0..5 {
            acc.add_sample(cpu_sample(3_600_000, 1.0));
        }

        // Should keep only 3 most recent
        assert_eq!(acc.sample_count(), 3);
    }

    #[test]
    fn test_cumulative_crp() {
        let mut acc = CrpAccumulator::new();
        acc.record_crp(10.0, 1.0);
        acc.record_crp(20.0, 2.0);
        acc.record_crp(5.0, 0.5);

        assert!((acc.cumulative_crp() - 35.0).abs() < 0.001);
    }

    #[test]
    fn test_effective_cumulative_with_decay() {
        let mut acc = CrpAccumulator::new();
        // Simulate an old entry by manipulating timestamp
        let now = crate::resource::now_ms();
        acc.history.push(CrpEntry {
            crp_amount: 100.0,
            timestamp_ms: now - (720 * 3_600_000), // exactly 1 half-life ago (720h)
            window_hours: 1.0,
        });
        acc.history.push(CrpEntry {
            crp_amount: 100.0,
            timestamp_ms: now,
            window_hours: 1.0,
        });

        // Old entry should be halved, new entry at full value
        let effective = acc.effective_cumulative_crp();
        // 100 × 0.5 + 100 × 1.0 = 150
        assert!(effective > 140.0 && effective < 160.0);
    }

    #[test]
    fn test_prune_history() {
        let mut acc = CrpAccumulator::new();
        let now = crate::resource::now_ms();

        acc.history.push(CrpEntry { crp_amount: 10.0, timestamp_ms: now, window_hours: 1.0 });
        acc.history.push(CrpEntry { crp_amount: 20.0, timestamp_ms: now - (100 * 3_600_000), window_hours: 1.0 }); // 100h ago
        acc.history.push(CrpEntry { crp_amount: 30.0, timestamp_ms: now - (200 * 3_600_000), window_hours: 1.0 }); // 200h ago

        acc.prune_history(150.0); // keep entries younger than 150h

        assert_eq!(acc.history.len(), 2);
        assert_eq!(acc.history[0].crp_amount, 10.0);
        assert_eq!(acc.history[1].crp_amount, 20.0);
    }

    #[test]
    fn test_set_network_size() {
        let mut acc = CrpAccumulator::new();
        acc.add_sample(cpu_sample(3_600_000, 1.0));

        let rate_small = acc.calculate_crp_rate();
        acc.set_network_size(1000);
        let rate_large = acc.calculate_crp_rate();

        assert!(rate_small > rate_large); // higher pioneer for smaller network
    }

    #[test]
    fn test_zero_window_hours_safe() {
        let mut acc = CrpAccumulator::with_network_size(100);
        // Window of 0 hours — should not panic
        acc.add_sample(cpu_sample(3_600_000, 0.0));
        let rate = acc.calculate_crp_rate();
        // With 0.001 clamped window, rate should be finite
        assert!(rate.is_finite());
    }

    #[test]
    fn test_decay_with_no_samples() {
        let acc = CrpAccumulator::new();
        assert_eq!(acc.calculate_crp_rate_with_decay(), 0.0);
    }

    #[test]
    fn test_multiple_samples_average() {
        let mut acc = CrpAccumulator::with_network_size(100);
        // Two samples: 0.5 CPU·hr each → average should be 0.5 CPU·hr
        acc.add_sample(cpu_sample(1_800_000, 1.0));
        acc.add_sample(cpu_sample(1_800_000, 1.0));

        let rate = acc.calculate_crp_rate();
        // score = (0.30 × 0.5 + 0.30 × 0.5) / 2 hours = 0.15/hr average
        // rate ≈ 0.15 × 1.30 ≈ 0.195
        assert!(rate > 0.15 && rate < 0.25);
    }
}
