//! Resource Match Engine — Phase 3.
//!
//! Matches consumer ResourceRequests against known provider resources.
//! Scoring considers:
//! - **Resource sufficiency**: how much headroom beyond the minimum request
//! - **Latency** (placeholder): will use ping RTT when available
//! - **Reliability** (placeholder): will use historical session success rate
//!
//! Design principle (Carmack): measure first, optimize later.
//! The scoring weights are constants now; they become configurable when we
//! have real data from production traffic.

use crate::resource::session::ResourceSessionManager;
use crate::resource::table::ResourceTable;
use crate::resource::types::*;

// ── Scoring weights ────────────────────────────────────────────

/// Weight for resource sufficiency score component.
const W_RESOURCE: f64 = 0.8;

/// Weight for latency score component (placeholder).
const W_LATENCY: f64 = 0.1;

/// Weight for reliability score component (placeholder).
const W_RELIABILITY: f64 = 0.1;

/// Default neutral score for placeholder components.
const NEUTRAL_PLACEHOLDER: f64 = 0.5;

/// How long a pending offer stays reserved before auto-release (ms).
pub const RESERVATION_TTL_MS: u64 = 30_000;

// ── Match result ───────────────────────────────────────────────

/// Result of matching a single provider against a request.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchResult {
    /// The provider's agent ID.
    pub provider_id: String,

    /// Total match score (0.0 ~ 1.0, higher = better).
    pub score: f64,

    /// Individual score components (for debugging / logging).
    pub components: ScoreComponents,

    /// The provider's advertisement.
    pub advertisement: ResourceAdvertisement,
}

/// Breakdown of match score components.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreComponents {
    /// How well the resources match (0.0 ~ 1.0).
    pub resource: f64,

    /// Latency score (placeholder, always 0.5).
    pub latency: f64,

    /// Historical reliability score (placeholder, always 0.5).
    pub reliability: f64,
}

impl std::fmt::Display for ScoreComponents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "resource={:.3} latency={:.3} reliability={:.3}",
            self.resource, self.latency, self.reliability
        )
    }
}

// ── Placeholder latency / reliability ──────────────────────────

/// Placeholder for per-peer latency data.
///
/// In Phase 4, this will be populated from Ping RTT data.
/// For now it returns a neutral score for all peers.
#[derive(Debug, Clone, Default)]
pub struct LatencyTracker;

impl LatencyTracker {
    pub fn new() -> Self {
        Self
    }

    /// Get latency score for a peer (placeholder: always neutral).
    pub fn score(&self, _agent_id: &str) -> f64 {
        NEUTRAL_PLACEHOLDER
    }
}

/// Placeholder for per-peer reliability data.
///
/// In Phase 4, this will track session success/failure ratios.
/// For now it returns a neutral score for all peers.
#[derive(Debug, Clone, Default)]
pub struct ReliabilityTracker;

impl ReliabilityTracker {
    pub fn new() -> Self {
        Self
    }

    /// Get reliability score for a peer (placeholder: always neutral).
    pub fn score(&self, _agent_id: &str) -> f64 {
        NEUTRAL_PLACEHOLDER
    }
}

// ── Match Engine ───────────────────────────────────────────────

/// The resource match engine.
///
/// Stateless — takes a request + table and returns ranked results.
/// Latency and reliability trackers are injected for future use.
#[derive(Debug, Clone)]
pub struct MatchEngine {
    pub latency: LatencyTracker,
    pub reliability: ReliabilityTracker,
}

impl Default for MatchEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchEngine {
    pub fn new() -> Self {
        Self {
            latency: LatencyTracker::new(),
            reliability: ReliabilityTracker::new(),
        }
    }

    /// Find all matching providers for a request, sorted by score (best first).
    ///
    /// Only returns providers whose advertisement satisfies ALL minimum
    /// requirements of the request, AND who have remaining capacity
    /// after accounting for currently allocated sessions.
    pub fn find_providers(
        &self,
        req: &ResourceRequest,
        table: &ResourceTable,
        sessions: &ResourceSessionManager,
    ) -> Vec<MatchResult> {
        let mut results: Vec<MatchResult> = Vec::new();

        for ad in table.entries() {
            // 1. Does the ad satisfy the minimum requirements?
            if !ad.satisfies(req) {
                continue;
            }

            // 2. Does the provider have remaining capacity?
            let (used_cpu, used_mem) = sessions.current_allocation(&ad.agent_id);
            let remaining_cpu = ad.cpu_offer - used_cpu;
            let remaining_mem = ad.memory_offer_mb.saturating_sub(used_mem);

            if remaining_cpu < req.min_cpu || remaining_mem < req.min_memory_mb {
                continue;
            }
            if ad.bandwidth_offer < req.min_bandwidth || ad.storage_offer < req.min_storage {
                // Already checked by satisfies(), but be explicit for allocated resources
                continue;
            }

            // 3. Compute score.
            let components = ScoreComponents {
                resource: Self::resource_score(&ad, req, remaining_cpu, remaining_mem),
                latency: self.latency.score(&ad.agent_id),
                reliability: self.reliability.score(&ad.agent_id),
            };

            let score = W_RESOURCE * components.resource
                + W_LATENCY * components.latency
                + W_RELIABILITY * components.reliability;

            results.push(MatchResult {
                provider_id: ad.agent_id.clone(),
                score,
                components,
                advertisement: ad,
            });
        }

        // Sort by score descending.
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        results
    }

    /// Find the single best match for a request.
    ///
    /// Returns `None` if no provider satisfies the request.
    pub fn find_best(
        &self,
        req: &ResourceRequest,
        table: &ResourceTable,
        sessions: &ResourceSessionManager,
    ) -> Option<MatchResult> {
        self.find_providers(req, table, sessions).into_iter().next()
    }

    /// Check if our own node can serve a request.
    ///
    /// Returns a MatchResult if we can serve, None otherwise.
    pub fn can_we_serve(
        &self,
        req: &ResourceRequest,
        my_ad: &ResourceAdvertisement,
        sessions: &ResourceSessionManager,
        our_agent_id: &str,
    ) -> Option<MatchResult> {
        if !my_ad.satisfies(req) {
            return None;
        }

        let (used_cpu, used_mem) = sessions.current_allocation(our_agent_id);
        let remaining_cpu = my_ad.cpu_offer - used_cpu;
        let remaining_mem = my_ad.memory_offer_mb.saturating_sub(used_mem);

        if remaining_cpu < req.min_cpu || remaining_mem < req.min_memory_mb {
            return None;
        }

        let components = ScoreComponents {
            resource: Self::resource_score(my_ad, req, remaining_cpu, remaining_mem),
            latency: self.latency.score(our_agent_id),
            reliability: self.reliability.score(our_agent_id),
        };

        let score = W_RESOURCE * components.resource
            + W_LATENCY * components.latency
            + W_RELIABILITY * components.reliability;

        Some(MatchResult {
            provider_id: our_agent_id.to_string(),
            score,
            components,
            advertisement: my_ad.clone(),
        })
    }

    /// Compute resource sufficiency score (0.0 ~ 1.0).
    ///
    /// Based on how much headroom the provider has beyond the request.
    /// Uses the *remaining* capacity (after current allocations).
    fn resource_score(
        ad: &ResourceAdvertisement,
        req: &ResourceRequest,
        remaining_cpu: f32,
        remaining_mem: u64,
    ) -> f64 {
        // Normalize each dimension to 0..1 based on how much of the ad's
        // total offer remains after satisfying the request.
        let cpu_ratio = if ad.cpu_offer > 0.0 {
            (remaining_cpu - req.min_cpu).max(0.0) as f64 / ad.cpu_offer as f64
        } else {
            0.0
        };

        let mem_ratio = if ad.memory_offer_mb > 0 {
            (remaining_mem.saturating_sub(req.min_memory_mb)) as f64
                / ad.memory_offer_mb as f64
        } else {
            0.0
        };

        let bw_ratio = if ad.bandwidth_offer > 0 {
            (ad.bandwidth_offer.saturating_sub(req.min_bandwidth)) as f64
                / ad.bandwidth_offer as f64
        } else {
            0.0
        };

        let stor_ratio = if ad.storage_offer > 0 {
            (ad.storage_offer.saturating_sub(req.min_storage)) as f64
                / ad.storage_offer as f64
        } else {
            0.0
        };

        // Weighted average: CPU and memory are most important.
        let score = cpu_ratio * 0.4 + mem_ratio * 0.3 + bw_ratio * 0.15 + stor_ratio * 0.15;

        // Clamp to [0, 1].
        let base_score = score.clamp(0.0, 1.0);

        // Age decay: advertisements older than 60s are penalized.
        // Linear decay from 1.0 → 0.1 over the next 120s, then stays at 0.1.
        let age_factor = {
            let age_ms = now_ms().saturating_sub(ad.timestamp);
            if age_ms <= 60_000 {
                1.0
            } else if age_ms <= 180_000 {
                // 60s..180s: 1.0 → 0.1 linearly
                1.0 - 0.9 * ((age_ms - 60_000) as f64 / 120_000.0)
            } else {
                0.1
            }
        };

        (base_score * age_factor).clamp(0.0, 1.0)
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ad(agent_id: &str, cpu: f32, mem: u64, bw: u64, stor: u64) -> ResourceAdvertisement {
        ResourceAdvertisement {
            agent_id: agent_id.to_string(),
            sequence: 1,
            timestamp: now_ms(),
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 256 * 1024 * 1024 * 1024,
            },
            cpu_offer: cpu,
            memory_offer_mb: mem,
            bandwidth_offer: bw,
            storage_offer: stor,
            features: vec!["always-on".to_string()],
            signature: Vec::new(),
            signing_pubkey: Vec::new(),
        }
    }

    fn make_request(cpu: f32, mem: u64) -> ResourceRequest {
        ResourceRequest {
            request_id: "req-001".to_string(),
            consumer_id: "did:walkie:consumer".to_string(),
            min_cpu: cpu,
            min_memory_mb: mem,
            min_bandwidth: 0,
            min_storage: 0,
            required_features: vec![],
            duration_ms: 60_000,
            priority: 75,
            expires_at: 0,
        }
    }

    fn populated_table() -> ResourceTable {
        let mut table = ResourceTable::new();
        table.update(make_ad("big", 0.8, 8192, 10_000_000, 100_000_000_000));
        table.update(make_ad("medium", 0.3, 2048, 5_000_000, 50_000_000_000));
        table.update(make_ad("small", 0.1, 512, 1_000_000, 10_000_000_000));
        table
    }

    // ── Unit tests: scoring ──

    #[test]
    fn test_resource_score_perfect_match() {
        let ad = make_ad("node", 0.5, 4096, 5_000_000, 50_000_000_000);
        // Request exactly what's offered → CPU and memory headroom = 0,
        // but bw/storage still have headroom since request doesn't need them.
        // Score should be low (only bw + storage contributions).
        let req = make_request(0.5, 4096);
        let score = MatchEngine::resource_score(&ad, &req, 0.5, 4096);
        // CPU (0.0*0.4) + Mem (0.0*0.3) + BW (1.0*0.15) + Stor (1.0*0.15) = 0.3
        assert!((score - 0.3).abs() < 0.001, "expected ~0.3, got {score}");
    }

    #[test]
    fn test_resource_score_with_headroom() {
        let ad = make_ad("node", 0.8, 8192, 10_000_000, 100_000_000_000);
        let req = make_request(0.1, 1024);
        let score = MatchEngine::resource_score(&ad, &req, 0.7, 7168);
        // headroom beyond request: cpu=0.6, mem=6144, all positive
        assert!(score > 0.0);
        assert!(score <= 1.0);
    }

    #[test]
    fn test_resource_score_clamped() {
        let ad = make_ad("node", 1.0, 8192, 10_000_000, 100_000_000_000);
        let req = make_request(0.0, 0);
        let score = MatchEngine::resource_score(&ad, &req, 1.0, 8192);
        // All ratios = 1.0 → score should be 1.0
        assert!((score - 1.0).abs() < 0.001);
    }

    // ── Unit tests: find_providers ──

    #[test]
    fn test_find_providers_all_match() {
        let engine = MatchEngine::new();
        let table = populated_table();
        let sessions = ResourceSessionManager::new();
        let req = make_request(0.05, 256);

        let results = engine.find_providers(&req, &table, &sessions);
        assert_eq!(results.len(), 3);

        // "big" should rank first (most headroom).
        assert_eq!(results[0].provider_id, "big");
        assert!(results[0].score > results[1].score);
        assert!(results[1].score > results[2].score);
    }

    #[test]
    fn test_find_providers_partial_match() {
        let engine = MatchEngine::new();
        let table = populated_table();
        let sessions = ResourceSessionManager::new();

        // Only "big" can satisfy 50% CPU + 4GB.
        let req = make_request(0.5, 4096);
        let results = engine.find_providers(&req, &table, &sessions);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].provider_id, "big");
    }

    #[test]
    fn test_find_providers_no_match() {
        let engine = MatchEngine::new();
        let table = populated_table();
        let sessions = ResourceSessionManager::new();

        // Impossible request.
        let req = make_request(1.0, 100_000);
        let results = engine.find_providers(&req, &table, &sessions);
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_providers_with_existing_allocations() {
        let engine = MatchEngine::new();
        let table = populated_table();
        let mut sessions = ResourceSessionManager::new();

        // Allocate most of "big"'s resources.
        sessions.create_session("consumer-1".into(), "big".into(), 0.7, 7000, 60_000);

        let req = make_request(0.2, 2048);
        let results = engine.find_providers(&req, &table, &sessions);

        // "big" can no longer serve (0.8 - 0.7 = 0.1 < 0.2 CPU).
        assert!(results.iter().all(|r| r.provider_id != "big"));
    }

    #[test]
    fn test_find_best_returns_highest() {
        let engine = MatchEngine::new();
        let table = populated_table();
        let sessions = ResourceSessionManager::new();
        let req = make_request(0.05, 256);

        let best = engine.find_best(&req, &table, &sessions);
        assert!(best.is_some());
        assert_eq!(best.unwrap().provider_id, "big");
    }

    #[test]
    fn test_find_best_none_when_no_match() {
        let engine = MatchEngine::new();
        let table = populated_table();
        let sessions = ResourceSessionManager::new();
        let req = make_request(1.0, 100_000);

        assert!(engine.find_best(&req, &table, &sessions).is_none());
    }

    // ── Unit tests: can_we_serve ──

    #[test]
    fn test_can_we_serve_yes() {
        let engine = MatchEngine::new();
        let ad = make_ad("us", 0.5, 4096, 5_000_000, 50_000_000_000);
        let sessions = ResourceSessionManager::new();
        let req = make_request(0.2, 1024);

        let result = engine.can_we_serve(&req, &ad, &sessions, "us");
        assert!(result.is_some());
        assert_eq!(result.unwrap().provider_id, "us");
    }

    #[test]
    fn test_can_we_serve_no_insufficient() {
        let engine = MatchEngine::new();
        let ad = make_ad("us", 0.1, 512, 1_000_000, 10_000_000_000);
        let sessions = ResourceSessionManager::new();
        let req = make_request(0.5, 1024);

        assert!(engine.can_we_serve(&req, &ad, &sessions, "us").is_none());
    }

    #[test]
    fn test_can_we_serve_no_already_allocated() {
        let engine = MatchEngine::new();
        let ad = make_ad("us", 0.5, 4096, 5_000_000, 50_000_000_000);
        let mut sessions = ResourceSessionManager::new();
        sessions.create_session("other".into(), "us".into(), 0.4, 3000, 60_000);

        let req = make_request(0.2, 2048);
        // 0.5 - 0.4 = 0.1 < 0.2 CPU → can't serve
        assert!(engine.can_we_serve(&req, &ad, &sessions, "us").is_none());
    }

    // ── Feature matching ──

    #[test]
    fn test_find_providers_feature_filter() {
        let engine = MatchEngine::new();
        let mut table = ResourceTable::new();

        let mut gpu_ad = make_ad("gpu-node", 0.5, 4096, 5_000_000, 50_000_000_000);
        gpu_ad.features.push("gpu".to_string());
        table.update(gpu_ad);
        table.update(make_ad("cpu-node", 0.5, 4096, 5_000_000, 50_000_000_000));

        let sessions = ResourceSessionManager::new();
        let mut req = make_request(0.1, 1024);
        req.required_features = vec!["gpu".to_string()];

        let results = engine.find_providers(&req, &table, &sessions);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].provider_id, "gpu-node");
    }

    // ── Placeholder components ──

    #[test]
    fn test_placeholder_latency_score() {
        let tracker = LatencyTracker::new();
        assert!((tracker.score("anyone") - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_placeholder_reliability_score() {
        let tracker = ReliabilityTracker::new();
        assert!((tracker.score("anyone") - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_score_components_display() {
        let sc = ScoreComponents {
            resource: 0.8,
            latency: 0.5,
            reliability: 0.5,
        };
        let s = sc.to_string();
        assert!(s.contains("resource=0.800"));
        assert!(s.contains("latency=0.500"));
    }

    // ── Score weight validation ──

    #[test]
    fn test_total_score_is_weighted_average() {
        let engine = MatchEngine::new();
        let table = populated_table();
        let sessions = ResourceSessionManager::new();
        let req = make_request(0.05, 256);

        let results = engine.find_providers(&req, &table, &sessions);
        for r in &results {
            let expected = W_RESOURCE * r.components.resource
                + W_LATENCY * r.components.latency
                + W_RELIABILITY * r.components.reliability;
            assert!((r.score - expected).abs() < 1e-10);
        }
    }

    // ── Edge: empty table ──

    #[test]
    fn test_find_providers_empty_table() {
        let engine = MatchEngine::new();
        let table = ResourceTable::new();
        let sessions = ResourceSessionManager::new();
        let req = make_request(0.1, 256);

        assert!(engine.find_providers(&req, &table, &sessions).is_empty());
        assert!(engine.find_best(&req, &table, &sessions).is_none());
    }

    // ── Concurrent request stress test ──

    #[test]
    fn test_concurrent_requests_dont_double_allocate() {
        let engine = MatchEngine::new();
        let table = populated_table();
        let mut sessions = ResourceSessionManager::new();

        // "big" has 0.8 CPU. Two requests of 0.5 each should only fit one.
        let req = make_request(0.5, 1024);

        let r1 = engine.find_providers(&req, &table, &sessions);
        assert!(r1.iter().any(|r| r.provider_id == "big"));

        // Simulate allocation for first request.
        sessions.create_session("c1".into(), "big".into(), 0.5, 1024, 60_000);

        // Second request: "big" should be excluded (0.8 - 0.5 = 0.3 < 0.5).
        let r2 = engine.find_providers(&req, &table, &sessions);
        assert!(r2.iter().all(|r| r.provider_id != "big"));
    }

    // ── Age decay tests ──

    #[test]
    fn test_age_decay_fresh_advertisement() {
        let engine = MatchEngine::new();
        let ad = make_ad("provider", 1.0, 8192, 100_000, 1_000_000);
        let req = make_request(0.1, 512);

        let mut table = populated_table();
        table.update(ad.clone());

        let sessions = ResourceSessionManager::new();
        let results = engine.find_providers(&req, &table, &sessions);

        // Find our specific provider
        let result = results.iter().find(|r| r.provider_id == "provider");
        assert!(result.is_some());
        assert!(result.unwrap().score > 0.8, "fresh ad should score high, got {}", result.unwrap().score);
    }

    #[test]
    fn test_age_decay_stale_advertisement() {
        let engine = MatchEngine::new();
        let mut ad = make_ad("provider", 1.0, 8192, 100_000, 1_000_000);
        // Set timestamp to 200s ago (beyond 180s decay window)
        ad.timestamp = crate::resource::now_ms() - 200_000;

        let mut table = populated_table();
        table.update(ad);

        let req = make_request(0.1, 512);
        let sessions = ResourceSessionManager::new();
        let results = engine.find_providers(&req, &table, &sessions);

        let result = results.iter().find(|r| r.provider_id == "provider");
        assert!(result.is_some());
        // Base score ~0.9, age_factor = 0.1, so final ~0.09
        let score = result.unwrap().score;
        assert!(score < 0.25, "stale ad should be penalized, got {}", score);
        assert!(score > 0.0, "stale ad should still have some score");
    }

    #[test]
    fn test_age_decay_middle_advertisement() {
        let engine = MatchEngine::new();
        let mut ad = make_ad("provider", 1.0, 8192, 100_000, 1_000_000);
        // 120s ago: 60s past start of decay, age_factor = 1.0 - 0.9*(60/120) = 0.55
        ad.timestamp = crate::resource::now_ms() - 120_000;

        let mut table = populated_table();
        table.update(ad);

        let req = make_request(0.1, 512);
        let sessions = ResourceSessionManager::new();
        let results = engine.find_providers(&req, &table, &sessions);

        let result = results.iter().find(|r| r.provider_id == "provider");
        assert!(result.is_some());
        let score = result.unwrap().score;
        assert!(
            score > 0.3 && score < 0.6,
            "mid-decay ad should score moderately, got {}", score
        );
    }
}
