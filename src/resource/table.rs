//! Resource table: local cache of all known node resource declarations.

use crate::resource::types::*;
use std::collections::HashMap;

/// How long before a declaration is considered stale (ms).
const AD_EXPIRY_MS: u64 = 180_000; // 3 minutes (3× broadcast interval)

/// Maximum entries in the table (prevents unbounded growth).
const MAX_ENTRIES: usize = 10_000;

/// Local resource table tracking all known node declarations.
#[derive(Debug, Clone)]
pub struct ResourceTable {
    /// agent_id → (advertisement, last_seen_ms)
    entries: HashMap<String, (ResourceAdvertisement, u64)>,
}

impl Default for ResourceTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Update table with a new advertisement.
    ///
    /// Only accepts ads with a sequence number strictly greater than the
    /// existing entry. Returns `true` if the table was actually updated.
    pub fn update(&mut self, ad: ResourceAdvertisement) -> bool {
        if ad.agent_id.is_empty() {
            return false;
        }

        let now = now_ms();

        match self.entries.get(&ad.agent_id) {
            Some((existing, _)) if ad.sequence <= existing.sequence => return false,
            _ => {}
        }

        // Evict oldest entry if at capacity (simple LRU-like).
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&ad.agent_id) {
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, ts))| ts)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(ad.agent_id.clone(), (ad, now));
        true
    }

    /// Remove all entries older than `AD_EXPIRY_MS`.
    /// Returns the number of entries evicted.
    pub fn evict_expired(&mut self) -> usize {
        let cutoff = now_ms().saturating_sub(AD_EXPIRY_MS);
        let before = self.entries.len();
        self.entries
            .retain(|_, (_, last_seen)| *last_seen > cutoff);
        before - self.entries.len()
    }

    /// Look up a specific node's advertisement.
    pub fn get(&self, agent_id: &str) -> Option<&ResourceAdvertisement> {
        self.entries.get(agent_id).map(|(ad, _)| ad)
    }

    /// Find all nodes that satisfy the given resource request,
    /// sorted by estimated capacity (highest first).
    pub fn find_candidates(&self, req: &ResourceRequest) -> Vec<ResourceCandidate> {
        let mut candidates: Vec<ResourceCandidate> = self
            .entries
            .iter()
            .filter(|(_, (ad, _))| ad.satisfies(req))
            .map(|(id, (ad, _))| {
                let score = Self::compute_score(ad, req);
                ResourceCandidate {
                    agent_id: id.clone(),
                    advertisement: ad.clone(),
                    score,
                }
            })
            .collect();

        // Sort highest score first.
        candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates
    }

    /// Number of entries currently tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all stored advertisements as a Vec.
    pub fn entries(&self) -> Vec<ResourceAdvertisement> {
        self.entries.values().map(|(ad, _)| ad.clone()).collect()
    }

    /// Compute a suitability score for a given ad/request pair.
    ///
    /// Higher score = better fit. Based on how much headroom the node
    /// has beyond the minimum request (驚羽: Least Loaded strategy).
    fn compute_score(ad: &ResourceAdvertisement, req: &ResourceRequest) -> f64 {
        let cpu_headroom = (ad.cpu_offer - req.min_cpu).max(0.0) as f64;
        let mem_headroom = (ad.memory_offer_mb as f64) - (req.min_memory_mb as f64);
        let bw_headroom = (ad.bandwidth_offer as f64) - (req.min_bandwidth as f64);
        let stor_headroom = (ad.storage_offer as f64) - (req.min_storage as f64);
        cpu_headroom * 4.0 + mem_headroom * 2.0 + bw_headroom * 1.0 + stor_headroom * 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ad(agent_id: &str, seq: u64, cpu: f32, mem: u64) -> ResourceAdvertisement {
        ResourceAdvertisement {
            agent_id: agent_id.to_string(),
            sequence: seq,
            timestamp: now_ms(),
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 256 * 1024 * 1024 * 1024,
            },
            cpu_offer: cpu,
            memory_offer_mb: mem,
            bandwidth_offer: 1_000_000,
            storage_offer: 10 * 1024 * 1024 * 1024,
            features: vec!["always-on".to_string()],
            signature: Vec::new(),
            signing_pubkey: Vec::new(),
        }
    }

    fn make_request(min_cpu: f32, min_mem: u64) -> ResourceRequest {
        ResourceRequest {
            request_id: String::new(),
            consumer_id: "did:walkie:consumer".to_string(),
            min_cpu,
            min_memory_mb: min_mem,
            min_bandwidth: 0,
            min_storage: 0,
            required_features: vec![],
            duration_ms: 60_000,
            priority: 75,
            expires_at: 0,
        }
    }

    #[test]
    fn test_update_accepts_new_entry() {
        let mut table = ResourceTable::new();
        let ad = make_ad("agent-1", 1, 0.2, 2048);
        assert!(table.update(ad));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_update_rejects_stale_sequence() {
        let mut table = ResourceTable::new();
        let ad1 = make_ad("agent-1", 5, 0.2, 2048);
        assert!(table.update(ad1));

        let ad2 = make_ad("agent-1", 3, 0.3, 4096); // older seq
        assert!(!table.update(ad2));
        // Should still have the seq=5 version
        assert_eq!(table.get("agent-1").unwrap().cpu_offer, 0.2);
    }

    #[test]
    fn test_update_accepts_newer_sequence() {
        let mut table = ResourceTable::new();
        let ad1 = make_ad("agent-1", 5, 0.2, 2048);
        table.update(ad1);

        let ad2 = make_ad("agent-1", 10, 0.5, 4096);
        assert!(table.update(ad2));
        assert_eq!(table.get("agent-1").unwrap().cpu_offer, 0.5);
    }

    #[test]
    fn test_update_rejects_empty_agent_id() {
        let mut table = ResourceTable::new();
        let ad = make_ad("", 1, 0.2, 2048);
        assert!(!table.update(ad));
    }

    #[test]
    fn test_evict_expired() {
        let mut table = ResourceTable::new();
        let ad = make_ad("agent-1", 1, 0.2, 2048);
        table.update(ad);

        // Manually backdate the entry.
        let cutoff = now_ms().saturating_sub(AD_EXPIRY_MS + 1000);
        if let Some(entry) = table.entries.get_mut("agent-1") {
            entry.1 = cutoff;
        }

        let evicted = table.evict_expired();
        assert_eq!(evicted, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn test_find_candidates_sorted_by_score() {
        let mut table = ResourceTable::new();
        table.update(make_ad("small", 1, 0.1, 1024));
        table.update(make_ad("big", 1, 0.8, 8192));
        table.update(make_ad("medium", 1, 0.3, 2048));

        let req = make_request(0.05, 512);
        let candidates = table.find_candidates(&req);

        assert_eq!(candidates.len(), 3);
        // "big" should be first (highest score).
        assert_eq!(candidates[0].agent_id, "big");
    }

    #[test]
    fn test_find_candidates_filters_unsatisfied() {
        let mut table = ResourceTable::new();
        table.update(make_ad("small", 1, 0.1, 512));
        table.update(make_ad("big", 1, 0.8, 8192));

        let req = make_request(0.5, 1024); // need at least 50% CPU + 1GB
        let candidates = table.find_candidates(&req);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].agent_id, "big");
    }

    #[test]
    fn test_find_candidates_feature_filter() {
        let mut table = ResourceTable::new();
        let mut ad = make_ad("gpu-node", 1, 0.5, 4096);
        ad.features.push("gpu".to_string());
        table.update(ad);

        let req = ResourceRequest {
            request_id: String::new(),
            consumer_id: "consumer".to_string(),
            min_cpu: 0.1,
            min_memory_mb: 0,
            min_bandwidth: 0,
            min_storage: 0,
            required_features: vec!["gpu".to_string()],
            duration_ms: 60_000,
            priority: 75,
            expires_at: 0,
        };

        let candidates = table.find_candidates(&req);
        assert_eq!(candidates.len(), 1);

        let req_no_gpu = ResourceRequest {
            required_features: vec!["fpga".to_string()],
            ..req.clone()
        };
        assert!(table.find_candidates(&req_no_gpu).is_empty());
    }

    #[test]
    fn test_ad_satisfies() {
        let ad = make_ad("agent", 1, 0.3, 4096);
        let req = make_request(0.2, 2048);
        assert!(ad.satisfies(&req));

        let req_too_much = make_request(0.5, 2048);
        assert!(!ad.satisfies(&req_too_much));
    }

    #[test]
    fn test_ad_bump() {
        let mut ad = make_ad("agent", 1, 0.2, 2048);
        let old_ts = ad.timestamp;
        ad.bump();
        assert_eq!(ad.sequence, 2);
        assert!(ad.timestamp >= old_ts);
    }

    #[test]
    fn test_ad_builder() {
        let spec = ResourceSpec {
            cpu_cores: 8,
            total_memory_mb: 16384,
            max_bandwidth_up_mbps: 200,
            total_storage_bytes: 512 * 1024 * 1024 * 1024,
        };
        let ad = ResourceAdvertisement::new("did:walkie:test".to_string(), spec)
            .with_cpu(0.25)
            .with_memory(4096)
            .with_bandwidth(2_000_000)
            .with_storage(50 * 1024 * 1024 * 1024)
            .with_feature("always-on")
            .with_feature("arm64");

        assert!((ad.cpu_offer - 0.25).abs() < f32::EPSILON);
        assert_eq!(ad.memory_offer_mb, 4096);
        assert_eq!(ad.bandwidth_offer, 2_000_000);
        assert!(ad.features.contains(&"arm64".to_string()));
        // Adding duplicate feature should not duplicate.
        let ad2 = ad.clone().with_feature("always-on");
        assert_eq!(
            ad2.features.iter().filter(|f| *f == "always-on").count(),
            1
        );
    }

    #[test]
    fn test_entries_returns_all() {
        let mut table = ResourceTable::new();
        table.update(make_ad("a", 1, 0.1, 512));
        table.update(make_ad("b", 2, 0.5, 4096));

        let entries = table.entries();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|a| a.agent_id == "a"));
        assert!(entries.iter().any(|a| a.agent_id == "b"));
    }

    #[test]
    fn test_entries_empty_table() {
        let table = ResourceTable::new();
        assert!(table.entries().is_empty());
    }
}
