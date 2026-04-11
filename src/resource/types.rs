//! Core types for the resource declaration module.

use serde::{Deserialize, Serialize};

/// Static hardware specification (set at startup, immutable).
///
/// Consumers need this for task matching: a "4-core 8GB offering 20% CPU"
/// is very different from a "16-core 64GB offering 20% CPU" (驚羽意見1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceSpec {
    /// Number of CPU cores.
    pub cpu_cores: u16,
    /// Total system memory in MB.
    pub total_memory_mb: u64,
    /// Maximum upload bandwidth in Mbps.
    pub max_bandwidth_up_mbps: u32,
    /// Total storage capacity in bytes.
    pub total_storage_bytes: u64,
}

/// A node's resource capability declaration.
///
/// Broadcast via Gossipsub on `/walkie-talkie/resource/1.0.0` (or embedded
/// in Heartbeat payload for small networks). Contains both static hardware
/// specs and dynamic resource offers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceAdvertisement {
    /// Declarer's DID (did:walkie:...)
    pub agent_id: String,

    /// Monotonically increasing sequence number (stale ads are discarded).
    pub sequence: u64,

    /// Declaration timestamp (ms since epoch).
    pub timestamp: u64,

    /// Static hardware specification.
    pub spec: ResourceSpec,

    // ── Dynamic resource offers ──

    /// CPU contribution offer (0.0 ~ 1.0, e.g. 0.2 = 20% of cpu_cores).
    pub cpu_offer: f32,

    /// Memory contribution offer in MB.
    pub memory_offer_mb: u64,

    /// Bandwidth contribution offer in bytes/sec.
    pub bandwidth_offer: u64,

    /// Storage contribution offer in bytes.
    pub storage_offer: u64,

    /// Feature tags for task matching (e.g. "always-on", "arm64", "gpu").
    pub features: Vec<String>,

    /// Ed25519 signature over all fields except this one.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl ResourceAdvertisement {
    /// Create a new advertisement with the given offers.
    pub fn new(agent_id: String, spec: ResourceSpec) -> Self {
        Self {
            agent_id,
            sequence: 0,
            timestamp: now_ms(),
            spec,
            cpu_offer: 0.0,
            memory_offer_mb: 0,
            bandwidth_offer: 0,
            storage_offer: 0,
            features: Vec::new(),
            signature: Vec::new(),
        }
    }

    /// Builder: set CPU offer (0.0 ~ 1.0).
    pub fn with_cpu(mut self, offer: f32) -> Self {
        self.cpu_offer = offer.clamp(0.0, 1.0);
        self
    }

    /// Builder: set memory offer in MB.
    pub fn with_memory(mut self, mb: u64) -> Self {
        self.memory_offer_mb = mb;
        self
    }

    /// Builder: set bandwidth offer in bytes/sec.
    pub fn with_bandwidth(mut self, bytes_per_sec: u64) -> Self {
        self.bandwidth_offer = bytes_per_sec;
        self
    }

    /// Builder: set storage offer in bytes.
    pub fn with_storage(mut self, bytes: u64) -> Self {
        self.storage_offer = bytes;
        self
    }

    /// Builder: add a feature tag.
    pub fn with_feature(mut self, feature: &str) -> Self {
        if !self.features.contains(&feature.to_string()) {
            self.features.push(feature.to_string());
        }
        self
    }

    /// Bump sequence number and timestamp for re-broadcast.
    pub fn bump(&mut self) {
        self.sequence += 1;
        self.timestamp = now_ms();
    }

    /// Check if this ad satisfies a resource request.
    pub fn satisfies(&self, req: &ResourceRequest) -> bool {
        let cpu_ok = self.cpu_offer >= req.min_cpu;
        let mem_ok = self.memory_offer_mb >= req.min_memory_mb;
        let bw_ok = self.bandwidth_offer >= req.min_bandwidth;
        let stor_ok = self.storage_offer >= req.min_storage;
        let feat_ok = req.required_features.iter().all(|f| self.features.contains(f));
        cpu_ok && mem_ok && bw_ok && stor_ok && feat_ok
    }

    /// Serialize the signable payload (all fields except signature).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_json::to_vec(&copy).unwrap_or_default()
    }
}

/// A resource request from a consumer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceRequest {
    /// Requester's DID.
    pub consumer_id: String,

    /// Minimum CPU share required (0.0 ~ 1.0).
    pub min_cpu: f32,

    /// Minimum memory required in MB.
    pub min_memory_mb: u64,

    /// Minimum bandwidth required in bytes/sec.
    pub min_bandwidth: u64,

    /// Minimum storage required in bytes.
    pub min_storage: u64,

    /// Required feature tags.
    pub required_features: Vec<String>,

    /// Expected usage duration in ms.
    pub duration_ms: u64,

    /// Request priority (0 = lowest, 255 = highest).
    pub priority: u8,
}

impl ResourceRequest {
    pub fn new(consumer_id: String) -> Self {
        Self {
            consumer_id,
            min_cpu: 0.0,
            min_memory_mb: 0,
            min_bandwidth: 0,
            min_storage: 0,
            required_features: Vec::new(),
            duration_ms: 60_000,
            priority: 75,
        }
    }
}

/// A resource offer from a provider in response to a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceOffer {
    /// Provider's DID.
    pub provider_id: String,

    /// The original request's consumer DID.
    pub consumer_id: String,

    /// Offered CPU share.
    pub cpu_amount: f32,

    /// Offered memory in MB.
    pub memory_amount_mb: u64,

    /// Offered bandwidth in bytes/sec.
    pub bandwidth_amount: u64,

    /// Offered storage in bytes.
    pub storage_amount: u64,

    /// Offer expiry timestamp (ms since epoch).
    pub expires_at: u64,

    /// Provider's signature.
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// Type of resource being allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Cpu,
    Memory,
    Bandwidth,
    Storage,
}

/// Status of a resource session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Offer sent, waiting for consumer to accept.
    Pending,
    /// Currently in use.
    Active,
    /// Consumer released normally.
    Released,
    /// Session timed out.
    Expired,
    /// Provider revoked the allocation.
    Revoked,
}

/// A candidate node found during resource discovery.
#[derive(Debug, Clone)]
pub struct ResourceCandidate {
    pub agent_id: String,
    pub advertisement: ResourceAdvertisement,
    /// Estimated capacity score (higher = better fit).
    pub score: f64,
}

/// Contribution record for a single resource session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContributionRecord {
    pub provider: String,
    pub consumer: String,
    pub resource_type: ResourceType,
    /// Declared contribution amount.
    pub declared_amount: f64,
    /// Measured actual contribution.
    pub actual_amount: f64,
    /// Session duration in ms.
    pub duration_ms: u64,
    /// Hash of the proof (WorkReceipt / StorageProof / BandwidthReceipt).
    pub proof_hash: Option<String>,
    pub timestamp: u64,
}

/// Local contribution ledger (stored per-node, no blockchain).
#[derive(Debug, Clone, Default)]
pub struct ContributionLedger {
    pub provided: Vec<ContributionRecord>,
    pub consumed: Vec<ContributionRecord>,
}

impl ContributionLedger {
    /// Calculate total contribution score: actual_amount × hours.
    pub fn total_contribution(&self) -> f64 {
        self.provided
            .iter()
            .map(|r| r.actual_amount * (r.duration_ms as f64 / 3_600_000.0))
            .sum()
    }
}

/// Current milliseconds since epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
