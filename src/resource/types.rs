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
/// Sent via Direct channel on peer connection (P2P integration).
/// Contains both static hardware specs and dynamic resource offers.
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

    /// Validate this advertisement against spec consistency and economy parameters.
    ///
    /// Checks that all offers are within spec limits and fields are sane.
    /// Economy parameters from `economy_params.rs` inform the validation rules.
    pub fn validate(&self) -> Result<(), ResourceValidationError> {
        // 1. Agent ID must be non-empty.
        if self.agent_id.is_empty() {
            return Err(ResourceValidationError::EmptyAgentId);
        }

        // 2. Sequence must be > 0 (bumped from initial 0 before sending).
        if self.sequence == 0 {
            return Err(ResourceValidationError::ZeroSequence);
        }

        // 3. CPU offer must be in [0.0, 1.0].
        if self.cpu_offer < 0.0 || self.cpu_offer > 1.0 {
            return Err(ResourceValidationError::CpuOfferOutOfRange(self.cpu_offer));
        }

        // 4. Memory offer must not exceed spec.
        if self.memory_offer_mb > self.spec.total_memory_mb {
            return Err(ResourceValidationError::MemoryOfferExceedsSpec {
                offered: self.memory_offer_mb,
                max: self.spec.total_memory_mb,
            });
        }

        // 5. Bandwidth offer must not exceed spec (Mbps → bytes/sec).
        let max_bw_bytes = (self.spec.max_bandwidth_up_mbps as u64)
            .saturating_mul(125_000); // Mbps × 1_000_000 / 8
        if self.bandwidth_offer > max_bw_bytes {
            return Err(ResourceValidationError::BandwidthOfferExceedsSpec {
                offered: self.bandwidth_offer,
                max: max_bw_bytes,
            });
        }

        // 6. Storage offer must not exceed spec.
        if self.storage_offer > self.spec.total_storage_bytes {
            return Err(ResourceValidationError::StorageOfferExceedsSpec {
                offered: self.storage_offer,
                max: self.spec.total_storage_bytes,
            });
        }

        // 7. Spec sanity: cpu_cores > 0.
        if self.spec.cpu_cores == 0 {
            return Err(ResourceValidationError::InvalidSpec {
                reason: "cpu_cores must be > 0".into(),
            });
        }

        // 8. Timestamp should not be more than 5 minutes in the future.
        let now = now_ms();
        if self.timestamp > now.saturating_add(300_000) {
            return Err(ResourceValidationError::FutureTimestamp);
        }

        Ok(())
    }
}

// ── Validation Error ───────────────────────────────────────────

/// Errors that can occur when validating a ResourceAdvertisement.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceValidationError {
    /// agent_id field is empty.
    EmptyAgentId,
    /// cpu_offer is outside [0.0, 1.0].
    CpuOfferOutOfRange(f32),
    /// memory_offer_mb exceeds spec.total_memory_mb.
    MemoryOfferExceedsSpec { offered: u64, max: u64 },
    /// bandwidth_offer exceeds spec.max_bandwidth_up_mbps (converted to bytes/sec).
    BandwidthOfferExceedsSpec { offered: u64, max: u64 },
    /// storage_offer exceeds spec.total_storage_bytes.
    StorageOfferExceedsSpec { offered: u64, max: u64 },
    /// ResourceSpec contains invalid values.
    InvalidSpec { reason: String },
    /// Timestamp is too far in the future.
    FutureTimestamp,
    /// Sequence number is zero (should be bumped before sending).
    ZeroSequence,
}

impl std::fmt::Display for ResourceValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyAgentId => write!(f, "agent_id is empty"),
            Self::CpuOfferOutOfRange(v) => write!(f, "cpu_offer {v} out of range [0.0, 1.0]"),
            Self::MemoryOfferExceedsSpec { offered, max } => {
                write!(f, "memory_offer {offered}MB exceeds spec {max}MB")
            }
            Self::BandwidthOfferExceedsSpec { offered, max } => {
                write!(f, "bandwidth_offer {offered} B/s exceeds spec {max} B/s")
            }
            Self::StorageOfferExceedsSpec { offered, max } => {
                write!(f, "storage_offer {offered} exceeds spec {max}")
            }
            Self::InvalidSpec { reason } => write!(f, "invalid spec: {reason}"),
            Self::FutureTimestamp => write!(f, "timestamp is too far in the future"),
            Self::ZeroSequence => write!(f, "sequence must be > 0"),
        }
    }
}

impl std::error::Error for ResourceValidationError {}

/// A resource request from a consumer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceRequest {
    /// Unique request ID (UUID v4 format).
    #[serde(default)]
    pub request_id: String,

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

    /// Request expiry timestamp (ms since epoch). 0 = no expiry.
    #[serde(default)]
    pub expires_at: u64,
}

impl ResourceRequest {
    pub fn new(consumer_id: String) -> Self {
        Self {
            request_id: String::new(),
            consumer_id,
            min_cpu: 0.0,
            min_memory_mb: 0,
            min_bandwidth: 0,
            min_storage: 0,
            required_features: Vec::new(),
            duration_ms: 60_000,
            priority: 75,
            expires_at: 0,
        }
    }

    /// Check if this request has expired.
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        now_ms() > self.expires_at
    }
}

/// Reason for rejecting a resource offer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RejectReason {
    /// Consumer found a better offer from another provider.
    BetterOffer,
    /// Consumer no longer needs the resources.
    Cancelled,
    /// Offer terms are unacceptable (e.g. too few resources).
    Unsatisfactory,
    /// Offer has expired.
    Expired,
    /// Custom reason.
    Other(String),
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BetterOffer => write!(f, "better offer found"),
            Self::Cancelled => write!(f, "request cancelled"),
            Self::Unsatisfactory => write!(f, "unsatisfactory terms"),
            Self::Expired => write!(f, "offer expired"),
            Self::Other(s) => write!(f, "{s}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_ad() -> ResourceAdvertisement {
        ResourceAdvertisement {
            agent_id: "did:walkie:test".to_string(),
            sequence: 1,
            timestamp: now_ms(),
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 256 * 1024 * 1024 * 1024,
            },
            cpu_offer: 0.2,
            memory_offer_mb: 2048,
            bandwidth_offer: 5_000_000,
            storage_offer: 50 * 1024 * 1024 * 1024,
            features: vec!["always-on".to_string()],
            signature: Vec::new(),
        }
    }

    #[test]
    fn test_validate_valid_ad() {
        let ad = make_valid_ad();
        assert!(ad.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_agent_id() {
        let mut ad = make_valid_ad();
        ad.agent_id = String::new();
        assert_eq!(
            ad.validate().unwrap_err(),
            ResourceValidationError::EmptyAgentId
        );
    }

    #[test]
    fn test_validate_zero_sequence() {
        let mut ad = make_valid_ad();
        ad.sequence = 0;
        assert_eq!(
            ad.validate().unwrap_err(),
            ResourceValidationError::ZeroSequence
        );
    }

    #[test]
    fn test_validate_cpu_offer_negative() {
        let mut ad = make_valid_ad();
        ad.cpu_offer = -0.1;
        assert!(matches!(
            ad.validate().unwrap_err(),
            ResourceValidationError::CpuOfferOutOfRange(_)
        ));
    }

    #[test]
    fn test_validate_cpu_offer_over_one() {
        let mut ad = make_valid_ad();
        ad.cpu_offer = 1.5;
        assert!(matches!(
            ad.validate().unwrap_err(),
            ResourceValidationError::CpuOfferOutOfRange(_)
        ));
    }

    #[test]
    fn test_validate_memory_exceeds_spec() {
        let mut ad = make_valid_ad();
        ad.memory_offer_mb = 16_384; // 16GB > 8GB spec
        assert!(matches!(
            ad.validate().unwrap_err(),
            ResourceValidationError::MemoryOfferExceedsSpec { .. }
        ));
    }

    #[test]
    fn test_validate_bandwidth_exceeds_spec() {
        let mut ad = make_valid_ad();
        // spec: 100 Mbps = 12,500,000 B/s. Offer more than that.
        ad.bandwidth_offer = 20_000_000;
        assert!(matches!(
            ad.validate().unwrap_err(),
            ResourceValidationError::BandwidthOfferExceedsSpec { .. }
        ));
    }

    #[test]
    fn test_validate_storage_exceeds_spec() {
        let mut ad = make_valid_ad();
        ad.storage_offer = 1_000_000_000_000; // 1TB > 256GB spec
        assert!(matches!(
            ad.validate().unwrap_err(),
            ResourceValidationError::StorageOfferExceedsSpec { .. }
        ));
    }

    #[test]
    fn test_validate_zero_cpu_cores() {
        let mut ad = make_valid_ad();
        ad.spec.cpu_cores = 0;
        assert!(matches!(
            ad.validate().unwrap_err(),
            ResourceValidationError::InvalidSpec { .. }
        ));
    }

    #[test]
    fn test_validate_future_timestamp() {
        let mut ad = make_valid_ad();
        ad.timestamp = now_ms() + 600_000; // 10 minutes in future
        assert_eq!(
            ad.validate().unwrap_err(),
            ResourceValidationError::FutureTimestamp
        );
    }

    #[test]
    fn test_validate_boundary_cpu_offer() {
        let mut ad = make_valid_ad();
        ad.cpu_offer = 0.0;
        assert!(ad.validate().is_ok());

        ad.cpu_offer = 1.0;
        assert!(ad.validate().is_ok());
    }

    #[test]
    fn test_validate_boundary_memory_offer() {
        let mut ad = make_valid_ad();
        ad.memory_offer_mb = ad.spec.total_memory_mb; // exact match
        assert!(ad.validate().is_ok());
    }

    #[test]
    fn test_validate_timestamp_within_tolerance() {
        let mut ad = make_valid_ad();
        ad.timestamp = now_ms() + 60_000; // 1 minute in future — within 5-min tolerance
        assert!(ad.validate().is_ok());
    }

    #[test]
    fn test_validation_error_display() {
        assert!(!ResourceValidationError::EmptyAgentId.to_string().is_empty());
        assert!(!ResourceValidationError::CpuOfferOutOfRange(1.5).to_string().is_empty());
        assert!(!ResourceValidationError::FutureTimestamp.to_string().is_empty());
        assert!(!ResourceValidationError::ZeroSequence.to_string().is_empty());
        assert!(!ResourceValidationError::MemoryOfferExceedsSpec { offered: 100, max: 50 }
            .to_string()
            .is_empty());
    }
}
