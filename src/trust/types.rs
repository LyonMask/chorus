//! Shared types for the trust layer.

use serde::{Deserialize, Serialize};

/// Trust level assigned to a peer after identity verification.
///
/// Progresses through levels as a node accumulates cryptographic
/// proof, guarantor backing, and community endorsements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum TrustLevel {
    /// Peer claimed a DID but provided no cryptographic proof.
    Unverified,
    /// DID ↔ PeerId verified via IdentityAttestation signature.
    Cryptographic,
    /// Backed by a guarantor's vouching.
    Guaranteed,
    /// Multiple peers independently vouch for this identity.
    CommunityVerified,
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unverified => write!(f, "Unverified"),
            Self::Cryptographic => write!(f, "Cryptographic"),
            Self::Guaranteed => write!(f, "Guaranteed"),
            Self::CommunityVerified => write!(f, "CommunityVerified"),
        }
    }
}

/// Errors emitted by trust-layer operations.
#[derive(Debug, Clone, PartialEq)]
pub enum TrustError {
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// Attestation has expired.
    Expired,
    /// Attestation was replayed (nonce already seen).
    Replayed,
    /// The DID in the attestation does not match the known identity.
    DidMismatch,
    /// The PeerId in the attestation does not match the connection.
    PeerIdMismatch,
    /// No public key on record for this DID.
    UnknownDid,
    /// The peer is not yet verified at the required level.
    InsufficientTrust,
    /// Not eligible to act as a guarantor.
    NotEligibleGuarantor,
    /// Already guaranteeing this node.
    AlreadyGuaranteed,
    /// Maximum number of guarantees reached.
    MaxGuaranteesReached,
    /// Guarantee certificate has expired.
    GuaranteeExpired,
    /// Invalid public key format.
    InvalidPublicKey,
    /// Generic trust-layer error.
    Other(String),
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::Expired => write!(f, "attestation expired"),
            Self::Replayed => write!(f, "replay detected"),
            Self::DidMismatch => write!(f, "DID mismatch"),
            Self::PeerIdMismatch => write!(f, "PeerId mismatch"),
            Self::UnknownDid => write!(f, "unknown DID"),
            Self::InsufficientTrust => write!(f, "insufficient trust level"),
            Self::NotEligibleGuarantor => write!(f, "not eligible to be guarantor"),
            Self::AlreadyGuaranteed => write!(f, "already guaranteeing this node"),
            Self::MaxGuaranteesReached => write!(f, "max guarantees reached"),
            Self::GuaranteeExpired => write!(f, "guarantee certificate expired"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for TrustError {}

/// Result of an endorsement cross-validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EndorsementResult {
    /// Provider's claimed usage is within tolerance of consumer's measurement.
    Honest,
    /// Minor discrepancy (10%–50%) — flag but don't slash.
    Suspicious { discrepancy_percent: f64 },
    /// Major discrepancy (>50%) — slash.
    Fraud { discrepancy_percent: f64 },
}

impl PartialEq for EndorsementResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Honest, Self::Honest) => true,
            (Self::Suspicious { discrepancy_percent: a }, Self::Suspicious { discrepancy_percent: b }) => {
                (a - b).abs() < f64::EPSILON
            }
            (Self::Fraud { discrepancy_percent: a }, Self::Fraud { discrepancy_percent: b }) => {
                (a - b).abs() < f64::EPSILON
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for EndorsementResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Honest => write!(f, "Honest"),
            Self::Suspicious { discrepancy_percent } => {
                write!(f, "Suspicious ({discrepancy_percent:.1}%)")
            }
            Self::Fraud { discrepancy_percent } => {
                write!(f, "Fraud ({discrepancy_percent:.1}%)")
            }
        }
    }
}

/// 10% tolerance for endorsement validation.
pub const MEASUREMENT_TOLERANCE_PERCENT: f64 = 10.0;

/// 5-minute TTL for identity attestations (replay defense).
pub const ATTESTATION_TTL_SECS: u64 = 300;

/// Wrapper for const access (allows future runtime override).
pub struct AttestationTtlSecs;
impl AttestationTtlSecs {
    pub const VALUE: u64 = ATTESTATION_TTL_SECS;
}

/// Composite trust score for a node.  Range 0.0–1.0.
///
/// Phase 4.1: weighted average of identity, endorsement, guarantor,
/// and slash components.  Phase 4.0 only uses `identity_score`.
#[derive(Debug, Clone, Default)]
pub struct TrustScore {
    pub identity_score: f64,
    pub endorsement_score: f64,
    pub guarantor_boost: f64,
    pub slash_penalty: f64,
    pub recency_weight: f64,
}

impl TrustScore {
    /// Weighted composite score: (identity×0.2 + endorsement×0.5 + guarantor×0.2) × slash_decay.
    /// Then multiplied by recency_weight and clamped to [0.0, 1.0].
    ///
    /// `slash_penalty` is a decay factor (1.0=no penalty, 0.0=max penalty).
    pub fn composite(&self) -> f64 {
        let base = self.identity_score * 0.2
            + self.endorsement_score * 0.5
            + self.guarantor_boost * 0.2;
        let raw = base * self.slash_penalty;
        (raw * self.recency_weight).clamp(0.0, 1.0)
    }

    /// Derive TrustLevel from composite score.
    pub fn level(&self) -> TrustLevel {
        match self.composite() {
            x if x >= 0.8 => TrustLevel::CommunityVerified,
            x if x >= 0.6 => TrustLevel::Guaranteed,
            x if x >= 0.3 => TrustLevel::Cryptographic,
            _ => TrustLevel::Unverified,
        }
    }

    /// Build a TrustScore from individual component scores.
    pub fn from_components(
        identity: f64,
        endorsement: f64,
        guarantor: f64,
        slash_penalty: f64,
        recency_weight: f64,
    ) -> Self {
        Self {
            identity_score: identity.clamp(0.0, 1.0),
            endorsement_score: endorsement.clamp(0.0, 1.0),
            guarantor_boost: guarantor.clamp(0.0, 1.0),
            slash_penalty: slash_penalty.clamp(0.0, 1.0),
            recency_weight: recency_weight.clamp(0.0, 1.0),
        }
    }

    /// CRP earnings multiplier based on TrustLevel.
    /// Unverified: 0.5×, Cryptographic: 1.0×, Guaranteed: 1.2×, CommunityVerified: 1.5×
    pub fn crp_multiplier(&self) -> f64 {
        match self.level() {
            TrustLevel::Unverified => 0.5,
            TrustLevel::Cryptographic => 1.0,
            TrustLevel::Guaranteed => 1.2,
            TrustLevel::CommunityVerified => 1.5,
        }
    }

    /// Resource match priority bonus based on TrustLevel.
    /// Unverified: 0%, Cryptographic: 0%, Guaranteed: 10%, CommunityVerified: 25%
    pub fn trust_bonus(&self) -> f64 {
        match self.level() {
            TrustLevel::Unverified => 0.0,
            TrustLevel::Cryptographic => 0.0,
            TrustLevel::Guaranteed => 0.10,
            TrustLevel::CommunityVerified => 0.25,
        }
    }
}
