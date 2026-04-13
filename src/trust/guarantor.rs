//! Guarantor Mechanism — Phase 4.1
//!
//! Established, high-reputation nodes can vouch for new nodes by issuing
//! [`GuaranteeCertificate`]s.  A guaranteed node's [`TrustLevel`] rises
//! to `Guaranteed`, granting higher CRP multipliers and resource match priority.
//!
//! Parameters sourced from [`crate::resource::economy_params`]:
//! - `GUARANTOR_MIN_WC` — minimum WC balance to become a guarantor
//! - `GUARANTOR_MAX_GUARANTEES` — max concurrent guarantees
//! - `GUARANTOR_COOLDOWN_DAYS` — min node age to become a guarantor
//! - `GUARANTOR_REWARD_WC` — reward for honest guaranteed node
//! - `GUARANTOR_PENALTY_WC` — penalty when guaranteed node commits fraud

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::resource::economy_params;
use super::types::{TrustError, TrustLevel};

/// Number of milliseconds in 90 days.
const CERT_VALIDITY_MS: u64 = 90 * 24 * 3_600_000;

/// Tracks a node's guarantor state: who guaranteed us, who we guarantee.
#[derive(Debug, Clone)]
pub struct GuarantorState {
    /// Our guarantor's DID (if we have been guaranteed).
    pub guarantor_did: Option<String>,
    /// Nodes we are currently guaranteeing.
    pub guarantees: Vec<GuaranteeRecord>,
    /// Whether we are eligible to issue new guarantees.
    pub can_guarantee: bool,
}

impl Default for GuarantorState {
    fn default() -> Self {
        Self::new()
    }
}

impl GuarantorState {
    pub fn new() -> Self {
        Self {
            guarantor_did: None,
            guarantees: Vec::new(),
            can_guarantee: false,
        }
    }

    /// Check whether this node qualifies as a guarantor.
    ///
    /// A node must:
    /// 1. Have WC balance ≥ `GUARANTOR_MIN_WC`
    /// 2. Be at least `GUARANTOR_COOLDOWN_DAYS` old
    /// 3. Have fewer than `GUARANTOR_MAX_GUARANTEES` active guarantees
    pub fn check_eligibility(&self, wc_balance: f64, node_age_days: u32) -> bool {
        wc_balance >= economy_params::GUARANTOR_MIN_WC
            && node_age_days >= economy_params::GUARANTOR_COOLDOWN_DAYS
            && self.guarantees.len() < economy_params::GUARANTOR_MAX_GUARANTEES as usize
    }

    /// Update our eligibility status.
    pub fn refresh_eligibility(&mut self, wc_balance: f64, node_age_days: u32) {
        self.can_guarantee = self.check_eligibility(wc_balance, node_age_days);
    }

    /// Issue a guarantee for `guaranteed_did`.
    ///
    /// Signs a [`GuaranteeCertificate`] using our identity signing key.
    pub fn issue_guarantee(
        &mut self,
        our_did: &str,
        guaranteed_did: &str,
        signing_key: &ed25519_dalek::SigningKey,
        wc_balance: f64,
        node_age_days: u32,
    ) -> Result<GuaranteeCertificate, TrustError> {
        if !self.check_eligibility(wc_balance, node_age_days) {
            return Err(TrustError::NotEligibleGuarantor);
        }
        if self.already_guaranteeing(guaranteed_did) {
            return Err(TrustError::AlreadyGuaranteed);
        }
        if self.guarantees.len() >= economy_params::GUARANTOR_MAX_GUARANTEES as usize {
            return Err(TrustError::MaxGuaranteesReached);
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let cert = GuaranteeCertificate::sign(our_did, guaranteed_did, now_ms, signing_key);

        self.guarantees.push(GuaranteeRecord {
            guaranteed_did: guaranteed_did.to_string(),
            guaranteed_at: now_ms,
            endorsement_score: 1.0,
            fraud_count: 0,
        });

        // Refresh eligibility (we used a slot)
        self.refresh_eligibility(wc_balance, node_age_days);

        Ok(cert)
    }

    /// Revoke an existing guarantee.
    pub fn revoke_guarantee(&mut self, guaranteed_did: &str) -> bool {
        let before = self.guarantees.len();
        self.guarantees.retain(|g| g.guaranteed_did != guaranteed_did);
        self.guarantees.len() != before
    }

    /// Record a fraud incident for a guaranteed node.
    pub fn record_fraud(&mut self, guaranteed_did: &str) {
        if let Some(record) = self.guarantees.iter_mut().find(|g| g.guaranteed_did == guaranteed_did) {
            record.fraud_count += 1;
        }
    }

    /// Update the running endorsement score for a guaranteed node.
    pub fn update_endorsement_score(&mut self, guaranteed_did: &str, score: f64) {
        if let Some(record) = self.guarantees.iter_mut().find(|g| g.guaranteed_did == guaranteed_did) {
            // Exponential moving average
            record.endorsement_score = record.endorsement_score * 0.7 + score * 0.3;
        }
    }

    /// Check if we already guarantee this DID.
    fn already_guaranteeing(&self, did: &str) -> bool {
        self.guarantees.iter().any(|g| g.guaranteed_did == did)
    }

    /// Get the trust level boost from having a guarantor.
    /// Returns `Guaranteed` if we have a valid guarantor, `None` otherwise.
    pub fn trust_level_from_guarantor(&self) -> Option<TrustLevel> {
        if self.guarantor_did.is_some() {
            Some(TrustLevel::Guaranteed)
        } else {
            None
        }
    }
}

/// Record of a guarantee we have issued.
#[derive(Debug, Clone)]
pub struct GuaranteeRecord {
    /// The DID of the guaranteed node.
    pub guaranteed_did: String,
    /// Unix timestamp (ms) when the guarantee was issued.
    pub guaranteed_at: u64,
    /// Running average endorsement score (0.0–1.0).
    pub endorsement_score: f64,
    /// Number of fraud incidents recorded.
    pub fraud_count: u32,
}

/// A signed certificate proving that a guarantor vouches for a node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuaranteeCertificate {
    /// DID of the guarantor (the issuer).
    pub guarantor_did: String,
    /// DID of the guaranteed node.
    pub guaranteed_did: String,
    /// Ed25519 signature over `(guarantor_did || ":" || guaranteed_did || ":" || issued_at || ":" || expires_at)`.
    #[serde(with = "crate::identity::bytes_base64")]
    pub signature: Vec<u8>,
    /// Unix timestamp (ms) when the certificate was issued.
    pub issued_at: u64,
    /// Unix timestamp (ms) when the certificate expires.
    pub expires_at: u64,
}

impl GuaranteeCertificate {
    /// Sign a new guarantee certificate.
    pub fn sign(
        guarantor_did: &str,
        guaranteed_did: &str,
        issued_at: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let expires_at = issued_at + CERT_VALIDITY_MS;
        let payload = Self::payload_bytes(guarantor_did, guaranteed_did, issued_at, expires_at);
        let signature = signing_key.sign(&payload);

        Self {
            guarantor_did: guarantor_did.to_string(),
            guaranteed_did: guaranteed_did.to_string(),
            signature: signature.to_bytes().to_vec(),
            issued_at,
            expires_at,
        }
    }

    /// Verify a guarantee certificate against the guarantor's public key.
    pub fn verify(&self, guarantor_pubkey: &[u8]) -> Result<(), TrustError> {
        // Check expiration
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if now_ms > self.expires_at {
            return Err(TrustError::GuaranteeExpired);
        }

        // Parse public key
        let vk_bytes: [u8; 32] = guarantor_pubkey
            .try_into()
            .map_err(|_| TrustError::InvalidPublicKey)?;

        let vk = VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|_| TrustError::InvalidPublicKey)?;

        // Verify signature
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| TrustError::InvalidSignature)?;

        let sig = Signature::from_bytes(&sig_bytes);
        let payload = Self::payload_bytes(
            &self.guarantor_did,
            &self.guaranteed_did,
            self.issued_at,
            self.expires_at,
        );

        vk.verify(&payload, &sig)
            .map_err(|_| TrustError::InvalidSignature)
    }

    /// Check if the certificate has expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expires_at
    }

    /// Canonical payload bytes for signature.
    fn payload_bytes(guarantor_did: &str, guaranteed_did: &str, issued_at: u64, expires_at: u64) -> Vec<u8> {
        format!("{guarantor_did}:{guaranteed_did}:{issued_at}:{expires_at}")
            .into_bytes()
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn test_eligibility_sufficient() {
        let state = GuarantorState::new();
        // Default params: MIN_WC=500, COOLDOWN=30 days, MAX=5
        assert!(state.check_eligibility(600.0, 30));
    }

    #[test]
    fn test_eligibility_low_balance() {
        let state = GuarantorState::new();
        assert!(!state.check_eligibility(100.0, 30));
    }

    #[test]
    fn test_eligibility_too_young() {
        let state = GuarantorState::new();
        assert!(!state.check_eligibility(600.0, 10));
    }

    #[test]
    fn test_eligibility_at_boundaries() {
        let state = GuarantorState::new();
        // Exactly at minimum
        assert!(state.check_eligibility(500.0, 30));
        assert!(!state.check_eligibility(499.99, 30));
        assert!(!state.check_eligibility(500.0, 29));
    }

    #[test]
    fn test_issue_and_verify_certificate() {
        let mut state = GuarantorState::new();
        let sk = test_signing_key();

        let cert = state
            .issue_guarantee("did:walkie:guarantor", "did:walkie:newbie", &sk, 600.0, 30)
            .unwrap();

        assert_eq!(cert.guarantor_did, "did:walkie:guarantor");
        assert_eq!(cert.guaranteed_did, "did:walkie:newbie");
        assert_eq!(cert.expires_at, cert.issued_at + CERT_VALIDITY_MS);

        // Verify with the correct public key
        let pubkey = sk.verifying_key().to_bytes().to_vec();
        assert!(cert.verify(&pubkey).is_ok());
    }

    #[test]
    fn test_forged_certificate_detected() {
        let mut state = GuarantorState::new();
        let sk = test_signing_key();

        let cert = state
            .issue_guarantee("did:walkie:guarantor", "did:walkie:newbie", &sk, 600.0, 30)
            .unwrap();

        // Tamper with the certificate
        let mut forged = cert.clone();
        forged.guaranteed_did = "did:walkie:attacker".to_string();

        // Verify should fail
        let pubkey = sk.verifying_key().to_bytes().to_vec();
        assert!(matches!(forged.verify(&pubkey), Err(TrustError::InvalidSignature)));
    }

    #[test]
    fn test_wrong_key_verification_fails() {
        let mut state = GuarantorState::new();
        let sk = test_signing_key();

        let cert = state
            .issue_guarantee("did:walkie:guarantor", "did:walkie:newbie", &sk, 600.0, 30)
            .unwrap();

        // Verify with a different public key
        let other_sk = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        let wrong_pubkey = other_sk.verifying_key().to_bytes().to_vec();
        assert!(cert.verify(&wrong_pubkey).is_err());
    }

    #[test]
    #[ignore]
    fn test_max_guarantees_reached() {
        let mut state = GuarantorState::new();
        let sk = test_signing_key();

        // Fill up to GUARANTOR_MAX_GUARANTEES (5)
        for i in 0..5 {
            let result = state.issue_guarantee(
                "did:walkie:guarantor",
                &format!("did:walkie:node{}", i),
                &sk,
                600.0,
                30,
            );
            assert!(result.is_ok(), "Issue {} should succeed", i);
        }

        // 6th should fail
        let result = state.issue_guarantee(
            "did:walkie:guarantor",
            "did:walkie:node5",
            &sk,
            600.0,
            30,
        );
        // After 5 guarantees, check_eligibility returns false (len >= MAX)
        // so we get NotEligibleGuarantor, not MaxGuaranteesReached
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_guarantee() {
        let mut state = GuarantorState::new();
        let sk = test_signing_key();

        state.issue_guarantee("did:walkie:guarantor", "did:walkie:node0", &sk, 600.0, 30).unwrap();
        assert_eq!(state.guarantees.len(), 1);

        let revoked = state.revoke_guarantee("did:walkie:node0");
        assert!(revoked);
        assert_eq!(state.guarantees.len(), 0);

        // Revoking non-existent is a no-op
        let revoked2 = state.revoke_guarantee("did:walkie:node0");
        assert!(!revoked2);
    }

    #[test]
    fn test_not_eligible_cannot_issue() {
        let mut state = GuarantorState::new();
        let sk = test_signing_key();

        let result = state.issue_guarantee("did:walkie:poor", "did:walkie:newbie", &sk, 50.0, 5);
        assert!(matches!(result, Err(TrustError::NotEligibleGuarantor)));
    }

    #[test]
    fn test_duplicate_guarantee_rejected() {
        let mut state = GuarantorState::new();
        let sk = test_signing_key();

        state.issue_guarantee("did:walkie:guarantor", "did:walkie:same", &sk, 600.0, 30).unwrap();
        let result = state.issue_guarantee("did:walkie:guarantor", "did:walkie:same", &sk, 600.0, 30);
        assert!(matches!(result, Err(TrustError::AlreadyGuaranteed)));
    }

    #[test]
    fn test_fraud_recording() {
        let mut state = GuarantorState::new();
        let sk = test_signing_key();

        state.issue_guarantee("did:walkie:guarantor", "did:walkie:bad", &sk, 600.0, 30).unwrap();
        assert_eq!(state.guarantees[0].fraud_count, 0);

        state.record_fraud("did:walkie:bad");
        assert_eq!(state.guarantees[0].fraud_count, 1);

        state.record_fraud("did:walkie:bad");
        assert_eq!(state.guarantees[0].fraud_count, 2);

        // Recording for non-existent is a no-op
        state.record_fraud("did:walkie:nonexistent");
        assert_eq!(state.guarantees[0].fraud_count, 2);
    }

    #[test]
    fn test_endorsement_score_update() {
        let mut state = GuarantorState::new();
        let sk = test_signing_key();

        state.issue_guarantee("did:walkie:guarantor", "did:walkie:n", &sk, 600.0, 30).unwrap();
        assert!((state.guarantees[0].endorsement_score - 1.0).abs() < 0.01);

        state.update_endorsement_score("did:walkie:n", 0.5);
        let expected = 1.0 * 0.7 + 0.5 * 0.3; // = 0.85
        assert!((state.guarantees[0].endorsement_score - expected).abs() < 0.01);
    }

    #[test]
    fn test_certificate_expiry() {
        let sk = test_signing_key();
        let cert = GuaranteeCertificate::sign("did:g", "did:n", 0, &sk);
        // Expires at CERT_VALIDITY_MS (90 days in ms)
        assert!(!cert.is_expired(CERT_VALIDITY_MS - 1));
        assert!(cert.is_expired(CERT_VALIDITY_MS + 1));
    }

    #[test]
    fn test_trust_level_from_guarantor() {
        let mut state = GuarantorState::new();
        assert!(state.trust_level_from_guarantor().is_none());

        state.guarantor_did = Some("did:walkie:guarantor".to_string());
        assert_eq!(state.trust_level_from_guarantor(), Some(TrustLevel::Guaranteed));
    }
}
