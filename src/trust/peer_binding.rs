//! PeerId↔DID Cryptographic Binding — IdentityAttestation.
//!
//! When two nodes establish an E2EE session (Noise X25519), they exchange
//! [`IdentityAttestation`] messages over the Direct channel to prove that
//! their libp2p PeerId truly belongs to their claimed DID.
//!
//! # Flow
//!
//! ```text
//! 1. Node A ↔ Node B: Noise handshake + key exchange → E2EE session
//! 2. B → A: IdentityAttestation { did, peer_id, sig, ts, nonce }
//! 3. A verifies: signature + timestamp + nonce uniqueness
//! 4. A marks binding as TrustLevel::Cryptographic
//! 5. A → B: IdentityAttestation (A's attestation)
//! 6. B verifies → marks Cryptographic
//! 7. Bidirectional binding complete
//! ```

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::types::{AttestationTtlSecs, TrustError};

// ── IdentityAttestation ─────────────────────────────────────────

/// A signed proof that "this PeerId is controlled by this DID's signing key".
///
/// Signed with the identity's Ed25519 key.  Verified by the receiving peer
/// using the DID's known public key (from prior [`crate::identity::AgentIdentity`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityAttestation {
    /// The agent's DID (e.g. "did:walkie:abc123").
    pub did: String,
    /// The libp2p PeerId this agent claims to control (base58 string).
    pub peer_id: String,
    /// Ed25519 signature over `(did || ":" || peer_id || ":" || nonce)`,
    /// signed by the identity's Ed25519 signing key.
    #[serde(with = "crate::identity::bytes_base64")]
    pub signature: Vec<u8>,
    /// Unix timestamp (ms) — for replay defense.
    pub timestamp: u64,
    /// Random 16-byte nonce — unique per attestation to prevent replay.
    #[serde(with = "crate::identity::bytes_base64")]
    pub nonce: Vec<u8>,
}

impl IdentityAttestation {
    /// Expected nonce length in bytes.
    pub const NONCE_LEN: usize = 16;

    // ── Construction ──

    /// Create and sign a new attestation.
    pub fn sign(did: &str, peer_id: &str, signing_key: &ed25519_dalek::SigningKey) -> Self {
        let mut nonce = vec![0u8; Self::NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let payload = Self::payload_bytes(did, peer_id, &nonce);
        let signature = signing_key.sign(&payload);

        Self {
            did: did.to_string(),
            peer_id: peer_id.to_string(),
            signature: signature.to_bytes().to_vec(),
            timestamp: now_ms(),
            nonce,
        }
    }

    /// Create an unsigned attestation (for testing / forging).
    #[cfg(test)]
    pub fn unsigned(did: &str, peer_id: &str, timestamp: u64, nonce: Vec<u8>) -> Self {
        Self {
            did: did.to_string(),
            peer_id: peer_id.to_string(),
            signature: vec![0u8; 64],
            timestamp,
            nonce,
        }
    }

    // ── Verification ──

    /// Verify the attestation:
    /// 1. Signature is valid Ed25519 over the canonical payload.
    /// 2. Timestamp is within TTL.
    ///
    /// Returns `Ok(())` on success, `Err(TrustError)` otherwise.
    pub fn verify(&self, expected_pubkey: &[u8]) -> Result<(), TrustError> {
        // 1. Check timestamp
        let now = now_ms();
        let ttl_ms = AttestationTtlSecs::VALUE * 1000;
        if self.timestamp.saturating_add(ttl_ms) < now {
            return Err(TrustError::Expired);
        }
        // Allow 30s clock skew into the future
        if self.timestamp > now.saturating_add(30_000) {
            return Err(TrustError::Expired);
        }

        // 2. Parse public key
        let vk = VerifyingKey::from_bytes(
            expected_pubkey
                .try_into()
                .map_err(|_| TrustError::InvalidSignature)?,
        )
        .map_err(|_| TrustError::InvalidSignature)?;

        // 3. Verify signature
        let payload = Self::payload_bytes(&self.did, &self.peer_id, &self.nonce);
        let sig_bytes: [u8; 64] = self.signature.clone().try_into()
            .map_err(|_| TrustError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);

        vk.verify(&payload, &sig)
            .map_err(|_| TrustError::InvalidSignature)?;

        Ok(())
    }

    /// Verify the attestation and check that the DID and PeerId match
    /// expected values.
    pub fn verify_with_identity(
        &self,
        expected_did: &str,
        expected_peer_id: &str,
        expected_pubkey: &[u8],
    ) -> Result<(), TrustError> {
        if self.did != expected_did {
            return Err(TrustError::DidMismatch);
        }
        if self.peer_id != expected_peer_id {
            return Err(TrustError::PeerIdMismatch);
        }
        self.verify(expected_pubkey)
    }

    // ── Internal ──

    /// Canonical payload: `did:peer_id:nonce`
    fn payload_bytes(did: &str, peer_id: &str, nonce: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(did.len() + 1 + peer_id.len() + 1 + nonce.len());
        buf.extend_from_slice(did.as_bytes());
        buf.push(b':');
        buf.extend_from_slice(peer_id.as_bytes());
        buf.push(b':');
        buf.extend_from_slice(nonce);
        buf
    }
}

// ── NonceStore — replay defense ─────────────────────────────────

/// Tracks recently seen nonces to detect replay attacks.
///
/// Bounded to `max_entries` with automatic eviction of oldest entries.
pub struct NonceStore {
    entries: std::collections::HashSet<Vec<u8>>,
    max_entries: usize,
}

impl NonceStore {
    /// Create a new nonce store with a maximum entry count.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: std::collections::HashSet::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Check if a nonce has been seen before.  If not, record it.
    ///
    /// Returns `Ok(())` if the nonce is fresh, `Err(TrustError::Replayed)` if duplicate.
    pub fn check_and_insert(&mut self, nonce: &[u8]) -> Result<(), TrustError> {
        if self.entries.contains(nonce) {
            return Err(TrustError::Replayed);
        }
        // Evict oldest entries if at capacity (HashSet has no ordering,
        // so we drain and re-insert — adequate for bounded use).
        if self.entries.len() >= self.max_entries {
            // Simple eviction: clear half the entries
            let target = self.max_entries / 2;
            let mut count = 0;
            self.entries.retain(|_| {
                count += 1;
                count > target
            });
        }
        self.entries.insert(nonce.to_vec());
        Ok(())
    }
}

// ── Helper ──────────────────────────────────────────────────────

/// Current unix timestamp in milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Helper: generate a signing key and return (key, pubkey_bytes).
    fn new_keypair() -> (SigningKey, Vec<u8>) {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey = key.verifying_key().to_bytes().to_vec();
        (key, pubkey)
    }

    #[test]
    fn test_sign_and_verify_normal() {
        let (key, pubkey) = new_keypair();
        let att = IdentityAttestation::sign("did:walkie:alice", "12D3KooWAAAA", &key);

        assert_eq!(att.did, "did:walkie:alice");
        assert_eq!(att.peer_id, "12D3KooWAAAA");
        assert_eq!(att.nonce.len(), IdentityAttestation::NONCE_LEN);
        assert!(att.verify(&pubkey).is_ok());
    }

    #[test]
    fn test_sign_and_verify_with_identity() {
        let (key, pubkey) = new_keypair();
        let att = IdentityAttestation::sign("did:walkie:bob", "12D3KooWBBBB", &key);

        // Correct identity — passes
        assert!(att.verify_with_identity("did:walkie:bob", "12D3KooWBBBB", &pubkey).is_ok());

        // Wrong DID — fails
        assert_eq!(
            att.verify_with_identity("did:walkie:eve", "12D3KooWBBBB", &pubkey),
            Err(TrustError::DidMismatch),
        );

        // Wrong PeerId — fails
        assert_eq!(
            att.verify_with_identity("did:walkie:bob", "12D3KooWCCCC", &pubkey),
            Err(TrustError::PeerIdMismatch),
        );
    }

    #[test]
    fn test_forged_signature_fails() {
        let (key, pubkey) = new_keypair();
        let (wrong_key, _) = new_keypair();

        // Sign with wrong_key but verify with pubkey (from key)
        let mut att = IdentityAttestation::sign("did:walkie:eve", "12D3KooWDDDD", &wrong_key);
        // Replace signature with a correct-looking but wrong one
        let att_correct = IdentityAttestation::sign("did:walkie:eve", "12D3KooWDDDD", &key);
        att.signature = att_correct.signature.clone();

        // Should fail because the signature was generated for a different nonce/payload
        // Actually, since we copied the signature from a different attestation,
        // the payload will differ (different nonce). Let's test differently:
        let att = IdentityAttestation::sign("did:walkie:eve", "12D3KooWDDDD", &wrong_key);
        assert_eq!(att.verify(&pubkey), Err(TrustError::InvalidSignature));
    }

    #[test]
    fn test_wrong_pubkey_fails() {
        let (key, _pubkey) = new_keypair();
        let (_, wrong_pubkey) = new_keypair();

        let att = IdentityAttestation::sign("did:walkie:alice", "12D3KooWAAAA", &key);
        assert_eq!(att.verify(&wrong_pubkey), Err(TrustError::InvalidSignature));
    }

    #[test]
    fn test_expired_attestation_fails() {
        let (key, pubkey) = new_keypair();

        let mut att = IdentityAttestation::sign("did:walkie:alice", "12D3KooWAAAA", &key);
        // Set timestamp to 10 minutes ago (TTL is 5 min)
        att.timestamp = now_ms().saturating_sub(600_000);

        assert_eq!(att.verify(&pubkey), Err(TrustError::Expired));
    }

    #[test]
    fn test_future_timestamp_fails() {
        let (key, pubkey) = new_keypair();

        let mut att = IdentityAttestation::sign("did:walkie:alice", "12D3KooWAAAA", &key);
        // Set timestamp 60s into the future (clock skew allowed is 30s)
        att.timestamp = now_ms().saturating_add(60_000);

        assert_eq!(att.verify(&pubkey), Err(TrustError::Expired));
    }

    #[test]
    fn test_nonce_store_replay_detection() {
        let mut store = NonceStore::new(100);
        let nonce = vec![1u8; 16];

        // First time — OK
        assert!(store.check_and_insert(&nonce).is_ok());

        // Replay — detected
        assert_eq!(store.check_and_insert(&nonce), Err(TrustError::Replayed));
    }

    #[test]
    fn test_nonce_store_different_nonces_ok() {
        let mut store = NonceStore::new(100);

        let nonce1 = vec![1u8; 16];
        let nonce2 = vec![2u8; 16];
        let nonce3 = vec![3u8; 16];

        assert!(store.check_and_insert(&nonce1).is_ok());
        assert!(store.check_and_insert(&nonce2).is_ok());
        assert!(store.check_and_insert(&nonce3).is_ok());
    }

    #[test]
    fn test_nonce_store_eviction() {
        let mut store = NonceStore::new(4); // small for testing

        for i in 0u8..8 {
            let nonce = vec![i; 16];
            assert!(store.check_and_insert(&nonce).is_ok());
        }

        // After eviction, some old nonces should be gone
        // The exact eviction is non-deterministic (HashSet), but we
        // verify the store still works.
        let fresh_nonce = vec![99u8; 16];
        assert!(store.check_and_insert(&fresh_nonce).is_ok());
    }

    #[test]
    fn test_payload_bytes_deterministic() {
        let nonce = vec![0xAB; 16];
        let payload1 = IdentityAttestation::payload_bytes("did:a", "peer1", &nonce);
        let payload2 = IdentityAttestation::payload_bytes("did:a", "peer1", &nonce);
        assert_eq!(payload1, payload2);
    }

    #[test]
    fn test_payload_bytes_differs_for_different_inputs() {
        let nonce = vec![0u8; 16];
        let p1 = IdentityAttestation::payload_bytes("did:a", "peer1", &nonce);
        let p2 = IdentityAttestation::payload_bytes("did:b", "peer1", &nonce);
        let p3 = IdentityAttestation::payload_bytes("did:a", "peer2", &nonce);
        let p4 = IdentityAttestation::payload_bytes("did:a", "peer1", &[1u8; 16]);

        assert_ne!(p1, p2);
        assert_ne!(p1, p3);
        assert_ne!(p1, p4);
    }
    #[test]
    fn test_attestation_replay_same_nonce_rejected() {
        let seed = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);

        let att1 = IdentityAttestation::sign("did:walkie:test1", "12D3KooWP", &signing_key);
        let att2 = IdentityAttestation::sign("did:walkie:test1", "12D3KooWP", &signing_key);

        // Each sign() produces a unique random nonce
        assert_ne!(att1.nonce, att2.nonce);

        let mut store = NonceStore::new(100);
        assert!(store.check_and_insert(&att1.nonce).is_ok());
        assert!(store.check_and_insert(&att2.nonce).is_ok());

        // Replay of same nonce must be rejected
        assert_eq!(store.check_and_insert(&att1.nonce), Err(TrustError::Replayed));
        assert_eq!(store.check_and_insert(&att2.nonce), Err(TrustError::Replayed));
    }
}
