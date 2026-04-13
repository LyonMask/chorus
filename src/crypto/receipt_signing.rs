//! Dual-signed receipt logic — Walkie Talkie Phase 4.
//!
//! WorkReceipt (and future BandwidthReceipt) require dual signatures:
//!   1. Provider signs → proves they generated the receipt
//!   2. Consumer countersigns → endorses the provider's claims
//!
//! A fully-signed receipt is required for CRP calculation and
//! fraud detection (endorsement system).

use ed25519_dalek::{Signer, Verifier, VerifyingKey, Signature};
use crate::resource::WorkReceipt;

/// Sign a WorkReceipt with the provider's Ed25519 signing key.
///
/// The signature covers all fields except `provider_signature` itself.
/// After signing, `provider_signature` is populated (64 bytes).
pub fn sign_work_receipt(
    receipt: &mut WorkReceipt,
    signing_key: &ed25519_dalek::SigningKey,
) {
    let payload = receipt_provider_payload(receipt);
    let signature = signing_key.sign(&payload);
    receipt.provider_signature = signature.to_bytes().to_vec();
}

/// Verify the provider's Ed25519 signature on a WorkReceipt.
///
/// Returns `true` if the signature is valid for the given public key.
pub fn verify_provider_signature(
    receipt: &WorkReceipt,
    provider_pubkey: &[u8],
) -> bool {
    verify_ed25519(&receipt.provider_signature, &receipt_provider_payload(receipt), provider_pubkey)
}

/// Consumer countersigns a WorkReceipt after verifying provider's claim.
///
/// The signature covers all fields except both signatures.
/// Error returned when countersign preconditions are not met.
#[derive(Debug, Clone, PartialEq)]
pub enum CountersignError {
    /// Provider has not signed the receipt yet.
    ProviderNotSigned,
    /// Provider signature is malformed (not 64 bytes).
    MalformedProviderSignature,
}

impl std::fmt::Display for CountersignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProviderNotSigned => write!(f, "provider has not signed this receipt"),
            Self::MalformedProviderSignature => write!(f, "provider signature is malformed"),
        }
    }
}

impl std::error::Error for CountersignError {}

/// Check that a WorkReceipt has a valid provider signature before countersigning.
///
/// Returns `Err` if the receipt is unsigned or the provider signature is malformed.
/// Use this before calling `countersign_work_receipt` to enforce dual-sign protocol.
pub fn require_provider_signed(receipt: &WorkReceipt) -> Result<(), CountersignError> {
    if receipt.provider_signature.is_empty() {
        return Err(CountersignError::ProviderNotSigned);
    }
    if receipt.provider_signature.len() != 64 {
        return Err(CountersignError::MalformedProviderSignature);
    }
    Ok(())
}

pub fn countersign_work_receipt(
    receipt: &mut WorkReceipt,
    consumer_signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), CountersignError> {
    require_provider_signed(receipt)?;
    let payload = receipt_full_payload(receipt);
    let signature = consumer_signing_key.sign(&payload);
    receipt.consumer_signature = signature.to_bytes().to_vec();
    Ok(())
}

/// Verify the consumer's countersignature on a WorkReceipt.
///
/// Returns `true` if the countersignature is valid for the given public key.
pub fn verify_consumer_signature(
    receipt: &WorkReceipt,
    consumer_pubkey: &[u8],
) -> bool {
    verify_ed25519(
        &receipt.consumer_signature,
        &receipt_full_payload(receipt),
        consumer_pubkey,
    )
}

/// Check if a receipt has been dual-signed by both parties.
pub fn is_fully_signed(receipt: &WorkReceipt) -> bool {
    !receipt.provider_signature.is_empty()
        && !receipt.consumer_signature.is_empty()
        && receipt.provider_signature.len() == 64
        && receipt.consumer_signature.len() == 64
}

/// Check if a receipt is completely unsigned (Phase 2 backward compat).
pub fn is_unverified(receipt: &WorkReceipt) -> bool {
    receipt.provider_signature.is_empty() && receipt.consumer_signature.is_empty()
}

/// Serialize the signable payload for the provider's signature.
///
/// Excludes `provider_signature` and `consumer_signature`.
fn receipt_provider_payload(receipt: &WorkReceipt) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        receipt.consumer,
        receipt.provider,
        receipt.session_id,
        receipt.cpu_used_ms,
        receipt.memory_peak_bytes,
        receipt.duration_ms,
        receipt.window_start,
        receipt.window_end,
        receipt.proof_hash(),
    )
    .into_bytes()
}

/// Serialize the full signable payload for the consumer's countersignature.
///
/// Includes all fields except both signatures.
fn receipt_full_payload(receipt: &WorkReceipt) -> Vec<u8> {
    // Consumer signs over provider_payload + provider_signature
    let mut data = receipt_provider_payload(receipt);
    data.push(b':');
    data.extend_from_slice(hex_encode(&receipt.provider_signature).as_bytes());
    data
}

/// Generic Ed25519 verification helper.
fn verify_ed25519(signature: &[u8], payload: &[u8], pubkey: &[u8]) -> bool {
    if signature.len() != 64 || pubkey.len() != 32 {
        return false;
    }

    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let pubkey_bytes: [u8; 32] = match pubkey.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let sig = Signature::from_bytes(&sig_bytes);

    let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    verifying_key.verify(payload, &sig).is_ok()
}

/// Encode bytes as lowercase hex string.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_test_receipt() -> WorkReceipt {
        WorkReceipt::new(
            "did:walkie:consumer".into(),
            "did:walkie:provider".into(),
            "session-42".into(),
            5000,
            1024 * 1024,
            10_000,
        )
    }

    fn generate_keypair() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        (sk, pk)
    }

    #[test]
    fn test_provider_sign_and_verify() {
        let (provider_sk, provider_pk) = generate_keypair();
        let mut receipt = make_test_receipt();

        sign_work_receipt(&mut receipt, &provider_sk);
        assert_eq!(receipt.provider_signature.len(), 64);

        assert!(verify_provider_signature(&receipt, &provider_pk));
    }

    #[test]
    fn test_consumer_countersign_and_verify() {
        let (provider_sk, provider_pk) = generate_keypair();
        let (consumer_sk, consumer_pk) = generate_keypair();
        let mut receipt = make_test_receipt();

        // Provider signs first
        sign_work_receipt(&mut receipt, &provider_sk);
        assert!(verify_provider_signature(&receipt, &provider_pk));

        // Consumer countersigns
        countersign_work_receipt(&mut receipt, &consumer_sk).unwrap();
        assert_eq!(receipt.consumer_signature.len(), 64);
        assert!(verify_consumer_signature(&receipt, &consumer_pk));
    }

    #[test]
    fn test_fully_signed() {
        let (provider_sk, _) = generate_keypair();
        let (consumer_sk, _) = generate_keypair();
        let mut receipt = make_test_receipt();

        assert!(!is_fully_signed(&receipt));
        assert!(is_unverified(&receipt));

        sign_work_receipt(&mut receipt, &provider_sk);
        assert!(!is_fully_signed(&receipt));
        assert!(!is_unverified(&receipt));

        countersign_work_receipt(&mut receipt, &consumer_sk).unwrap();
        assert!(is_fully_signed(&receipt));
    }

    #[test]
    fn test_tampered_receipt_fails() {
        let (provider_sk, provider_pk) = generate_keypair();
        let mut receipt = make_test_receipt();

        sign_work_receipt(&mut receipt, &provider_sk);
        assert!(verify_provider_signature(&receipt, &provider_pk));

        // Tamper with cpu_used_ms
        receipt.cpu_used_ms = 999_999;
        assert!(!verify_provider_signature(&receipt, &provider_pk));
    }

    #[test]
    fn test_wrong_key_fails() {
        let (provider_sk, _) = generate_keypair();
        let (_, wrong_pk) = generate_keypair();
        let mut receipt = make_test_receipt();

        sign_work_receipt(&mut receipt, &provider_sk);
        assert!(!verify_provider_signature(&receipt, &wrong_pk));
    }

    #[test]
    fn test_empty_signature_fails() {
        let receipt = make_test_receipt();
        let pubkey = vec![0u8; 32];
        assert!(!verify_provider_signature(&receipt, &pubkey));
        assert!(!verify_consumer_signature(&receipt, &pubkey));
    }

    #[test]
    fn test_wrong_length_signature_fails() {
        let receipt = make_test_receipt();
        let pubkey = vec![0u8; 32];
        // Create a receipt with wrong-length signature
        let mut receipt = receipt;
        receipt.provider_signature = vec![1u8; 32]; // 32 instead of 64
        assert!(!verify_provider_signature(&receipt, &pubkey));
        assert!(!is_fully_signed(&receipt));
    }

    #[test]
    fn test_wrong_length_pubkey_fails() {
        let (provider_sk, _) = generate_keypair();
        let mut receipt = make_test_receipt();
        sign_work_receipt(&mut receipt, &provider_sk);

        let bad_pubkey = vec![0u8; 16];
        assert!(!verify_provider_signature(&receipt, &bad_pubkey));
    }

    #[test]
    fn test_unverified_receipt() {
        let receipt = make_test_receipt();
        assert!(is_unverified(&receipt));
        assert!(!is_fully_signed(&receipt));
    }

    #[test]
    fn test_countersign_unsigned_receipt_rejected() {
        let (consumer_sk, _) = generate_keypair();
        let mut receipt = make_test_receipt();
        // Provider has NOT signed — countersign should fail
        let result = countersign_work_receipt(&mut receipt, &consumer_sk);
        assert_eq!(result, Err(CountersignError::ProviderNotSigned));
    }

    #[test]
    fn test_require_provider_signed_malformed() {
        let receipt = {
            let mut r = make_test_receipt();
            r.provider_signature = vec![1u8; 32]; // wrong length
            r
        };
        assert_eq!(require_provider_signed(&receipt), Err(CountersignError::MalformedProviderSignature));
    }

    #[test]
    fn test_countersign_tampered_provider_sig_fails() {
        let (provider_sk, provider_pk) = generate_keypair();
        let (consumer_sk, consumer_pk) = generate_keypair();
        let mut receipt = make_test_receipt();

        sign_work_receipt(&mut receipt, &provider_sk);
        countersign_work_receipt(&mut receipt, &consumer_sk).unwrap();

        // Both sigs should be valid before tampering
        assert!(verify_provider_signature(&receipt, &provider_pk));
        assert!(verify_consumer_signature(&receipt, &consumer_pk));

        // Tamper with provider signature — both sigs break because
        // consumer sig covers provider sig hash
        receipt.provider_signature[0] ^= 0xFF;
        assert!(!verify_provider_signature(&receipt, &provider_pk));
        assert!(!verify_consumer_signature(&receipt, &consumer_pk));
    }

}
