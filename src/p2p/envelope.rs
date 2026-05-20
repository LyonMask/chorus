//! Wire protocol — Crypto Envelope.
//!
//! Serialized as JSON over Gossipsub (or, in the future, over
//! a dedicated request-response Direct channel).

/// Gossipsub topic for chorus messages.
pub const WT_TOPIC: &str = "/chorus/1.0.0";

/// Wire format for all encrypted traffic.
///
/// Serialized as JSON bytes and published to the Gossipsub topic.
/// Recipients who share an E2EE session with the sender can
/// decrypt the `Encrypted` variant; all others see opaque ciphertext.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CryptoEnvelope {
    /// Offer our X25519 public key to start a session.
    KeyOffer {
        public_key: Vec<u8>,
    },
    /// Accept a key offer + send our own public key.
    KeyAccept {
        public_key: Vec<u8>,
    },
    /// Encrypted payload (ChaCha20-Poly1305: nonce(12) || ct+tag).
    Encrypted {
        ciphertext: Vec<u8>,
    },
    /// Agent identity claim (sent over encrypted channel after session established).
    IdentityClaim {
        #[serde(with = "crate::identity::bytes_base64")]
        identity_json: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_envelope_serialization() {
        let offer = CryptoEnvelope::KeyOffer {
            public_key: vec![1u8; 32],
        };
        let bytes = serde_json::to_vec(&offer).unwrap();
        let decoded: CryptoEnvelope = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            CryptoEnvelope::KeyOffer { public_key } => assert_eq!(public_key.len(), 32),
            _ => panic!("wrong variant"),
        }

        let enc = CryptoEnvelope::Encrypted {
            ciphertext: vec![0u8; 28], // nonce(12) + tag(16)
        };
        let bytes = serde_json::to_vec(&enc).unwrap();
        let decoded: CryptoEnvelope = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            CryptoEnvelope::Encrypted { ciphertext } => assert_eq!(ciphertext.len(), 28),
            _ => panic!("wrong variant"),
        }
    }
}
