//! Agent Identity Protocol — Walkie Talkie v4
//!
//! Each Agent has a cryptographically-verifiable identity:
//!   - **agent_id**: `did:walkie:<ed25519-pubkey-base64url>` — globally unique
//!   - **signing keypair**: Ed25519 — signs identity claims + messages
//!   - **capabilities**: declared abilities (e.g. "code-review", "translate")
//!
//! Wire exchange happens via a dedicated Gossipsub topic
//! (`/walkie-talkie/identity/1.0.0`) after the E2EE session is established.

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use thiserror::Error;

// ─── DID Format ──────────────────────────────────────────────────

/// DID method prefix for Walkie Talkie agents.
pub const DID_PREFIX: &str = "did:walkie";

/// Identity exchange Gossipsub topic.
pub const IDENTITY_TOPIC: &str = "/walkie-talkie/identity/1.0.0";

/// Convert a raw Ed25519 public key (32 bytes) to a did:walkie string.
pub fn did_from_pubkey(pubkey_bytes: &[u8]) -> String {
    let encoded = base64_url_encode(pubkey_bytes);
    format!("{DID_PREFIX}:{encoded}")
}

/// Extract the raw public key bytes from a did:walkie string.
/// Returns None if the format is invalid.
pub fn pubkey_from_did(did: &str) -> Option<Vec<u8>> {
    let rest = did.strip_prefix(DID_PREFIX)?.strip_prefix(':')?;
    base64_url_decode_inner(rest).ok()
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode_inner(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data)
}

// ─── Agent Identity ─────────────────────────────────────────────

/// Cryptographic identity for an AI Agent.
///
/// Serialized as JSON for wire exchange. The `signature` field is an
/// Ed25519 signature over the canonical JSON of all other fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Globally unique identifier: `did:walkie:<base64url-pubkey>`
    pub agent_id: String,

    /// Human-readable name (e.g. "Rustacean", "CodeReview Bot")
    pub display_name: String,

    /// Declared capabilities (e.g. ["code-review", "p2p-routing", "translate"])
    pub capabilities: Vec<String>,

    /// Ed25519 public key (raw 32 bytes, used for verification)
    #[serde(with = "bytes_base64")]
    pub public_key: Vec<u8>,

    /// DID of the human/organization that created this Agent
    pub owner_id: String,

    /// Software version string (e.g. "walkie-talkie-core/0.2.0")
    pub version: String,

    /// Unix timestamp (ms) when this identity was created
    pub created_at: u64,

    /// Ed25519 signature over all other fields (base64url)
    #[serde(with = "bytes_base64")]
    pub signature: Vec<u8>,
}

pub mod bytes_base64 {
    use base64::Engine;
    use serde::{self, Deserialize, Serializer, Deserializer};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
        s.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Invalid DID format: {0}")]
    InvalidDID(String),
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("Public key does not match agent_id")]
    PublicKeyMismatch,
    #[error("Serialization failed: {0}")]
    Serialization(String),
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Identity expired (created_at={created_at})")]
    Expired { created_at: u64 },
    #[error("Missing required field: {0}")]
    MissingField(String),
}

pub type Result<T> = std::result::Result<T, IdentityError>;

impl AgentIdentity {
    /// The data that gets signed (everything except `signature`).
    fn signing_payload(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Payload<'a> {
            agent_id: &'a str,
            display_name: &'a str,
            capabilities: &'a [String],
            public_key: &'a [u8],
            owner_id: &'a str,
            version: &'a str,
            created_at: u64,
        }
        let payload = Payload {
            agent_id: &self.agent_id,
            display_name: &self.display_name,
            capabilities: &self.capabilities,
            public_key: &self.public_key,
            owner_id: &self.owner_id,
            version: &self.version,
            created_at: self.created_at,
        };
        serde_json::to_vec(&payload)
            .map_err(|e| IdentityError::Serialization(e.to_string()))
    }

    /// Verify that the identity is self-signed and the public key matches the agent_id.
    pub fn verify(&self) -> Result<()> {
        // 1. Check agent_id matches public_key
        let expected_did = did_from_pubkey(&self.public_key);
        if expected_did != self.agent_id {
            return Err(IdentityError::PublicKeyMismatch);
        }

        // 2. Reconstruct the signing payload
        let payload = self.signing_payload()?;

        // 3. Verify Ed25519 signature
        let pubkey_bytes: [u8; 32] = self.public_key.clone().try_into()
            .map_err(|_| IdentityError::InvalidDID("public_key must be 32 bytes".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| IdentityError::InvalidDID("invalid Ed25519 public key".into()))?;

        let signature_bytes: [u8; 64] = self.signature.clone().try_into()
            .map_err(|_| IdentityError::InvalidSignature)?;

        let signature = Signature::from_bytes(&signature_bytes);

        verifying_key.verify(&payload, &signature)
            .map_err(|_| IdentityError::InvalidSignature)?;

        Ok(())
    }

    /// Check if this agent declares a specific capability.
    pub fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c.eq_ignore_ascii_case(cap))
    }

    /// A short display string for logging.
    pub fn short_id(&self) -> String {
        self.agent_id.chars().take(24).collect()
    }
}

// ─── Identity Builder ───────────────────────────────────────────

/// Creates and signs AgentIdentity documents.
pub struct IdentityBuilder {
    display_name: String,
    capabilities: Vec<String>,
    owner_id: String,
    version: String,
}

impl IdentityBuilder {
    pub fn new(display_name: &str) -> Self {
        Self {
            display_name: display_name.to_string(),
            capabilities: Vec::new(),
            owner_id: String::new(),
            version: "walkie-talkie-core/0.2.0".to_string(),
        }
    }

    pub fn capability(mut self, cap: &str) -> Self {
        self.capabilities.push(cap.to_string());
        self
    }

    pub fn capabilities(mut self, caps: &[&str]) -> Self {
        self.capabilities.extend(caps.iter().map(|s| s.to_string()));
        self
    }

    pub fn owner_id(mut self, id: &str) -> Self {
        self.owner_id = id.to_string();
        self
    }

    pub fn version(mut self, v: &str) -> Self {
        self.version = v.to_string();
        self
    }

    /// Generate a new Ed25519 keypair and sign the identity document.
    /// Returns the signed identity and the signing key (keep secret!).
    pub fn build(self) -> Result<(AgentIdentity, SigningKey)> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();

        let agent_id = did_from_pubkey(&pubkey_bytes);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let identity = AgentIdentity {
            agent_id,
            display_name: self.display_name,
            capabilities: self.capabilities,
            public_key: pubkey_bytes.to_vec(),
            owner_id: self.owner_id,
            version: self.version,
            created_at,
            signature: Vec::new(), // placeholder, filled below
        };

        let payload = identity.signing_payload()?;
        let signature = signing_key.sign(&payload);

        let signed = AgentIdentity {
            signature: signature.to_bytes().to_vec(),
            ..identity
        };

        Ok((signed, signing_key))
    }

    /// Build with a pre-existing signing key (for deterministic testing).
    #[cfg(test)]
    pub fn build_with_key(self, signing_key: &SigningKey) -> Result<AgentIdentity> {
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();

        let agent_id = did_from_pubkey(&pubkey_bytes);
        let created_at = 1700000000000u64; // deterministic for tests

        let identity = AgentIdentity {
            agent_id,
            display_name: self.display_name,
            capabilities: self.capabilities,
            public_key: pubkey_bytes.to_vec(),
            owner_id: self.owner_id,
            version: self.version,
            created_at,
            signature: Vec::new(),
        };

        let payload = identity.signing_payload()?;
        let signature = signing_key.sign(&payload);

        let signed = AgentIdentity {
            signature: signature.to_bytes().to_vec(),
            ..identity
        };

        Ok(signed)
    }
}

// ─── Identity Document for Wire Exchange ────────────────────────

/// Wrapper for exchanging identities over Gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEnvelope {
    /// The signed agent identity.
    pub identity: AgentIdentity,
    /// PeerId of the sender (for routing).
    pub peer_id: String,
}

impl IdentityEnvelope {
    /// Create a new envelope with the given identity and peer_id.
    pub fn new(identity: AgentIdentity, peer_id: &str) -> Self {
        Self {
            identity,
            peer_id: peer_id.to_string(),
        }
    }

    /// Verify the contained identity.
    pub fn verify(&self) -> Result<()> {
        self.identity.verify()
    }
}

// ─── Resource Advertisement Signing ────────────────────

/// Sign a [`ResourceAdvertisement`](crate::resource::ResourceAdvertisement)
/// with the given Ed25519 signing key.
///
/// Populates `signing_pubkey` (the verifier's public key, 32 bytes) and
/// `signature` (64 bytes) on the advertisement in place and returns the
/// signed clone.
pub fn sign_advertisement(
    ad: &mut crate::resource::ResourceAdvertisement,
    signing_key: &SigningKey,
) {
    let pubkey_bytes = signing_key.verifying_key().to_bytes().to_vec();
    ad.signing_pubkey = pubkey_bytes.clone();
    ad.signature.clear();

    let payload = ad.signable_bytes();
    let signature = signing_key.sign(&payload);
    ad.signature = signature.to_bytes().to_vec();
}

/// Verify the Ed25519 signature on a
/// [`ResourceAdvertisement`](crate::resource::ResourceAdvertisement).
///
/// Delegates to [`ResourceAdvertisement::verify_signature()`].
pub fn verify_advertisement(
    ad: &crate::resource::ResourceAdvertisement,
) -> std::result::Result<(), crate::resource::ResourceValidationError> {
    ad.verify_signature()
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DID format ──

    #[test]
    fn test_did_roundtrip() {
        let pubkey = [0xABu8; 32];
        let did = did_from_pubkey(&pubkey);
        assert!(did.starts_with("did:walkie:"));
        assert_eq!(did.len(), 11 + 43); // prefix + base64url(32 bytes) ≈ 43

        let recovered = pubkey_from_did(&did).unwrap();
        assert_eq!(recovered, pubkey.to_vec());
    }

    #[test]
    fn test_pubkey_from_invalid_did() {
        assert!(pubkey_from_did("not-a-did").is_none());
        assert!(pubkey_from_did("did:walkie:!!!invalid-base64").is_none());
        assert!(pubkey_from_did("did:other:abc").is_none());
    }

    // ── Identity creation & verification ──

    #[test]
    fn test_create_and_verify_identity() {
        let (identity, _signing_key) = IdentityBuilder::new("Rustacean")
            .capabilities(&["p2p-routing", "crypto"])
            .owner_id("did:walkie:owner123")
            .version("0.2.0")
            .build()
            .unwrap();

        assert!(identity.agent_id.starts_with("did:walkie:"));
        assert_eq!(identity.display_name, "Rustacean");
        assert_eq!(identity.capabilities, vec!["p2p-routing", "crypto"]);
        assert_eq!(identity.owner_id, "did:walkie:owner123");
        assert_eq!(identity.version, "0.2.0");
        assert_eq!(identity.public_key.len(), 32);
        assert_eq!(identity.signature.len(), 64);
        assert!(identity.created_at > 1700000000000);
        assert!(identity.verify().is_ok());
    }

    #[test]
    fn test_identity_has_capability() {
        let (identity, _) = IdentityBuilder::new("TestBot")
            .capabilities(&["translate", "summarize"])
            .build()
            .unwrap();

        assert!(identity.has_capability("translate"));
        assert!(identity.has_capability("TRANSLATE")); // case insensitive
        assert!(!identity.has_capability("code-review"));
    }

    #[test]
    fn test_deterministic_identity() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);

        let a = IdentityBuilder::new("Agent")
            .build_with_key(&signing_key)
            .unwrap();
        let b = IdentityBuilder::new("Agent")
            .build_with_key(&signing_key)
            .unwrap();

        assert_eq!(a.agent_id, b.agent_id);
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.created_at, b.created_at);
    }

    // ── Tamper detection ──

    #[test]
    fn test_tampered_display_name_fails() {
        let (mut identity, _) = IdentityBuilder::new("Honest")
            .build()
            .unwrap();

        identity.display_name = "Impostor".to_string();
        assert!(identity.verify().is_err());
    }

    #[test]
    fn test_tampered_capabilities_fails() {
        let (mut identity, _) = IdentityBuilder::new("Limited")
            .capabilities(&["read"])
            .build()
            .unwrap();

        identity.capabilities.push("admin".to_string());
        assert!(identity.verify().is_err());
    }

    #[test]
    fn test_tampered_public_key_fails() {
        let (mut identity, _) = IdentityBuilder::new("Agent")
            .build()
            .unwrap();

        identity.public_key[0] ^= 0xFF;
        assert!(matches!(
            identity.verify(),
            Err(IdentityError::PublicKeyMismatch)
        ));
    }

    #[test]
    fn test_tampered_signature_fails() {
        let (mut identity, _) = IdentityBuilder::new("Agent")
            .build()
            .unwrap();

        identity.signature[10] ^= 0xFF;
        assert!(matches!(
            identity.verify(),
            Err(IdentityError::InvalidSignature)
        ));
    }

    #[test]
    fn test_tampered_owner_fails() {
        let (mut identity, _) = IdentityBuilder::new("Agent")
            .owner_id("alice")
            .build()
            .unwrap();

        identity.owner_id = "eve".to_string();
        assert!(identity.verify().is_err());
    }

    // ── Serialization roundtrip ──

    #[test]
    fn test_identity_serialization_roundtrip() {
        let (identity, _) = IdentityBuilder::new("TestBot")
            .capabilities(&["code-review"])
            .owner_id("did:walkie:org")
            .build()
            .unwrap();

        let json = serde_json::to_vec(&identity).unwrap();
        let decoded: AgentIdentity = serde_json::from_slice(&json).unwrap();

        assert_eq!(decoded.agent_id, identity.agent_id);
        assert_eq!(decoded.display_name, identity.display_name);
        assert_eq!(decoded.capabilities, identity.capabilities);
        assert_eq!(decoded.public_key, identity.public_key);
        assert_eq!(decoded.owner_id, identity.owner_id);
        assert_eq!(decoded.version, identity.version);
        assert_eq!(decoded.signature, identity.signature);
        // Verify the deserialized identity is still valid
        assert!(decoded.verify().is_ok());
    }

    #[test]
    fn test_identity_envelope_roundtrip() {
        let (identity, _) = IdentityBuilder::new("Agent")
            .build()
            .unwrap();

        let envelope = IdentityEnvelope::new(identity, "12D3KooWTest");
        let json = serde_json::to_vec(&envelope).unwrap();
        let decoded: IdentityEnvelope = serde_json::from_slice(&json).unwrap();

        assert_eq!(decoded.peer_id, "12D3KooWTest");
        assert_eq!(decoded.identity.display_name, "Agent");
        assert!(decoded.verify().is_ok());
    }

    #[test]
    fn test_short_id() {
        let (identity, _) = IdentityBuilder::new("LongNameAgent")
            .build()
            .unwrap();
        let short = identity.short_id();
        assert_eq!(short.len(), 24);
        assert!(short.starts_with("did:walkie:"));
    }

    #[test]
    fn test_identity_without_owner() {
        let (identity, _) = IdentityBuilder::new("Standalone")
            .build()
            .unwrap();
        assert!(identity.owner_id.is_empty());
        assert!(identity.verify().is_ok());
    }

    // ── Additional boundary tests ──

    #[test]
    fn test_tampered_version_fails() {
        let (mut identity, _) = IdentityBuilder::new("Agent")
            .version("0.1.0")
            .build()
            .unwrap();
        identity.version = "0.99.0-tampered".to_string();
        assert!(matches!(identity.verify(), Err(IdentityError::InvalidSignature)));
    }

    #[test]
    fn test_tampered_created_at_fails() {
        let (mut identity, _) = IdentityBuilder::new("Agent")
            .build()
            .unwrap();
        identity.created_at = 9999999999999;
        assert!(matches!(identity.verify(), Err(IdentityError::InvalidSignature)));
    }

    #[test]
    fn test_empty_display_name_valid() {
        let seed = [77u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let identity = IdentityBuilder::new("")
            .build_with_key(&signing_key)
            .unwrap();
        assert!(identity.display_name.is_empty());
        assert!(identity.verify().is_ok());
    }

    #[test]
    fn test_did_empty_string() {
        assert!(pubkey_from_did("").is_none());
        // "did:walkie:" decodes to Some([]) (empty base64url = empty vec)
        let result = pubkey_from_did("did:walkie:");
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_short_pubkey_did() {
        // 16 bytes instead of 32 — should encode/decode fine but produce wrong DID
        let short = [0xABu8; 16];
        let did = did_from_pubkey(&short);
        assert!(did.starts_with("did:walkie:"));
        let recovered = pubkey_from_did(&did).unwrap();
        assert_eq!(recovered.len(), 16);
    }

    #[test]
    fn test_empty_capabilities_list() {
        let seed = [88u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let identity = IdentityBuilder::new("Agent")
            .build_with_key(&signing_key)
            .unwrap();
        assert!(identity.capabilities.is_empty());
        assert!(!identity.has_capability("anything"));
        assert!(identity.verify().is_ok());
    }

    #[test]
    fn test_identity_with_very_long_display_name() {
        let long_name = "A".repeat(10_000);
        let (identity, _) = IdentityBuilder::new(&long_name)
            .build()
            .unwrap();
        assert_eq!(identity.display_name.len(), 10_000);
        assert!(identity.verify().is_ok());
    }

    // ── Advertisement signing tests ──────────────────────────────

    #[test]
    fn test_sign_and_verify_advertisement() {
        use crate::resource::{ResourceAdvertisement, ResourceSpec};

        let signing_key = SigningKey::generate(&mut OsRng);
        let mut ad = ResourceAdvertisement {
            agent_id: "did:walkie:test".into(),
            sequence: 1,
            timestamp: 1617000000000,
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 1024 * 1024 * 1024,
            },
            cpu_offer: 0.5,
            memory_offer_mb: 4096,
            bandwidth_offer: 5_000_000,
            storage_offer: 512 * 1024 * 1024,
            features: vec!["gpu".into()],
            signing_pubkey: Vec::new(),
            signature: Vec::new(),
        };

        sign_advertisement(&mut ad, &signing_key);

        // pubkey should be 32 bytes, signature 64 bytes
        assert_eq!(ad.signing_pubkey.len(), 32);
        assert_eq!(ad.signature.len(), 64);

        // Verification should succeed
        assert!(verify_advertisement(&ad).is_ok());
    }

    #[test]
    fn test_tampered_advertisement_fails_verification() {
        use crate::resource::{ResourceAdvertisement, ResourceSpec};

        let signing_key = SigningKey::generate(&mut OsRng);
        let mut ad = ResourceAdvertisement {
            agent_id: "did:walkie:test".into(),
            sequence: 1,
            timestamp: 1617000000000,
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 1024 * 1024 * 1024,
            },
            cpu_offer: 0.5,
            memory_offer_mb: 4096,
            bandwidth_offer: 5_000_000,
            storage_offer: 512 * 1024 * 1024,
            features: vec!["gpu".into()],
            signing_pubkey: Vec::new(),
            signature: Vec::new(),
        };

        sign_advertisement(&mut ad, &signing_key);

        // Tamper with cpu_offer after signing
        ad.cpu_offer = 1.0;

        // Verification should fail
        assert!(verify_advertisement(&ad).is_err());
    }

    #[test]
    fn test_unsigned_advertisement_fails_verification() {
        use crate::resource::{ResourceAdvertisement, ResourceSpec};

        let ad = ResourceAdvertisement {
            agent_id: "did:walkie:test".into(),
            sequence: 1,
            timestamp: 1617000000000,
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 1024 * 1024 * 1024,
            },
            cpu_offer: 0.5,
            memory_offer_mb: 4096,
            bandwidth_offer: 5_000_000,
            storage_offer: 512 * 1024 * 1024,
            features: vec![],
            signing_pubkey: Vec::new(),
            signature: Vec::new(),
        };

        assert!(verify_advertisement(&ad).is_err());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        use crate::resource::{ResourceAdvertisement, ResourceSpec};

        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);

        let mut ad = ResourceAdvertisement {
            agent_id: "did:walkie:test".into(),
            sequence: 1,
            timestamp: 1617000000000,
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 1024 * 1024 * 1024,
            },
            cpu_offer: 0.5,
            memory_offer_mb: 4096,
            bandwidth_offer: 5_000_000,
            storage_offer: 512 * 1024 * 1024,
            features: vec![],
            signing_pubkey: Vec::new(),
            signature: Vec::new(),
        };

        sign_advertisement(&mut ad, &signing_key);

        // Replace pubkey with wrong key's pubkey — signature won't match
        ad.signing_pubkey = wrong_key.verifying_key().to_bytes().to_vec();

        assert!(verify_advertisement(&ad).is_err());
    }

    // ── IdentityRegistry ──

/// A verified mapping between a libp2p PeerId and a did:walkie DID.
#[derive(Debug, Clone)]
pub struct PeerDidBinding {
    /// The did:walkie identifier (e.g. "did:walkie:abc123")
    pub did: String,
    /// Ed25519 public key (32 bytes)
    pub pub_key: Vec<u8>,
    /// Unix timestamp (ms) when the binding was created
    pub bound_at: u64,
}

/// Registry for bidirectional PeerId↔DID bindings.
///
/// Maintains two lookup indexes:
///   peer_id → DID  (used when receiving a message: "who sent this?")
///   DID → peer_id  (used when sending: "where is this agent?")
#[derive(Debug, Clone)]
pub struct IdentityRegistry {
    peer_to_did: std::collections::HashMap<String, PeerDidBinding>,
    did_to_peer: std::collections::HashMap<String, String>,
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityRegistry {
    pub fn new() -> Self {
        Self {
            peer_to_did: std::collections::HashMap::new(),
            did_to_peer: std::collections::HashMap::new(),
        }
    }

    /// Bind a peer_id to a DID. If the DID was already bound to a different
    /// peer, the old binding is removed first (reconnection scenario).
    pub fn bind(&mut self, peer_id: &str, did: &str, pub_key: Vec<u8>) {
        // Remove old peer→DID if this peer was bound before
        if let Some(old) = self.peer_to_did.remove(peer_id) {
            self.did_to_peer.remove(&old.did);
        }
        // Remove old DID→peer if this DID was bound to a different peer
        if let Some(old_peer) = self.did_to_peer.remove(did) {
            self.peer_to_did.remove(&old_peer);
        }

        let binding = PeerDidBinding {
            did: did.to_string(),
            pub_key,
            bound_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        self.peer_to_did.insert(peer_id.to_string(), binding);
        self.did_to_peer.insert(did.to_string(), peer_id.to_string());
    }

    /// Look up DID by peer_id.
    pub fn did_for_peer(&self, peer_id: &str) -> Option<&str> {
        self.peer_to_did.get(peer_id).map(|b| b.did.as_str())
    }

    /// Look up peer_id by DID.
    pub fn peer_for_did(&self, did: &str) -> Option<&str> {
        self.did_to_peer.get(did).map(|s| s.as_str())
    }

    /// Remove a binding by peer_id. Returns `true` if a binding existed.
    pub fn unbind(&mut self, peer_id: &str) -> bool {
        if let Some(binding) = self.peer_to_did.remove(peer_id) {
            self.did_to_peer.remove(&binding.did);
            true
        } else {
            false
        }
    }

    /// Get the full binding for a peer_id.
    pub fn get_binding(&self, peer_id: &str) -> Option<&PeerDidBinding> {
        self.peer_to_did.get(peer_id)
    }

    /// Number of active bindings.
    pub fn len(&self) -> usize {
        self.peer_to_did.len()
    }

    /// Check if the registry is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.peer_to_did.is_empty()
    }
}

    // ── IdentityRegistry Tests ──

    #[test]
    fn test_registry_bind_and_lookup() {
        let mut registry = IdentityRegistry::new();
        let peer_id = "12D3KooWABC";
        let did = "did:walkie:test-key";
        let pubkey = vec![42u8; 32];

        registry.bind(peer_id, did, pubkey.clone());
        assert_eq!(registry.did_for_peer(peer_id), Some(did));
        assert_eq!(registry.peer_for_did(did), Some(peer_id));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_registry_reverse_lookup() {
        let mut registry = IdentityRegistry::new();

        registry.bind("peer-1", "did:walkie:alice", vec![1u8; 32]);
        registry.bind("peer-2", "did:walkie:bob", vec![2u8; 32]);

        assert_eq!(registry.peer_for_did("did:walkie:alice"), Some("peer-1"));
        assert_eq!(registry.peer_for_did("did:walkie:bob"), Some("peer-2"));
    }

    #[test]
    fn test_registry_unbind() {
        let mut registry = IdentityRegistry::new();

        registry.bind("peer-1", "did:walkie:alice", vec![1u8; 32]);
        assert_eq!(registry.len(), 1);

        let removed = registry.unbind("peer-1");
        assert!(removed);
        assert!(registry.did_for_peer("peer-1").is_none());
        assert!(registry.peer_for_did("did:walkie:alice").is_none());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_rebind_moves_old_binding() {
        let mut registry = IdentityRegistry::new();

        // Bind alice to peer-1
        registry.bind("peer-1", "did:walkie:alice", vec![1u8; 32]);
        // Rebind alice to peer-2 (simulates reconnection with new PeerId)
        registry.bind("peer-2", "did:walkie:alice", vec![1u8; 32]);

        // Old binding should be gone
        assert!(registry.did_for_peer("peer-1").is_none());
        // New binding should work
        assert_eq!(registry.did_for_peer("peer-2"), Some("did:walkie:alice"));
        // DID should map to new peer
        assert_eq!(registry.peer_for_did("did:walkie:alice"), Some("peer-2"));
        // Only 1 binding total
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_registry_get_binding() {
        let mut registry = IdentityRegistry::new();
        let pubkey = vec![42u8; 32];

        registry.bind("peer-1", "did:walkie:alice", pubkey.clone());
        let binding = registry.get_binding("peer-1").unwrap();

        assert_eq!(binding.did, "did:walkie:alice");
        assert_eq!(binding.pub_key, pubkey);
        assert!(binding.bound_at > 0);
    }
}
