pub use chacha20poly1305::aead::Aead;

use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use thiserror::Error;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Encrypted message format: nonce (12 bytes) || ciphertext+tag
pub const NONCE_SIZE: usize = 12;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Invalid ciphertext length")]
    InvalidCiphertext,
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A shared secret key for a peer session.
pub struct SessionKey {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl SessionKey {
    /// Create from a raw 32-byte key (e.g. from X25519 DH).
    pub fn from_raw_key(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(key).expect("32 bytes, always valid"),
            counter: 0,
        }
    }

    pub fn new(shared_secret: &SharedSecret) -> Self {
        let key = shared_secret.as_bytes();
        Self::from_raw_key(key)
    }

    /// Encrypt plaintext -> nonce(12) || ciphertext+tag
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Encryption(e.to_string()))?;

        let mut output = nonce_bytes.to_vec();
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt nonce(12) || ciphertext+tag -> plaintext
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE + 16 {
            return Err(Error::InvalidCiphertext);
        }

        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| Error::Decryption("Authentication failed".into()))
    }
}

/// CryptoLayer manages key exchange and encrypted sessions.
pub struct CryptoLayer {
    sessions: std::collections::HashMap<String, SessionKey>,
}

impl Default for CryptoLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoLayer {
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
        }
    }

    /// Generate a new X25519 keypair.
    pub fn generate_keypair(&self) -> Result<KeyPair> {
        let mut private_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut private_bytes);

        let secret = StaticSecret::from(private_bytes);
        let public = PublicKey::from(&secret);

        Ok(KeyPair {
            public: public.as_bytes().to_vec(),
            private: secret.to_bytes().to_vec(),
        })
    }

    /// Perform X25519 DH: our_private * their_public = shared_secret
    pub fn diffie_hellman(our_private: &[u8], their_public: &[u8]) -> Result<SharedSecret> {
        if our_private.len() != 32 || their_public.len() != 32 {
            return Err(Error::KeyGeneration("Keys must be 32 bytes".into()));
        }

        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(our_private);
        let secret = StaticSecret::from(priv_bytes);

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(their_public);
        let public = PublicKey::from(pub_bytes);

        Ok(secret.diffie_hellman(&public))
    }

    /// Create a session with a peer.
    pub fn create_session(&mut self, peer_id: &str, shared_secret: &SharedSecret) {
        self.sessions
            .insert(peer_id.to_string(), SessionKey::new(shared_secret));
    }

    /// Encrypt a message for a specific peer.
    pub fn encrypt_for(&mut self, peer_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or_else(|| Error::PeerNotFound(peer_id.to_string()))?;
        session.encrypt(plaintext)
    }

    /// Decrypt a message from a specific peer.
    pub fn decrypt_from(&mut self, peer_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or_else(|| Error::PeerNotFound(peer_id.to_string()))?;
        session.decrypt(data)
    }

    /// Check if a session exists for a peer.
    pub fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.contains_key(peer_id)
    }
}

/// A keypair for key exchange.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_session() -> SessionKey {
        // Do a real DH to get a SharedSecret
        let alice_sec = StaticSecret::from([1u8; 32]);
        let _alice_pub = PublicKey::from(&alice_sec);
        let bob_sec = StaticSecret::from([2u8; 32]);
        let bob_pub = PublicKey::from(&bob_sec);
        let shared = alice_sec.diffie_hellman(&bob_pub);
        SessionKey::new(&shared)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut session = make_test_session();

        let plaintext = b"Hello, Walkie Talkie!";
        let encrypted = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let mut session = make_test_session();

        let enc1 = session.encrypt(b"message 1").unwrap();
        let enc2 = session.encrypt(b"message 1").unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_diffie_hellman() {
        let crypto = CryptoLayer::new();
        let alice = crypto.generate_keypair().unwrap();
        let bob = crypto.generate_keypair().unwrap();

        let shared_a = CryptoLayer::diffie_hellman(&alice.private, &bob.public).unwrap();
        let shared_b = CryptoLayer::diffie_hellman(&bob.private, &alice.public).unwrap();
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }

    #[test]
    fn test_full_e2ee() {
        let mut alice = CryptoLayer::new();
        let mut bob = CryptoLayer::new();

        let alice_keys = alice.generate_keypair().unwrap();
        let bob_keys = bob.generate_keypair().unwrap();

        let shared_a = CryptoLayer::diffie_hellman(&alice_keys.private, &bob_keys.public).unwrap();
        let shared_b = CryptoLayer::diffie_hellman(&bob_keys.private, &alice_keys.public).unwrap();

        alice.create_session("bob", &shared_a);
        bob.create_session("alice", &shared_b);

        // Alice -> Bob
        let msg = b"Push-to-talk!";
        let enc = alice.encrypt_for("bob", msg).unwrap();
        let dec = bob.decrypt_from("alice", &enc).unwrap();
        assert_eq!(msg.to_vec(), dec);

        // Bob -> Alice
        let reply = b"Roger that!";
        let enc2 = bob.encrypt_for("alice", reply).unwrap();
        let dec2 = alice.decrypt_from("bob", &enc2).unwrap();
        assert_eq!(reply.to_vec(), dec2);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let mut session = make_test_session();

        let mut encrypted = session.encrypt(b"secret").unwrap();
        encrypted[15] ^= 0xff;
        assert!(session.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_wrong_peer_fails() {
        let mut alice = CryptoLayer::new();
        let bob = CryptoLayer::new();

        let alice_keys = alice.generate_keypair().unwrap();
        let bob_keys = bob.generate_keypair().unwrap();

        let shared = CryptoLayer::diffie_hellman(&alice_keys.private, &bob_keys.public).unwrap();
        alice.create_session("bob", &shared);

        // Try to decrypt from unknown peer
        assert!(alice.decrypt_from("eve", b"garbage").is_err());
    }

    // ── Boundary tests ──

    #[test]
    fn test_encrypt_empty_plaintext() {
        let mut session = make_test_session();
        let encrypted = session.encrypt(b"").unwrap();
        assert!(encrypted.len() > NONCE_SIZE); // nonce + poly1305 tag even for empty
        let decrypted = session.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_nonce_only_fails() {
        let mut session = make_test_session();
        let data = [0u8; NONCE_SIZE]; // 12 bytes nonce, zero bytes ciphertext
        assert!(session.decrypt(&data).is_err());
    }

    #[test]
    fn test_decrypt_short_tag_fails() {
        let mut session = make_test_session();
        // NONCE_SIZE + 15 bytes: one byte short of the 16-byte Poly1305 tag
        let data = [0u8; NONCE_SIZE + 15];
        assert!(session.decrypt(&data).is_err());
    }

    #[test]
    fn test_decrypt_valid_length_invalid_content_fails() {
        let mut session = make_test_session();
        // Valid length (nonce + tag), but random bytes = invalid AEAD
        let data = [0x42u8; NONCE_SIZE + 16];
        assert!(session.decrypt(&data).is_err());
    }

    #[test]
    fn test_multiple_sequential_encryptions_counter_increments() {
        let mut session = make_test_session();
        let enc1 = session.encrypt(b"a").unwrap();
        let enc2 = session.encrypt(b"b").unwrap();
        let enc3 = session.encrypt(b"c").unwrap();
        // All nonces must differ (counter increments)
        let nonce1 = &enc1[..NONCE_SIZE];
        let nonce2 = &enc2[..NONCE_SIZE];
        let nonce3 = &enc3[..NONCE_SIZE];
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        // All decrypt correctly
        assert_eq!(session.decrypt(&enc1).unwrap(), b"a");
        assert_eq!(session.decrypt(&enc2).unwrap(), b"b");
        assert_eq!(session.decrypt(&enc3).unwrap(), b"c");
    }

    #[test]
    fn test_diffie_hellman_wrong_key_lengths() {
        let result = CryptoLayer::diffie_hellman(&[1u8; 16], &[2u8; 32]);
        assert!(result.is_err());
        let result = CryptoLayer::diffie_hellman(&[1u8; 32], &[2u8; 16]);
        assert!(result.is_err());
        let result = CryptoLayer::diffie_hellman(&[1u8; 31], &[2u8; 33]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_large_payload() {
        let mut session = make_test_session();
        let large = vec![0xABu8; 64 * 1024]; // 64 KB
        let encrypted = session.encrypt(&large).unwrap();
        let decrypted = session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.len(), 64 * 1024);
        assert_eq!(decrypted, large);
    }
}
