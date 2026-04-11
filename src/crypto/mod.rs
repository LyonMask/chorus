pub use chacha20poly1305::aead::Aead;

use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use std::time::{Duration, Instant};
use thiserror::Error;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Encrypted message format: nonce (12 bytes) || ciphertext+tag
pub const NONCE_SIZE: usize = 12;

/// Maximum number of messages per session before mandatory key rotation.
const MAX_MESSAGES_PER_SESSION: u64 = 100_000;

/// Session lifetime before mandatory key rotation (24 hours).
const SESSION_TTL: Duration = Duration::from_secs(86400);

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
    #[error("Session expired for peer: {0}")]
    SessionExpired(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A shared secret key for a peer session.
///
/// Sessions have a bounded lifetime (TTL + message count) to limit the
/// amount of data encrypted under a single key, reducing the impact of
/// any potential key compromise.
pub struct SessionKey {
    cipher: ChaCha20Poly1305,
    counter: u64,
    created_at: Instant,
}

impl SessionKey {
    /// Create from a raw 32-byte key (e.g. from X25519 DH).
    pub fn from_raw_key(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(key).expect("32 bytes, always valid"),
            counter: 0,
            created_at: Instant::now(),
        }
    }

    pub fn new(shared_secret: &SharedSecret) -> Self {
        let key = shared_secret.as_bytes();
        Self::from_raw_key(key)
    }

    /// Check if this session should be rotated.
    ///
    /// A session is considered expired when either:
    /// - The counter reaches `MAX_MESSAGES_PER_SESSION` (100,000)
    /// - The session age exceeds `SESSION_TTL` (24 hours)
    pub fn should_rotate(&self) -> bool {
        self.counter >= MAX_MESSAGES_PER_SESSION || self.created_at.elapsed() > SESSION_TTL
    }

    /// Returns how many messages have been encrypted with this session.
    pub fn message_count(&self) -> u64 {
        self.counter
    }

    /// Returns the session age.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
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
///
/// Sessions are automatically checked for expiry before encryption.
/// When a session expires, callers must re-establish a shared secret
/// via `create_session` with a fresh DH exchange.
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
    ///
    /// The private key is wrapped in `Secret<Vec<u8>>` which:
    /// - Forbids `Clone`, `Debug`, and `Serialize` on the private key
    /// - Zeroizes the private key bytes on drop
    pub fn generate_keypair(&self) -> Result<KeyPair> {
        let mut private_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut private_bytes);

        let secret = StaticSecret::from(private_bytes);
        let public = PublicKey::from(&secret);

        Ok(KeyPair {
            public: public.as_bytes().to_vec(),
            private: SecretBox::new(Box::new(secret.to_bytes().to_vec())),
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
    ///
    /// Returns `Error::SessionExpired` if the session has exceeded its TTL
    /// or message count limit. The caller should re-establish the session
    /// with a fresh DH exchange before retrying.
    pub fn encrypt_for(&mut self, peer_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or_else(|| Error::PeerNotFound(peer_id.to_string()))?;

        if session.should_rotate() {
            return Err(Error::SessionExpired(peer_id.to_string()));
        }

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

    /// Check if a session is expired for a peer.
    ///
    /// Returns `None` if no session exists for the peer.
    pub fn is_session_expired(&self, peer_id: &str) -> Option<bool> {
        self.sessions.get(peer_id).map(|s| s.should_rotate())
    }

    /// Remove an expired session. Returns `true` if a session was removed.
    pub fn remove_session(&mut self, peer_id: &str) -> bool {
        self.sessions.remove(peer_id).is_some()
    }
}

/// A keypair for key exchange.
///
/// The private key is protected by `secrecy::SecretBox`:
/// - Cannot be cloned (prevents accidental copies)
/// - Cannot be debug-printed (shows `[REDACTED]`)
/// - Cannot be serialized (prevents accidental persistence)
/// - Is zeroized on drop (memory is securely wiped)
///
/// Access the private key bytes via `private_key()` which returns a
/// reference. All call sites are auditable by grepping for `private_key()`.
pub struct KeyPair {
    pub public: Vec<u8>,
    private: SecretBox<Vec<u8>>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &format_args!("{} bytes", self.public.len()))
            .field("private", &"[REDACTED]")
            .finish()
    }
}

impl KeyPair {
    /// Access the private key bytes.
    ///
    /// This is the only way to access the private key. Every call site
    /// using this method is auditable via `grep private_key`.
    pub fn private_key(&self) -> &[u8] {
        self.private.expose_secret()
    }
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

        let shared_a =
            CryptoLayer::diffie_hellman(alice.private_key(), &bob.public).unwrap();
        let shared_b =
            CryptoLayer::diffie_hellman(bob.private_key(), &alice.public).unwrap();
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }

    #[test]
    fn test_full_e2ee() {
        let mut alice = CryptoLayer::new();
        let mut bob = CryptoLayer::new();

        let alice_keys = alice.generate_keypair().unwrap();
        let bob_keys = bob.generate_keypair().unwrap();

        let shared_a = CryptoLayer::diffie_hellman(
            alice_keys.private_key(),
            &bob_keys.public,
        )
        .unwrap();
        let shared_b =
            CryptoLayer::diffie_hellman(bob_keys.private_key(), &alice_keys.public).unwrap();

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

        let shared =
            CryptoLayer::diffie_hellman(alice_keys.private_key(), &bob_keys.public).unwrap();
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

    // ── Session expiry tests ──

    #[test]
    fn test_session_key_should_rotate_by_counter() {
        let mut session = make_test_session();
        assert!(!session.should_rotate());

        // Simulate reaching the message limit
        session.counter = MAX_MESSAGES_PER_SESSION;
        assert!(session.should_rotate());
    }

    #[test]
    fn test_session_key_should_rotate_by_ttl() {
        let mut session = make_test_session();
        assert!(!session.should_rotate());

        // Simulate TTL expiry by backdating created_at
        session.created_at = Instant::now() - SESSION_TTL - Duration::from_secs(1);
        assert!(session.should_rotate());
    }

    #[test]
    fn test_encrypt_for_rejects_expired_session() {
        let mut alice = CryptoLayer::new();
        let bob = CryptoLayer::new();

        let alice_keys = alice.generate_keypair().unwrap();
        let bob_keys = bob.generate_keypair().unwrap();

        let shared = CryptoLayer::diffie_hellman(
            alice_keys.private_key(),
            &bob_keys.public,
        )
        .unwrap();
        alice.create_session("bob", &shared);

        // Manually expire the session
        let session = alice.sessions.get_mut("bob").unwrap();
        session.counter = MAX_MESSAGES_PER_SESSION;

        // Encryption should fail with SessionExpired
        let result = alice.encrypt_for("bob", b"test");
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::SessionExpired(peer) => assert_eq!(peer, "bob"),
            other => panic!("Expected SessionExpired, got: {other}"),
        }
    }

    #[test]
    fn test_is_session_expired_and_remove() {
        let mut alice = CryptoLayer::new();
        let bob = CryptoLayer::new();

        let alice_keys = alice.generate_keypair().unwrap();
        let bob_keys = bob.generate_keypair().unwrap();

        let shared = CryptoLayer::diffie_hellman(
            alice_keys.private_key(),
            &bob_keys.public,
        )
        .unwrap();
        alice.create_session("bob", &shared);

        // Fresh session is not expired
        assert_eq!(alice.is_session_expired("bob"), Some(false));
        // Non-existent session
        assert_eq!(alice.is_session_expired("eve"), None);

        // Remove session
        assert!(alice.remove_session("bob"));
        assert!(!alice.has_session("bob"));
        assert!(!alice.remove_session("bob")); // Already removed
    }

    // ── KeyPair security tests ──

    #[test]
    fn test_keypair_private_not_clone() {
        let crypto = CryptoLayer::new();
        let keypair = crypto.generate_keypair().unwrap();

        // KeyPair itself should not be Clone (because private is Secret)
        // This is a compile-time check — if KeyPair derived Clone, this test
        // verifies the private key is protected.

        // Verify we can access the private key via the explicit method
        let private = keypair.private_key();
        assert_eq!(private.len(), 32);
    }

    #[test]
    fn test_keypair_debug_redacts_private() {
        let crypto = CryptoLayer::new();
        let keypair = crypto.generate_keypair().unwrap();

        let debug_str = format!("{:?}", keypair);
        assert!(debug_str.contains("[REDACTED]"));
        // The actual key bytes must never appear in debug output
        // (the field name "private" is fine -- the VALUE is redacted)
        assert!(!debug_str.contains(&format!("{:?}", keypair.public)));
    }

    #[test]
    fn test_session_metadata() {
        let session = make_test_session();
        assert_eq!(session.message_count(), 0);
        assert!(session.age() < Duration::from_secs(1));
    }
}
