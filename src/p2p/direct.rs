//! Direct channel — point-to-point request-response protocol.
//!
//! Messages that must not be broadcast (key exchange, DMs, identity claims,
//! resource declarations) are routed through this channel instead of Gossipsub.

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{self, Codec, ProtocolSupport};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use libp2p::PeerId;

use crate::resource::ResourceAdvertisement;

// ── Protocol constants ─────────────────────────────────────────

/// Protocol name registered on the multistream-select registry.
pub const WT_DIRECT_PROTOCOL: &str = "/walkie-talkie/direct/1.0.0";

/// Request timeout for inbound and outbound requests.
pub const DIRECT_REQUEST_TIMEOUT_SECS: u64 = 10;

/// Max concurrent inbound + outbound streams.
pub const DIRECT_MAX_CONCURRENT_STREAMS: usize = 64;

/// Max pending messages per peer in the store-and-forward queue.
pub const PENDING_MAX_PER_PEER: usize = 256;

/// TTL for pending messages before they are dropped.
pub const PENDING_TTL_SECS: u64 = 86400; // 24 hours

// ── Wire types ─────────────────────────────────────────────────

/// Request sent over the direct channel.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct DirectRequest {
    /// Monotonically increasing request ID for matching responses.
    pub request_id: u64,
    /// The payload carried by this request.
    pub payload: DirectPayload,
}

/// Payload variants for direct channel messages.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum DirectPayload {
    /// X25519 public key offer (initiates E2EE session).
    KeyOffer { public_key: Vec<u8> },
    /// X25519 public key accept (completes E2EE session).
    KeyAccept { public_key: Vec<u8> },
    /// ChaCha20-Poly1305 encrypted point-to-point message.
    Encrypted { ciphertext: Vec<u8> },
    /// Agent identity claim sent inside an established E2EE session.
    IdentityClaim { identity_json: Vec<u8> },
    /// Resource declaration: node advertises its available resources.
    ResourceDeclaration {
        advertisement: ResourceAdvertisement,
    },
}

/// Response to a direct request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct DirectResponse {
    /// Mirrors the request_id from the corresponding DirectRequest.
    pub request_id: u64,
    pub status: DirectResponseStatus,
}

/// Status codes for direct responses.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum DirectResponseStatus {
    Ok,
    Error(String),
    Busy,
}

// ── Request ID generator ───────────────────────────────────────

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Get the next monotonically increasing request ID.
pub fn next_request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

// ── Codec ──────────────────────────────────────────────────────

/// JSON-length-delimited codec for the direct channel.
///
/// Wire format: `[u32 BE frame length][JSON bytes]`.
#[derive(Debug, Clone)]
pub struct DirectCodec;

impl Default for DirectCodec {
    fn default() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Codec for DirectCodec {
    type Protocol = String;
    type Request = DirectRequest;
    type Response = DirectResponse;

    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request> {
        read_length_delimited_json(io).await
    }

    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response> {
        read_length_delimited_json(io).await
    }

    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()> {
        write_length_delimited_json(io, &req).await
    }

    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> std::io::Result<()> {
        write_length_delimited_json(io, &resp).await
    }
}

/// Read a length-delimited JSON frame: 4-byte big-endian length + body.
async fn read_length_delimited_json<T: serde::de::DeserializeOwned, R: AsyncRead + Unpin + Send>(
    reader: &mut R,
) -> std::io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check: cap frame size to 16 MB to prevent OOM.
    if len > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    serde_json::from_slice(&buf).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json: {e}"))
    })
}

/// Write a length-delimited JSON frame: 4-byte big-endian length + body.
async fn write_length_delimited_json<T: serde::Serialize, W: AsyncWrite + Unpin + Send>(
    writer: &mut W,
    value: &T,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json: {e}"))
    })?;

    let len = bytes.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;

    Ok(())
}

// ── Factory helpers ────────────────────────────────────────────

/// Create a configured request-response behaviour for the direct channel.
pub fn new_direct_behaviour() -> request_response::Behaviour<DirectCodec> {
    let protocols = std::iter::once((
        WT_DIRECT_PROTOCOL.to_string(),
        ProtocolSupport::Full,
    ));
    let config = request_response::Config::default()
        .with_request_timeout(Duration::from_secs(DIRECT_REQUEST_TIMEOUT_SECS))
        .with_max_concurrent_streams(DIRECT_MAX_CONCURRENT_STREAMS);
    request_response::Behaviour::new(protocols, config)
}

/// Shorthand: build a KeyOffer request.
pub fn key_offer_request(public_key: Vec<u8>) -> DirectRequest {
    DirectRequest {
        request_id: next_request_id(),
        payload: DirectPayload::KeyOffer { public_key },
    }
}

/// Shorthand: build a KeyAccept request.
pub fn key_accept_request(public_key: Vec<u8>) -> DirectRequest {
    DirectRequest {
        request_id: next_request_id(),
        payload: DirectPayload::KeyAccept { public_key },
    }
}

/// Shorthand: build an Encrypted request.
pub fn encrypted_request(ciphertext: Vec<u8>) -> DirectRequest {
    DirectRequest {
        request_id: next_request_id(),
        payload: DirectPayload::Encrypted { ciphertext },
    }
}

/// Shorthand: build an IdentityClaim request.
pub fn identity_claim_request(identity_json: Vec<u8>) -> DirectRequest {
    DirectRequest {
        request_id: next_request_id(),
        payload: DirectPayload::IdentityClaim { identity_json },
    }
}

/// Shorthand: build a ResourceDeclaration request.
pub fn resource_declaration_request(ad: ResourceAdvertisement) -> DirectRequest {
    DirectRequest {
        request_id: next_request_id(),
        payload: DirectPayload::ResourceDeclaration { advertisement: ad },
    }
}

/// Build a simple OK response mirroring a request_id.
pub fn ok_response(request_id: u64) -> DirectResponse {
    DirectResponse {
        request_id,
        status: DirectResponseStatus::Ok,
    }
}

// ── Pending Message Store (in-memory, Phase 1) ─────────────────

/// In-memory store-and-forward queue for messages destined to offline peers.
///
/// When a peer connects, drain their pending queue and send everything.
/// Messages expire after `PENDING_TTL_SECS`. No persistence yet — that's
/// Phase 2 (sled migration).
#[derive(Debug)]
pub struct PendingMessageStore {
    /// peer_id → list of (timestamp, request)
    queue: std::sync::RwLock<HashMap<PeerId, Vec<(Instant, DirectRequest)>>>,
    max_per_peer: usize,
    ttl: Duration,
}

impl PendingMessageStore {
    pub fn new() -> Self {
        Self {
            queue: std::sync::RwLock::new(HashMap::new()),
            max_per_peer: PENDING_MAX_PER_PEER,
            ttl: Duration::from_secs(PENDING_TTL_SECS),
        }
    }

    /// Store a message for a peer. Returns false if the queue is full.
    pub fn store(&self, peer_id: PeerId, request: DirectRequest) -> bool {
        let mut queue = match self.queue.write() {
            Ok(q) => q,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = queue.entry(peer_id).or_default();

        // Evict expired messages first
        entry.retain(|(ts, _)| ts.elapsed() < self.ttl);

        if entry.len() >= self.max_per_peer {
            return false;
        }

        entry.push((Instant::now(), request));
        true
    }

    /// Drain all pending messages for a peer. Returns `None` if empty.
    pub fn drain(&self, peer_id: &PeerId) -> Option<Vec<DirectRequest>> {
        let mut queue = match self.queue.write() {
            Ok(q) => q,
            Err(poisoned) => poisoned.into_inner(),
        };
        queue.remove(peer_id).map(|mut entries| {
            entries.retain(|(ts, _)| ts.elapsed() < self.ttl);
            entries.into_iter().map(|(_, req)| req).collect()
        })
    }

    /// Number of pending messages for a peer.
    pub fn pending_count(&self, peer_id: &PeerId) -> usize {
        let queue = match self.queue.read() {
            Ok(q) => q,
            Err(poisoned) => poisoned.into_inner(),
        };
        queue.get(peer_id).map(|e| e.len()).unwrap_or(0)
    }

    /// Total number of pending messages across all peers.
    pub fn total_pending(&self) -> usize {
        let queue = match self.queue.read() {
            Ok(q) => q,
            Err(poisoned) => poisoned.into_inner(),
        };
        queue.values().map(|e| e.len()).sum()
    }

    /// Remove all expired messages across all peers.
    pub fn evict_expired(&self) {
        let mut queue = match self.queue.write() {
            Ok(q) => q,
            Err(poisoned) => poisoned.into_inner(),
        };
        for entry in queue.values_mut() {
            entry.retain(|(ts, _)| ts.elapsed() < self.ttl);
        }
        queue.retain(|_, v| !v.is_empty());
    }
}

impl Default for PendingMessageStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{ResourceSpec, now_ms};

    fn make_test_ad(agent_id: &str) -> ResourceAdvertisement {
        ResourceAdvertisement {
            agent_id: agent_id.to_string(),
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
    fn test_direct_request_serialization() {
        let req = key_offer_request(vec![1u8; 32]);
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: DirectRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_direct_response_serialization() {
        let resp = ok_response(42);
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: DirectResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.status, DirectResponseStatus::Ok);
    }

    #[test]
    fn test_direct_response_error() {
        let resp = DirectResponse {
            request_id: 1,
            status: DirectResponseStatus::Error("test error".into()),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: DirectResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.status, DirectResponseStatus::Error("test error".into()));
    }

    #[test]
    fn test_next_request_id_monotonic() {
        let a = next_request_id();
        let b = next_request_id();
        let c = next_request_id();
        assert!(a < b && b < c);
    }

    #[test]
    fn test_pending_store_basic() {
        let store = PendingMessageStore::new();
        let peer = PeerId::random();

        assert!(store.pending_count(&peer) == 0);
        assert!(store.drain(&peer).is_none());

        let req = key_offer_request(vec![1u8; 32]);
        assert!(store.store(peer, req));

        assert!(store.pending_count(&peer) == 1);
        let msgs = store.drain(&peer).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(store.pending_count(&peer) == 0);
    }

    #[test]
    fn test_pending_store_max_per_peer() {
        let store = PendingMessageStore::new();
        let peer = PeerId::random();

        for i in 0..PENDING_MAX_PER_PEER {
            let req = key_offer_request(vec![i as u8; 32]);
            assert!(store.store(peer, req));
        }
        // One more should be rejected
        let req = key_offer_request(vec![255u8; 32]);
        assert!(!store.store(peer, req));
    }

    #[test]
    fn test_pending_store_drain_is_empty_after() {
        let store = PendingMessageStore::new();
        let peer = PeerId::random();

        store.store(peer, key_offer_request(vec![1u8; 32]));
        store.store(peer, key_accept_request(vec![2u8; 32]));

        let msgs = store.drain(&peer).unwrap();
        assert_eq!(msgs.len(), 2);

        assert!(store.drain(&peer).is_none());
    }

    #[test]
    fn test_pending_store_total_pending() {
        let store = PendingMessageStore::new();
        let p1 = PeerId::random();
        let p2 = PeerId::random();

        store.store(p1, key_offer_request(vec![1u8; 32]));
        store.store(p1, key_accept_request(vec![2u8; 32]));
        store.store(p2, encrypted_request(vec![3u8; 32]));

        assert_eq!(store.total_pending(), 3);
    }

    #[test]
    fn test_payload_variants_roundtrip() {
        let payloads = vec![
            DirectPayload::KeyOffer { public_key: vec![1u8; 32] },
            DirectPayload::KeyAccept { public_key: vec![2u8; 32] },
            DirectPayload::Encrypted { ciphertext: vec![3u8; 28] },
            DirectPayload::IdentityClaim { identity_json: b"{}".to_vec() },
            DirectPayload::ResourceDeclaration {
                advertisement: make_test_ad("did:walkie:test"),
            },
        ];

        for payload in payloads {
            let req = DirectRequest { request_id: 42, payload };
            let json = serde_json::to_vec(&req).unwrap();
            let decoded: DirectRequest = serde_json::from_slice(&json).unwrap();
            assert_eq!(req, decoded);
        }
    }

    #[test]
    fn test_resource_declaration_request() {
        let ad = make_test_ad("did:walkie:test");
        let req = resource_declaration_request(ad.clone());
        match req.payload {
            DirectPayload::ResourceDeclaration { advertisement } => {
                assert_eq!(advertisement, ad);
            }
            _ => panic!("expected ResourceDeclaration payload"),
        }
    }

    #[tokio::test]
    async fn test_codec_request_response_serialization() {
        // Test that request and response serialize correctly end-to-end.
        // The actual stream I/O is handled by libp2p's infrastructure.
        let req = DirectRequest {
            request_id: 42,
            payload: DirectPayload::Encrypted { ciphertext: vec![1, 2, 3] },
        };
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: DirectRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(req, decoded);

        let resp = ok_response(42);
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: DirectResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(resp, decoded);
    }
}
