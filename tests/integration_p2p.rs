//! Integration tests for two-node P2P communication.
//!
//! Scenarios:
//! 1. Two nodes connect + auto key exchange via Direct channel
//! 2. Encrypted message round-trip
//! 3. Structured AgentMessage round-trip
//! 4. Multiple encrypted messages
//! 5. Connection lifecycle events

use std::time::Duration;
use tokio::sync::mpsc;
use walkie_talkie_core::identity::{AgentIdentity, IdentityBuilder};
use walkie_talkie_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};
use walkie_talkie_core::protocol::{AgentMessage, MessageProtocol};

/// Helper: create a P2PConfig for testing with a specific listen port.
fn test_config(port: u16) -> P2PConfig {
    let mut cfg = P2PConfig::default();
    cfg.listen_on = vec![format!("/ip4/127.0.0.1/tcp/{port}")];
    cfg.ping_interval_secs = 2;
    cfg.ping_timeout_secs = 3;
    cfg.idle_timeout_secs = 30;
    cfg
}

/// Helper: build a minimal AgentIdentity for testing.
fn test_identity(name: &str) -> AgentIdentity {
    IdentityBuilder::new(name)
        .capability("test")
        .owner_id(&format!("did:walkie:{name}"))
        .build()
        .expect("identity build")
        .0
}

/// Spawn two nodes on specific ports, wait for listen addresses from events.
/// Returns (net_a, ev_a, addr_a, net_b, ev_b, addr_b).
async fn spawn_pair(
    port_a: u16,
    port_b: u16,
) -> (
    P2PNetwork,
    mpsc::UnboundedReceiver<P2PEvent>,
    String,
    P2PNetwork,
    mpsc::UnboundedReceiver<P2PEvent>,
    String,
) {
    let (net_a, mut ev_a) = P2PNetwork::new(test_config(port_a)).expect("node_a");
    let (net_b, mut ev_b) = P2PNetwork::new(test_config(port_b)).expect("node_b");

    // Collect listen addresses from events
    let addr_a = wait_for_event(&mut ev_a, |e| matches!(e, P2PEvent::Listening { .. }), Duration::from_secs(3)).await;
    let addr_a_str = match addr_a {
        P2PEvent::Listening { address } => address.to_string(),
        _ => panic!("expected Listening event"),
    };

    let addr_b = wait_for_event(&mut ev_b, |e| matches!(e, P2PEvent::Listening { .. }), Duration::from_secs(3)).await;
    let addr_b_str = match addr_b {
        P2PEvent::Listening { address } => address.to_string(),
        _ => panic!("expected Listening event"),
    };

    (net_a, ev_a, addr_a_str, net_b, ev_b, addr_b_str)
}

// ── Test 1: Connection + auto key exchange ──

#[tokio::test]
async fn test_two_nodes_connect_and_exchange_keys() {
    let (mut net_a, mut ev_a, addr_a, mut net_b, mut ev_b, addr_b) =
        spawn_pair(0, 0).await;

    tracing::info!("node_a listening on {}", addr_a);
    tracing::info!("node_b listening on {}", addr_b);

    // B dials A
    net_b.dial(&addr_a).await.expect("dial_b_to_a");

    // Wait for both to establish session
    wait_for_session(&mut ev_a, &mut ev_b, Duration::from_secs(8)).await;

    let peer_b_id = *net_b.local_peer_id();
    let peer_a_id = *net_a.local_peer_id();
    assert!(net_a.has_session(&peer_b_id).await.expect("has_session_a"));
    assert!(net_b.has_session(&peer_a_id).await.expect("has_session_b"));

    net_a.shutdown().ok();
    net_b.shutdown().ok();
}

// ── Test 2: Encrypted message round-trip ──

#[tokio::test]
async fn test_encrypted_message_roundtrip() {
    let (mut net_a, mut ev_a, addr_a, mut net_b, mut ev_b, addr_b) =
        spawn_pair(0, 0).await;

    // A dials B
    net_a.dial(&addr_b).await.expect("dial");
    wait_for_session(&mut ev_a, &mut ev_b, Duration::from_secs(8)).await;

    let peer_b_id = *net_b.local_peer_id();
    let plaintext = b"hello from node_a".to_vec();

    net_a.send_encrypted(peer_b_id, plaintext.clone()).await.expect("send_encrypted");

    // B should receive the decrypted message
    let msg = wait_for_event(&mut ev_b, |e| matches!(e, P2PEvent::EncryptedMessage { .. }), Duration::from_secs(8)).await;
    match msg {
        P2PEvent::EncryptedMessage { plaintext: received, .. } => {
            assert_eq!(received, plaintext);
        }
        _ => panic!("expected EncryptedMessage, got {:?}", msg),
    }

    net_a.shutdown().ok();
    net_b.shutdown().ok();
}

// ── Test 3: Structured AgentMessage round-trip ──

#[tokio::test]
async fn test_structured_message_roundtrip() {
    let (mut net_a, mut ev_a, _addr_a, mut net_b, mut ev_b, addr_b) =
        spawn_pair(0, 0).await;

    net_a.dial(&addr_b).await.expect("dial");
    wait_for_session(&mut ev_a, &mut ev_b, Duration::from_secs(8)).await;

    let peer_b_id = *net_b.local_peer_id();
    let identity = test_identity("node_a");

    let msg = AgentMessage::new(
        &identity,
        MessageProtocol::TaskAssignment,
        serde_json::json!({"action": "ping", "data": 42}),
    );

    let msg_bytes = msg.to_json_bytes().expect("serialize msg");
    net_a.send_encrypted(peer_b_id, msg_bytes).await.expect("send");

    let event = wait_for_event(&mut ev_b, |e| matches!(e, P2PEvent::StructuredMessage { .. }), Duration::from_secs(8)).await;
    match event {
        P2PEvent::StructuredMessage { message, .. } => {
            assert_eq!(message.protocol.tag(), "TASK");
            assert_eq!(message.payload_i64("data"), Some(42));
        }
        _ => panic!("expected StructuredMessage, got {:?}", event),
    }

    net_a.shutdown().ok();
    net_b.shutdown().ok();
}

// ── Test 4: Multiple encrypted messages ──

#[tokio::test]
async fn test_multiple_encrypted_messages() {
    let (mut net_a, mut ev_a, _addr_a, mut net_b, mut ev_b, addr_b) =
        spawn_pair(0, 0).await;

    net_a.dial(&addr_b).await.expect("dial");
    wait_for_session(&mut ev_a, &mut ev_b, Duration::from_secs(8)).await;

    let peer_b_id = *net_b.local_peer_id();

    for i in 0..5 {
        let msg = format!("message {i}").into_bytes();
        net_a.send_encrypted(peer_b_id, msg).await.expect("send");
    }

    let mut received = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while received < 5 {
        if deadline.elapsed().as_nanos() > 0 {
            break;
        }
        match tokio::time::timeout(Duration::from_secs(1), ev_b.recv()).await {
            Ok(Some(P2PEvent::EncryptedMessage { .. })) => received += 1,
            Ok(Some(_)) => {} // other events, skip
            Ok(None) | Err(_) => break,
        }
    }
    assert_eq!(received, 5, "expected 5 messages, got {received}");

    net_a.shutdown().ok();
    net_b.shutdown().ok();
}

// ── Test 5: Connection lifecycle events ──

#[tokio::test]
async fn test_connection_lifecycle_events() {
    let (mut net_a, mut ev_a, _addr_a, net_b, _ev_b, addr_b) =
        spawn_pair(0, 0).await;

    net_a.dial(&addr_b).await.expect("dial");

    // Should see PeerConnected
    let event = wait_for_event(&mut ev_a, |e| matches!(e, P2PEvent::PeerConnected { .. }), Duration::from_secs(8)).await;
    assert!(matches!(event, P2PEvent::PeerConnected { .. }));

    // Should see SessionEstablished
    let event = wait_for_event(&mut ev_a, |e| matches!(e, P2PEvent::SessionEstablished { .. }), Duration::from_secs(8)).await;
    assert!(matches!(event, P2PEvent::SessionEstablished { .. }));

    // list_peers should include B
    let peers = net_a.list_peers().await.expect("list_peers");
    assert!(!peers.is_empty());

    net_a.shutdown().ok();
    net_b.shutdown().ok();
}

// ── Test 6: Broadcast still works via Gossipsub ──

#[tokio::test]
async fn test_broadcast_via_gossipsub() {
    let (mut net_a, mut ev_a, _addr_a, mut net_b, mut ev_b, addr_b) =
        spawn_pair(0, 0).await;

    net_a.dial(&addr_b).await.expect("dial");
    wait_for_session(&mut ev_a, &mut ev_b, Duration::from_secs(8)).await;

    // Broadcast raw bytes
    let data = b"broadcast test".to_vec();
    net_a.broadcast(data.clone()).await.expect("broadcast");

    // B should receive as RawMessage (not encrypted)
    let event = wait_for_event(&mut ev_b, |e| matches!(e, P2PEvent::RawMessage { .. }), Duration::from_secs(8)).await;
    match event {
        P2PEvent::RawMessage { data: received, .. } => {
            assert_eq!(received, data);
        }
        _ => panic!("expected RawMessage, got {:?}", event),
    }

    net_a.shutdown().ok();
    net_b.shutdown().ok();
}

// ── Helpers ──

/// Wait for both sides to receive SessionEstablished.
async fn wait_for_session(
    ev_a: &mut mpsc::UnboundedReceiver<P2PEvent>,
    ev_b: &mut mpsc::UnboundedReceiver<P2PEvent>,
    timeout: Duration,
) {
    let mut a_ok = false;
    let mut b_ok = false;
    let deadline = tokio::time::Instant::now() + timeout;

    while !a_ok || !b_ok {
        if deadline.elapsed().as_nanos() > 0 {
            panic!("timeout waiting for session: a={a_ok}, b={b_ok}");
        }
        tokio::select! {
            event = ev_a.recv() => {
                if let Some(P2PEvent::SessionEstablished { .. }) = event {
                    a_ok = true;
                }
            }
            event = ev_b.recv() => {
                if let Some(P2PEvent::SessionEstablished { .. }) = event {
                    b_ok = true;
                }
            }
        }
    }
}

/// Wait for a specific event type, with timeout. Returns the matched event.
async fn wait_for_event<F>(
    rx: &mut mpsc::UnboundedReceiver<P2PEvent>,
    predicate: F,
    timeout: Duration,
) -> P2PEvent
where
    F: Fn(&P2PEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = timeout.saturating_sub(deadline.elapsed());
        if remaining.as_nanos() == 0 {
            panic!("timeout waiting for event");
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(event)) => {
                if predicate(&event) {
                    return event;
                }
            }
            Ok(None) => panic!("event channel closed"),
            Err(_) => panic!("timeout waiting for event"),
        }
    }
}
