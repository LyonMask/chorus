//! P2P Two-Node Demo — Walkie Talkie Core
//!
//! Two nodes chatting on the local network via Gossipsub + mDNS.
//!
//! # Usage
//!
//! ```bash
//! # Terminal 1 — Node A
//! cargo run --example p2p-basic
//!
//! # Terminal 2 — Node B (paste Node A's listen address)
//! cargo run --example p2p-basic -- /ip4/127.0.0.1/tcp/<PORT>
//! ```
//!
//! mDNS will also auto-discover peers on the same LAN.
//! Type messages and press Enter to broadcast. `Ctrl+C` to quit.

use std::error::Error;

use tokio::io::{AsyncBufReadExt, BufReader};

use chorus_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ── Logging ──
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,libp2p_gossipsub=debug,libp2p_mdns=debug".into()),
        )
        .with_target(false)
        .with_thread_ids(false)
        .init();

    // ── Config ──
    let remote_addr = std::env::args().nth(1);

    let config = P2PConfig {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
        bootstrap_peers: remote_addr
            .as_ref()
            .map(|a| vec![a.clone()])
            .unwrap_or_default(),
        enable_mdns: true,
        agent_version: Some("chorus-demo/0.1.0-alpha".to_string()),
        ping_interval_secs: 10,
        ping_timeout_secs: 15,
        ..Default::default()
    };

    // ── Create network ──
    let (network, mut events) = P2PNetwork::new(config)?;
    let peer_id = *network.local_peer_id();

    println!("╔══════════════════════════════════════════════╗");
    println!("║     📡 Walkie Talkie — P2P Network Demo     ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║  Peer ID: {peer_id:<36}║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // ── Spawn stdin reader ──
    let net = network.clone();
    let my_id = peer_id;
    tokio::spawn(async move {
        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let text = line.trim();
            if text.is_empty() {
                continue;
            }
            match text {
                "/quit" | "/q" => break,
                "/peers" => match net.list_peers().await {
                    Ok(peers) => {
                        println!("Connected peers ({}):", peers.len());
                        for p in &peers {
                            println!("  - {p}");
                        }
                    }
                    Err(e) => eprintln!("Error listing peers: {e}"),
                },
                "/addrs" => match net.external_addresses().await {
                    Ok(addrs) => {
                        println!("External addresses:");
                        for a in &addrs {
                            println!("  - {a}");
                        }
                    }
                    Err(e) => eprintln!("Error: {e}"),
                },
                _ => {
                    let msg = format!("[{my_id}] {text}");
                    if let Err(e) = net.broadcast(msg.into_bytes()).await {
                        eprintln!("Broadcast error: {e}");
                    }
                }
            }
        }
    });

    println!("Commands: type message to broadcast | /peers | /addrs | /quit");
    println!();

    // ── Event loop ──
    while let Some(event) = events.recv().await {
        match event {
            P2PEvent::Listening { address } => {
                println!("🎧 Listening on: {address}");
                if remote_addr.is_none() {
                    println!("   Share this address to connect another node:");
                    println!("   cargo run --example p2p-basic -- {address}");
                    println!();
                }
            }
            P2PEvent::PeerConnected { peer_id } => {
                println!("✓ Connected: {peer_id}");
            }
            P2PEvent::PeerDisconnected { peer_id } => {
                println!("✗ Disconnected: {peer_id}");
            }
            P2PEvent::PeerDiscovered { peer_id, addresses } => {
                println!("📡 mDNS discovered: {peer_id} at {addresses:?}");
            }
            P2PEvent::PeerExpired { peer_id } => {
                println!("📡 mDNS expired: {peer_id}");
            }
            P2PEvent::RawMessage { from: _, data } => {
                let text = String::from_utf8_lossy(&data);
                println!("📨 {text}");
            }
            P2PEvent::Identify { peer_id, info } => {
                println!(
                    "🔐 Identified {peer_id}: agent={}, protocols={:?}",
                    info.agent_version, info.protocols
                );
            }
            P2PEvent::PingSuccess { peer_id, rtt } => {
                println!("🏓 Ping {peer_id}: {rtt:.2?}");
            }
            P2PEvent::EncryptedMessage { from, plaintext } => {
                let text = String::from_utf8_lossy(&plaintext);
                println!("🔒 [{}] {}", from, text);
            }
            P2PEvent::SessionEstablished { peer_id } => {
                println!("🔒 Session with {peer_id}");
            }
            P2PEvent::SessionFailed { peer_id, reason } => {
                println!("❌ Session fail {peer_id}: {reason}");
            }
            P2PEvent::AgentIdentified { peer_id: _, identity } => {
                println!("🪪 Agent: {} ({})", identity.display_name, identity.short_id());
            }
            P2PEvent::IdentityVerificationFailed { peer_id, reason } => {
                println!("❌ Identity fail {peer_id}: {reason}");
            }
            P2PEvent::StructuredMessage { from, message } => {
                println!(
                    "📋 {} [{}]: {}",
                    &from.to_string()[..8.min(from.to_string().len())],
                    message.protocol.tag(),
                    message.summary()
                );
            }
            P2PEvent::PingFailure { peer_id, error } => {
                println!("🏓 Ping FAIL {peer_id}: {error}");
            }
            P2PEvent::DirectMessage { from, request_id, payload } => {
                println!("📨 Direct #{} from {}: {:?}", request_id, from, payload);
            }
            P2PEvent::DirectSendFailed { peer_id, reason } => {
                println!("❌ Direct send fail {peer_id}: {reason}");
            }
            P2PEvent::DirectResponse { from, response } => {
                println!("📨 Direct response from {}: {:?}", from, response);
            }
            P2PEvent::PendingMessagesSent { peer_id, count } => {
                println!("📤 Flush {} pending to {}", count, peer_id);
            }
            P2PEvent::ResourceDeclared { peer_id, advertisement } => {
                println!(
                    "📦 Resource from {peer_id}: agent={}, cpu={:.1}%, mem={}MB",
                    advertisement.agent_id,
                    advertisement.cpu_offer * 100.0,
                    advertisement.memory_offer_mb
                );
            }
            P2PEvent::ResourceDeclarationRejected { peer_id, reason } => {
                println!("❌ Resource rejected from {peer_id}: {reason}");
            }
            P2PEvent::ResourceOfferSent { peer_id, session_id } => {
                println!("📦 Offer sent to {peer_id}: session={session_id}");
            }
            P2PEvent::ResourceOfferReceived { peer_id, offer } => {
                println!(
                    "📦 Offer from {peer_id}: cpu={:.1}, mem={}MB",
                    offer.cpu_amount, offer.memory_amount_mb
                );
            }
            P2PEvent::ResourceSessionStarted { peer_id, session_id, expires_at } => {
                println!("✅ Session started with {peer_id}: session={session_id}, expires_at={expires_at}");
            }
            P2PEvent::ResourceReleased { peer_id, session_id, contribution_delta } => {
                println!(
                    "👋 Session released {peer_id}: session={session_id}, delta={contribution_delta:.4}"
                );
            }
            P2PEvent::ResourceRequestFailed { peer_id, reason } => {
                println!("❌ Resource request failed {peer_id}: {reason}");
            }
            P2PEvent::IdentityAttestationVerified { peer_id, did } => {
                println!("🔐 Identity attestation verified {peer_id}: {did}");
            }
            P2PEvent::RelayReservationAccepted { relay_peer_id } => {
                println!("🔌 Relay reservation accepted: {relay_peer_id}");
            }
            P2PEvent::RelayConnectionUpgraded { peer_id } => {
                println!("🔨 Direct connection upgraded (hole punch): {peer_id}");
            }
        }
    }

    println!("\nEvent channel closed. Goodbye.");
    Ok(())
}
