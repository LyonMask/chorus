//! Encrypted P2P Chat — Chorus Core (Phase D)
//!
//! Two nodes with **automatic E2EE**: key exchange happens on connect,
//! all messages are transparently encrypted/decrypted by P2PNetwork.
//!
//! ```bash
//! # Terminal 1 — Node A
//! cargo run --example encrypted_chat
//!
//! # Terminal 2 — Node B (paste Node A's address)
//! cargo run --example encrypted_chat -- /ip4/127.0.0.1/tcp/<PORT>
//! ```

use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Notify;

use chorus_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

fn hms() -> String {
    let s = now_ms() / 1000;
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .with_thread_ids(false)
        .init();

    let remote_addr = std::env::args().nth(1);

    let (network, mut events) = P2PNetwork::new(P2PConfig {
        bootstrap_peers: remote_addr
            .as_ref()
            .map(|a| vec![a.clone()])
            .unwrap_or_default(),
        auto_key_exchange: true,
        ..Default::default()
    })?;

    let peer_id = network.local_peer_id().to_string();
    let my_short = short(&peer_id);

    println!();
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║   🔐 Chorus — Encrypted P2P Chat         ║");
    println!("╠═══════════════════════════════════════════════════╣");
    println!("║  Peer   : {my_short}...                            ║");
    println!("║  Crypto : X25519 + ChaCha20-Poly1305             ║");
    println!("║  E2EE   : Automatic on connect                   ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!();
    println!("Commands: /peers  /sessions  /quit");
    println!("Type anything else to send encrypted message.");
    println!();

    // Signal: at least one encrypted session exists
    let session_ready = Arc::new(Notify::new());
    let has_session = Arc::new(AtomicBool::new(false));

    // ── Stdin handler ──
    let net_in = network.clone();
    let ready = session_ready.clone();
    let has_sess = has_session.clone();

    tokio::spawn(async move {
        // Wait for at least one session before accepting input
        ready.notified().await;
        println!("🔐 Session ready. You can now type messages.");
        println!();

        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let text = line.trim().to_string();
            if text.is_empty() { continue; }

            match text.as_str() {
                "/quit" | "/q" => { let _ = net_in.shutdown(); break; }
                "/peers" => {
                    match net_in.list_peers().await {
                        Ok(peers) => {
                            println!("Connected peers ({}):", peers.len());
                            for p in &peers {
                                let ok = net_in.has_session(p).await.unwrap_or(false);
                                let icon = if ok { "🔒" } else { "🔓" };
                                println!("  {icon} {}", short(&p.to_string()));
                            }
                        }
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "/sessions" => {
                    match net_in.list_peers().await {
                        Ok(peers) => {
                            let mut n = 0;
                            for p in &peers {
                                if net_in.has_session(p).await.unwrap_or(false) {
                                    println!("  🔒 {} — active", short(&p.to_string()));
                                    n += 1;
                                }
                            }
                            if n == 0 { println!("No encrypted sessions."); }
                        }
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                _ => {
                    match net_in.list_peers().await {
                        Ok(peers) => {
                            let mut sent = 0;
                            for p in &peers {
                                if net_in.has_session(p).await.unwrap_or(false) {
                                    let payload = format!("{}|{}", now_ms(), text);
                                    match net_in.send_encrypted(*p, payload.into_bytes()).await {
                                        Ok(_) => { sent += 1; }
                                        Err(e) => eprintln!("Encrypt error: {e}"),
                                    }
                                }
                            }
                            if sent > 0 {
                                let ts = hms();
                                println!(">> [{ts}] {my_short}: {text}  (encrypted, {sent} peer(s))");
                            } else if !has_sess.load(Ordering::Relaxed) {
                                println!("⚠ No encrypted session yet. Waiting...");
                            }
                        }
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
            }
        }
    });

    // ── Event loop ──
    while let Some(event) = events.recv().await {
        match event {
            P2PEvent::Listening { address } => {
                println!("🎧 Listening on: {address}");
                if remote_addr.is_none() {
                    println!("   Share: cargo run --example encrypted_chat -- {address}");
                    println!();
                }
            }
            P2PEvent::PeerConnected { peer_id } => {
                println!("+ Connected: {}...", short(&peer_id.to_string()));
                println!("  ⏳ Key exchange in progress...");
            }
            P2PEvent::PeerDisconnected { peer_id } => {
                println!("- Disconnected: {}...", short(&peer_id.to_string()));
            }
            P2PEvent::PeerDiscovered { peer_id, .. } => {
                println!("📡 Discovered: {}...", short(&peer_id.to_string()));
            }
            P2PEvent::SessionEstablished { peer_id } => {
                println!("🔒 Secure session: {}...", short(&peer_id.to_string()));
                if !has_session.load(Ordering::Relaxed) {
                    has_session.store(true, Ordering::Relaxed);
                    session_ready.notify_one();
                }
            }
            P2PEvent::SessionFailed { peer_id, reason } => {
                println!("❌ Session failed with {}...: {reason}", short(&peer_id.to_string()));
            }
            P2PEvent::Identify { peer_id, info } => {
                println!("ℹ️  {} is: {}", short(&peer_id.to_string()), info.agent_version);
            }
            P2PEvent::EncryptedMessage { from, plaintext } => {
                let raw = String::from_utf8_lossy(&plaintext);
                let display = if let Some(pos) = raw.find('|') {
                    &raw[pos + 1..]
                } else {
                    &raw
                };
                let ts = hms();
                let peer_short = short(&from.to_string());
                println!("[{ts}] 🔒 {peer_short}: {}", display.trim());
            }
            P2PEvent::RawMessage { from, data } => {
                let text = String::from_utf8_lossy(&data);
                println!("📡 [raw] {}: {}", short(&from.to_string()), text);
            }
            P2PEvent::AgentIdentified { peer_id, identity } => {
                let _ts = hms();
                let caps = identity.capabilities.join(", ");
                println!("[{}] 🪪 {} is {} [{}]", hms(), short(&peer_id.to_string()), identity.display_name, caps);
            }
            P2PEvent::IdentityVerificationFailed { peer_id: _, reason } => {
                println!("❌ Identity fail: {reason}");
            }
            P2PEvent::StructuredMessage { from, message } => {
                println!("📋 {} [{}]: {}", short(&from.to_string()), message.protocol.tag(), message.summary());
            }
            P2PEvent::PingFailure { peer_id, error } => {
                println!("🏓 Ping FAIL {}: {}", short(&peer_id.to_string()), error);
            }
            _ => {}
        }
    }

    println!("\nGoodbye.");
    Ok(())
}
