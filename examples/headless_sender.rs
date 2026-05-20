//! headless_sender — Connect to a peer and send messages, log everything
//!
//! Usage: cargo run --example headless_sender -- <multiaddr> <message1> <message2> ...

use chorus_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info,libp2p=warn")
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("Usage: headless_sender <multiaddr> <message1> [message2...]");
        std::process::exit(1);
    }

    let target_addr = &args[0];
    let messages = &args[1..];

    let cfg = P2PConfig {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".into()],
        auto_key_exchange: true,
        ..Default::default()
    };

    let (net, mut ev) = P2PNetwork::new(cfg)?;
    let net = Arc::new(net);

    eprintln!("🎤 Sender started, dialing {}...", target_addr);
    net.dial(target_addr).await?;

    // Wait for E2EE
    let target_peer = Arc::new(std::sync::Mutex::new(None::<libp2p::PeerId>));
    let _tp = target_peer.clone();
    let e2ee_ready = Arc::new(tokio::sync::Notify::new());

    let tp2 = target_peer.clone();
    let e2ee2 = e2ee_ready.clone();
    tokio::spawn(async move {
        while let Some(e) = ev.recv().await {
            match &e {
                P2PEvent::Listening { address } => eprintln!("🎧 Listening: {}", address),
                P2PEvent::PeerConnected { peer_id } => {
                    eprintln!("🟢 Connected: {}", peer_id);
                    *tp2.lock().unwrap() = Some(*peer_id);
                }
                P2PEvent::SessionEstablished { peer_id } => {
                    eprintln!("🔐 E2EE with {}", peer_id);
                    e2ee2.notify_one();
                }
                P2PEvent::EncryptedMessage { from: _, plaintext } => {
                    let text = String::from_utf8_lossy(plaintext);
                    println!("RECEIVED|{}|{}", chrono_now(), text);
                }
                P2PEvent::AgentIdentified { identity, .. } => {
                    eprintln!("🪪 {}", identity.display_name);
                }
                _ => {}
            }
        }
    });

    // Wait for E2EE or timeout
    tokio::select! {
        _ = e2ee_ready.notified() => {}
        _ = tokio::time::sleep(std::time::Duration::from_secs(20)) => {
            eprintln!("⚠️ E2EE timeout after 20s");
        }
    }

    let peer = *target_peer.lock().unwrap();
    match peer {
        Some(pid) => {
            for msg in messages {
                eprintln!("📤 Sending: {}", msg);
                let send_ts = chrono_now();
                match net.send_encrypted(pid, msg.as_bytes().to_vec()).await {
                    Ok(()) => println!("SENT|{}|{}", send_ts, msg),
                    Err(e) => eprintln!("❌ Send failed: {}", e),
                }
                // Wait for response
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            }
        }
        None => eprintln!("❌ No peer connected"),
    }

    // Wait a bit more for any late responses
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    eprintln!("✅ Done");
    Ok(())
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let s = ms / 1000;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        (s / 3600) % 24,
        (s / 60) % 60,
        s % 60,
        ms % 1000
    )
}
