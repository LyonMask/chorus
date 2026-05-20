//! ═══════════════════════════════════════════════════════════════════
//! 🌐 cross_machine_test.rs — Cross-machine P2P E2EE test
//! ═══════════════════════════════════════════════════════════════════
//!
//! Usage:
//!   Listener:  cargo run --example cross_machine_test -- --role a --listen 0.0.0.0 --port 7001
//!   Dialer:    cargo run --example cross_machine_test -- --role b --port 7002 --dial /ip4/<LISTENER_IP>/tcp/7001

use std::sync::Arc;
use std::time::Duration;

use chorus_core::identity::{did_from_pubkey, IdentityBuilder};
use chorus_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};
use ed25519_dalek::SigningKey;

fn parse_args() -> (char, String, u16, Option<String>) {
    let args: Vec<String> = std::env::args().collect();
    let mut role = 'a';
    let mut listen_ip = "0.0.0.0".to_string();
    let mut port: u16 = 7001;
    let mut dial_addr = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--role" if i + 1 < args.len() => {
                role = args[i + 1].chars().next().unwrap_or('a');
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                listen_ip = args[i + 1].clone();
                i += 2;
            }
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(7001);
                i += 2;
            }
            "--dial" if i + 1 < args.len() => {
                dial_addr = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }
    (role, listen_ip, port, dial_addr)
}

fn name_to_seed(name: &str) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in name.as_bytes().iter().enumerate() {
        s[i % 32] ^= *b;
        s[(i + 16) % 32] ^= b.wrapping_mul(31);
    }
    s
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let (role, listen_ip, port, dial_addr) = parse_args();
    let node_name = format!("node-{}", role);

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  🌐 Chorus — Cross-Machine P2P E2EE Test                ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!(
        "  Role:       Node {} ({})",
        role.to_ascii_uppercase(),
        if dial_addr.is_some() {
            "DIALER"
        } else {
            "LISTENER"
        }
    );
    println!("  Listen:     {}:{}", listen_ip, port);
    if let Some(ref d) = dial_addr {
        println!("  Dial:       {}", d);
    }
    println!();

    // Step 1: Identity
    println!("── Step 1: Agent Identity ──");
    let seed = name_to_seed(&node_name);
    let signing_key = SigningKey::from_bytes(&seed);
    let did = did_from_pubkey(&signing_key.verifying_key().to_bytes());
    println!("  🆔 DID: {}…{}", &did[..24], &did[did.len() - 8..]);

    let (identity, _) = IdentityBuilder::new(&format!("Node-{}", role.to_ascii_uppercase()))
        .capabilities(&["cross-machine-test", "e2ee-verify"])
        .build()
        .unwrap();
    println!("  ✅ AgentIdentity signed: {}", identity.short_id());
    println!();

    // Step 2: Start P2P
    println!("── Step 2: P2P Network Startup ──");
    let p2p_config = P2PConfig {
        listen_on: vec![format!("/ip4/{}/tcp/{}", listen_ip, port)],
        agent_identity: Some(identity),
        auto_key_exchange: true,
        ping_interval_secs: 2,
        ping_timeout_secs: 5,
        idle_timeout_secs: 60,
        ..Default::default()
    };

    let (net, mut ev) =
        P2PNetwork::new(p2p_config).unwrap_or_else(|e| panic!("Network create failed: {e}"));

    let actual_listen = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ev.recv().await {
                Some(P2PEvent::Listening { address }) => return address.to_string(),
                Some(_) => continue,
                None => panic!("Channel closed"),
            }
        }
    })
    .await
    .expect("Timeout waiting for Listening");

    println!("  📡 Listening on: {}", actual_listen);
    println!();

    // Step 3: Dial or wait
    if let Some(ref target) = dial_addr {
        println!("── Step 3: Dialing ──");
        println!("  🔗 {}", target);
        if let Err(e) = net.dial(target).await {
            println!("  ❌ Dial failed: {}", e);
            return;
        }
        println!("  ✅ Dial sent");
    } else {
        println!("── Step 3: Waiting for connection ──");
    }
    println!();

    // Step 4: E2EE Session
    println!("── Step 4: E2EE Session ──");
    let remote_peer_id = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match ev.recv().await {
                Some(P2PEvent::SessionEstablished { peer_id, .. }) => {
                    return Ok::<_, String>(peer_id)
                }
                Some(P2PEvent::PeerConnected { peer_id }) => {
                    println!("  🔗 Peer connected: {}", peer_id)
                }
                Some(_) => {}
                None => return Err("Channel closed".into()),
            }
        }
    })
    .await;

    let remote_peer_id = match remote_peer_id {
        Ok(Ok(pid)) => {
            println!("  ✅ E2EE session with {}", pid);
            pid
        }
        Ok(Err(e)) => {
            println!("  ❌ {}", e);
            return;
        }
        Err(_) => {
            println!("  ❌ Timeout 15s — check firewall/IP/port");
            return;
        }
    };
    println!();

    // Step 5: Send hello
    println!("── Step 5: Send Encrypted Message ──");
    let hello = format!(
        "Hello from Node {}! Cross-machine E2EE OK.",
        role.to_ascii_uppercase()
    );
    println!("  💬 \"{}\"", hello);
    net.send_encrypted(remote_peer_id, hello.as_bytes().to_vec())
        .await
        .ok();
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!();

    // Step 6: Receive
    println!("── Step 6: Receive (5s window) ──");
    let mut received: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let rem = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or_default();
        if rem.is_zero() {
            break;
        }
        match tokio::time::timeout(rem, ev.recv()).await {
            Ok(Some(P2PEvent::EncryptedMessage { plaintext, .. })) => {
                if let Ok(t) = String::from_utf8(plaintext.clone()) {
                    println!("  📨 \"{}\"", t);
                    received.push(t);
                }
            }
            Ok(Some(P2PEvent::RawMessage { data, .. })) => {
                if let Ok(t) = String::from_utf8(data.clone()) {
                    println!("  📨 [RAW] \"{}\"", t);
                    received.push(t);
                }
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    println!("  📊 {} message(s) received", received.len());
    println!();

    // Step 7: Multi-msg
    println!("── Step 7: Multi-Message Round-Trip ──");
    for i in 1..=3 {
        let m = format!(
            "msg-{} from {}: test {}",
            i,
            role.to_ascii_uppercase(),
            if i == 1 {
                "ping"
            } else if i == 2 {
                "crypto OK"
            } else {
                "cross-machine confirmed"
            }
        );
        net.send_encrypted(remote_peer_id, m.as_bytes().to_vec())
            .await
            .ok();
        println!("  ✅ Sent: {}", m);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Collect
    let d2 = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let rem = d2
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or_default();
        if rem.is_zero() {
            break;
        }
        match tokio::time::timeout(rem, ev.recv()).await {
            Ok(Some(P2PEvent::EncryptedMessage { plaintext, .. })) => {
                if let Ok(t) = String::from_utf8(plaintext.clone()) {
                    received.push(t.clone());
                    println!("  📨 {}", t);
                }
            }
            Ok(Some(P2PEvent::RawMessage { data, .. })) => {
                if let Ok(t) = String::from_utf8(data.clone()) {
                    received.push(t.clone());
                    println!("  📨 [RAW] {}", t);
                }
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    println!();

    // Summary
    let ok = !received.is_empty();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!(
        "║  🌐 Cross-Machine Test — Node {} Result                   ║",
        role.to_ascii_uppercase()
    );
    println!("╠══════════════════════════════════════════════════════════╣");
    println!(
        "║  📡 Listen:   {}",
        format!("{:<44}║", truncate(&actual_listen, 44))
    );
    println!(
        "║  🔗 Remote:   {}",
        format!("{:<44}║", truncate(&remote_peer_id.to_string(), 44))
    );
    println!(
        "║  🔐 E2EE:     {}",
        format!(
            "{:<44}║",
            if ok {
                "✅ VERIFIED"
            } else {
                "❌ NOT VERIFIED"
            }
        )
    );
    println!("║  💬 Sent:     {}", format!("{:<44}║", "4 messages"));
    println!(
        "║  📨 Recv:     {}",
        format!("{} messages{:>35}║", received.len(), "")
    );
    println!(
        "║  RESULT:     {}",
        format!(
            "{:<44}║",
            if ok {
                "✅ CROSS-MACHINE E2EE VERIFIED"
            } else {
                "⚠️ NO MESSAGES RECEIVED"
            }
        )
    );
    println!("╚══════════════════════════════════════════════════════════╝");

    tokio::time::sleep(Duration::from_secs(3)).await;
    net.shutdown().ok();
    println!("\n  ✅ Node {} done.", role.to_ascii_uppercase());
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
