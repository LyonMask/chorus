//! Agent Task POC — Layer 2 Structured Messaging
//!
//! Demonstrates AI Agent structured interaction:
//!   1. Create cryptographic identity (Ed25519 DID)
//!   2. Connect via P2P network
//!   3. Exchange structured messages (Task, Intent, Status, Data)
//!   4. Auto-reply pattern (accept tasks, respond to intents)
//!
//! Usage:
//!   Terminal 1:  cargo run --example agent_task
//!   Terminal 2:  cargo run --example agent_task -- <multiaddr>

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

use walkie_talkie_core::identity::{AgentIdentity, IdentityBuilder, IdentityEnvelope};
use walkie_talkie_core::protocol::{AgentMessage, MessageProtocol};
use walkie_talkie_core::p2p::{P2PEvent, P2PNetwork};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // ── Create agent identity ──────────────────────────────────
    let (my_identity, _signing_key) = IdentityBuilder::new("Steve")
        .capabilities(&["code-review", "architecture"])
        .build()?;

    println!("╔══════════════════════════════════════════╗");
    println!("║   Agent Task POC — Walkie Talkie v4     ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("  Agent ID:     {}", my_identity.short_id());
    println!("  Display:      {}", my_identity.display_name);
    println!("  Capabilities: {:?}", my_identity.capabilities);
    println!("  DID:          {}", my_identity.agent_id);
    println!();

    // ── Create P2P network ────────────────────────────────────
    let (network, mut event_rx) = P2PNetwork::new_default()?;
    network.listen("/ip4/0.0.0.0/tcp/0").await?;

    // Dial a peer if address provided
    if let Some(addr) = std::env::args().nth(1) {
        println!("  Dialing {}...", addr);
        network.dial(&addr).await?;
    }

    // Track discovered agents: peer_id_string -> AgentIdentity
    let known_agents: Arc<Mutex<HashMap<String, AgentIdentity>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // ── Spawn stdin handler ───────────────────────────────────
    let net_in = network.clone();
    let net_shutdown = network.clone();
    let agents_in = known_agents.clone();
    let my_id = my_identity.clone();

    tokio::spawn(async move {
        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();

        println!("  Type 'help' for commands.\n");

        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim().to_string();
            if line.is_empty() { continue; }
            let parts: Vec<&str> = line.split_whitespace().collect();

            match parts.first().copied() {
                Some("task") => {
                    // task <name> [json_params]
                    if parts.len() < 2 {
                        println!("  Usage: task <name> [json_params]");
                        continue;
                    }
                    let task_name = parts[1];
                    let params: serde_json::Value = if parts.len() > 2 {
                        serde_json::from_str(&parts[2..].join(" ")).unwrap_or(serde_json::json!({}))
                    } else {
                        serde_json::json!({})
                    };
                    let msg = AgentMessage::task(&my_id, task_name, params);
                    println!("  [TASK→] {} — {}", my_id.display_name, task_name);
                    if let Ok(bytes) = msg.to_json_bytes() {
                        let _ = net_in.broadcast(bytes).await;
                    }
                }

                Some("status") => {
                    // status <status_text> [percent] [note]
                    if parts.len() < 2 {
                        println!("  Usage: status <status_text> [percent] [note]");
                        continue;
                    }
                    let status = parts[1];
                    let pct: u8 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let note = if parts.len() > 3 { parts[3..].join(" ") } else { String::new() };
                    let msg = AgentMessage::status(&my_id, status, pct, &note);
                    println!("  [STATUS→] {} — {}%", my_id.display_name, pct);
                    if let Ok(bytes) = msg.to_json_bytes() {
                        let _ = net_in.broadcast(bytes).await;
                    }
                }

                Some("intent") => {
                    // intent <action> <json_params>
                    if parts.len() < 2 {
                        println!("  Usage: intent <action> [json_params]");
                        continue;
                    }
                    let action = parts[1];
                    let params: serde_json::Value = if parts.len() > 2 {
                        serde_json::from_str(&parts[2..].join(" ")).unwrap_or(serde_json::json!({}))
                    } else {
                        serde_json::json!({})
                    };
                    let msg = AgentMessage::intent(&my_id, action, params);
                    println!("  [INTENT→] Can you {}?", action);
                    if let Ok(bytes) = msg.to_json_bytes() {
                        let _ = net_in.broadcast(bytes).await;
                    }
                }

                Some("data") => {
                    // data <format> [json_data]
                    if parts.len() < 2 {
                        println!("  Usage: data <format> [json_data]");
                        continue;
                    }
                    let format = parts[1];
                    let data_val: serde_json::Value = if parts.len() > 2 {
                        serde_json::from_str(&parts[2..].join(" ")).unwrap_or(serde_json::json!({}))
                    } else {
                        serde_json::json!({})
                    };
                    let msg = AgentMessage::data(&my_id, format, data_val);
                    if let Ok(bytes) = msg.to_json_bytes() {
                        let _ = net_in.broadcast(bytes).await;
                    }
                }

                Some("ping") => {
                    let msg = AgentMessage::heartbeat(&my_id, "online", 0.0);
                    if let Ok(bytes) = msg.to_json_bytes() {
                        let _ = net_in.broadcast(bytes).await;
                    }
                    println!("  [PING→] Heartbeat sent.");
                }

                Some("list") => {
                    let agents = agents_in.lock().await;
                    if agents.is_empty() {
                        println!("  No agents discovered yet.");
                    } else {
                        println!("  Discovered Agents:");
                        for (_, identity) in agents.iter() {
                            println!("    {} — {} [{:?}]",
                                identity.short_id(),
                                identity.display_name,
                                identity.capabilities,
                            );
                        }
                    }
                }

                Some("help") => {
                    println!("  ╔══════════════════════════════════════╗");
                    println!("  ║  Agent Task POC Commands             ║");
                    println!("  ╠══════════════════════════════════════╣");
                    println!("  ║  task <name> [json]    ║ Assign task  ║");
                    println!("  ║  status <s> [pct] [n] ║ Report status║");
                    println!("  ║  intent <act> [json]  ║ Negotiate    ║");
                    println!("  ║  data <fmt> [json]    ║ Exchange     ║");
                    println!("  ║  ping                   ║ Heartbeat   ║");
                    println!("  ║  list                   ║ Show agents ║");
                    println!("  ║  quit                   ║ Exit        ║");
                    println!("  ╚══════════════════════════════════════╝");
                }

                Some("quit") | Some("exit") => {
                    println!("  Shutting down...");
                    let _ = net_shutdown.shutdown();
                    break;
                }

                _ => {
                    // Default: plain text message
                    let msg = AgentMessage::text(&my_id, &line);
                    if let Ok(bytes) = msg.to_json_bytes() {
                        let _ = net_in.broadcast(bytes).await;
                    }
                }
            }
        }
    });

    // ── Main event loop ───────────────────────────────────────
    while let Some(event) = event_rx.recv().await {
        match event {
            P2PEvent::Listening { address } => {
                println!("  >> Listening on: {}", address);
            }

            P2PEvent::PeerConnected { peer_id } => {
                println!("  >> Peer connected: {}", peer_id);
                // Broadcast our identity to the new peer
                let envelope = IdentityEnvelope::new(my_identity.clone(), &peer_id.to_string());
                if let Ok(bytes) = serde_json::to_vec(&envelope) {
                    let _ = network.broadcast(bytes).await;
                }
            }

            P2PEvent::PeerDisconnected { peer_id } => {
                println!("  >> Peer disconnected: {}", peer_id);
                known_agents.lock().await.remove(&peer_id.to_string());
            }

            P2PEvent::AgentIdentified { peer_id, identity } => {
                println!("  [IDENTITY✓] {} — {} [{:?}]",
                    identity.short_id(),
                    identity.display_name,
                    identity.capabilities,
                );
                known_agents.lock().await.insert(peer_id.to_string(), identity);
            }

            P2PEvent::IdentityVerificationFailed { peer_id, reason } => {
                println!("  [IDENTITY✗] {}: {}", peer_id, reason);
            }

            P2PEvent::StructuredMessage { from, message } => {
                handle_structured_message(&from, &message, &my_identity, &network).await;
            }

            P2PEvent::RawMessage { from, data } => {
                // Try to parse as identity envelope or agent message
                let from_str = from.to_string();

                if let Ok(envelope) = serde_json::from_slice::<IdentityEnvelope>(&data) {
                    match envelope.verify() {
                        Ok(()) => {
                            let id = &envelope.identity;
                            println!("  [IDENTITY✓] {} — {} [{:?}]",
                                id.short_id(), id.display_name, id.capabilities);
                            known_agents.lock().await.insert(from_str, id.clone());
                        }
                        Err(e) => println!("  [IDENTITY✗] Verification failed: {}", e),
                    }
                } else if let Ok(msg) = AgentMessage::from_json_bytes(&data) {
                    handle_structured_message(&from, &msg, &my_identity, &network).await;
                }
            }

            P2PEvent::EncryptedMessage { from, plaintext } => {
                if let Ok(msg) = AgentMessage::from_json_bytes(&plaintext) {
                    handle_structured_message(&from, &msg, &my_identity, &network).await;
                }
            }

            P2PEvent::SessionEstablished { peer_id } => {
                println!("  [🔒] E2EE session with {}", peer_id);
            }

            P2PEvent::SessionFailed { peer_id, reason } => {
                println!("  [🔒✗] Session with {} failed: {}", peer_id, reason);
            }

            P2PEvent::PeerDiscovered { peer_id, .. } => {
                println!("  [mDNS] Discovered {}", peer_id);
            }

            // Ignore events we don't need to display
            _ => {}
        }
    }

    println!("\n  Terminated. Agents known: {}", known_agents.lock().await.len());
    Ok(())
}

/// Handle incoming structured AgentMessage with auto-reply logic.
async fn handle_structured_message(
    _from: &libp2p::PeerId,
    msg: &AgentMessage,
    my_identity: &AgentIdentity,
    network: &P2PNetwork,
) {
    match msg.protocol {
        MessageProtocol::Heartbeat => {
            if let Some(status) = msg.payload_str("status") {
                let load = msg.payload_object()
                    .and_then(|o| o.get("load").and_then(|v| v.as_f64()))
                    .unwrap_or(0.0);
                println!("  [PING←] {} — {} (load: {:.0}%)",
                    msg.from_agent.display_name, status, load * 100.0);
            }
        }

        MessageProtocol::TaskAssignment => {
            let task = msg.payload_str("task").unwrap_or("?");
            println!("  [TASK←] {} → me: {} — {:?}", msg.from_agent.display_name, task, msg.payload);
            // Auto-reply: accept
            let reply = msg.make_reply(serde_json::json!({
                "status": "accepted",
                "eta_ms": 5000,
            }));
            if let Ok(bytes) = reply.to_json_bytes() {
                let _ = network.broadcast(bytes).await;
            }
            println!("  [TASK→] Auto-accepted: {}", task);
        }

        MessageProtocol::StatusReport => {
            let _status = msg.payload_str("status").unwrap_or("?");
            let pct = msg.payload_i64("percent").unwrap_or(0);
            let note = msg.payload_str("note").unwrap_or("");
            println!("  [STATUS←] {} — {}% — {}", msg.from_agent.display_name, pct, note);
        }

        MessageProtocol::IntentNegotiation => {
            let action = msg.payload_str("action").unwrap_or("?");
            println!("  [INTENT←] {} asks: {} — {:?}", msg.from_agent.display_name, action, msg.payload);
            // Auto-reply if we have the capability mentioned in params
            let can_do = msg.payload_object()
                .and_then(|o| o.get("capability"))
                .and_then(|v| v.as_str())
                .map(|cap| my_identity.has_capability(cap))
                .unwrap_or(true);
            let reply = msg.make_reply(serde_json::json!({
                "can_do": can_do,
                "eta_ms": if can_do { 3000 } else { 0 },
            }));
            if let Ok(bytes) = reply.to_json_bytes() {
                let _ = network.broadcast(bytes).await;
            }
            println!("  [INTENT→] Replied: {}", if can_do { "yes" } else { "no" });
        }

        MessageProtocol::DataExchange => {
            if let Some(text) = msg.payload_str("text") {
                println!("  [TEXT←] {}: {}", msg.from_agent.display_name, text);
            } else {
                println!("  [DATA←] {} sent data: {:?}", msg.from_agent.display_name, msg.payload);
            }
        }

        MessageProtocol::HumanHandoff => {
            let reason = msg.payload_str("reason").unwrap_or("?");
            let summary = msg.payload_str("summary").unwrap_or("");
            println!("  [🚨HUMAN←] {} escalated: {} — {}",
                msg.from_agent.display_name, reason, summary);
        }
    }
}
