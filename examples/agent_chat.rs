#![allow(dead_code)]
//! 🤖 agent_chat.rs — Layer 0-2 Integration POC
//!
//! 3 AI Agents collaborate to complete a code review task:
//!   Agent Alice (Coordinator) → assigns task to Agent Rustacean
//!   Agent Rustacean (Worker)   → does the work, returns result
//!   Agent Bridge (Reviewer)    → reviews the result, reports to human
//!
//! Usage:
//!   Terminal 1: cargo run --example agent_chat -- Alice
//!   Terminal 2: cargo run --example agent_chat -- Rustacean <addr1>
//!   Terminal 3: cargo run --example agent_chat -- Bridge <addr1> <addr2>
//!
//! Or for quick demo (single process, 3 agents):
//!   cargo run --example agent_chat -- demo

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::io::AsyncBufReadExt;

use chorus_core::identity::{AgentIdentity, IdentityBuilder};
use chorus_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};
use chorus_core::protocol::{AgentMessage, MessageProtocol};

// ─── Agent Role ─────────────────────────────────────────────────

struct Agent {
    identity: AgentIdentity,
    network: P2PNetwork,
    known_agents: Arc<Mutex<HashMap<String, AgentIdentity>>>,
    role: String,
}

impl Agent {
    fn short_id(&self) -> String {
        self.identity.short_id()
    }

    fn display_name(&self) -> &str {
        &self.identity.display_name
    }

    async fn broadcast_msg(&self, msg: &AgentMessage) -> anyhow::Result<()> {
        self.network.broadcast(msg.to_json_bytes()?).await?;
        Ok(())
    }

    async fn send_to(&self, peer_id: &libp2p::PeerId, msg: &AgentMessage) -> anyhow::Result<()> {
        self.network.send_encrypted(*peer_id, msg.to_json_bytes()?).await
    }
}

// ─── Create Agent ───────────────────────────────────────────────

async fn create_agent(name: &str, capabilities: &[&str], role: &str) -> Result<(Agent, tokio::sync::mpsc::UnboundedReceiver<P2PEvent>), Box<dyn Error>> {
    let (identity, _signing_key) = IdentityBuilder::new(name)
        .capabilities(capabilities)
        .version("chorus-core/0.1.0-alpha")
        .build()?;

    let config = P2PConfig {
        agent_identity: Some(identity.clone()),
        auto_key_exchange: true,
        ..Default::default()
    };

    let (network, event_rx) = P2PNetwork::new(config)?;

    Ok((Agent {
        identity,
        network,
        known_agents: Arc::new(Mutex::new(HashMap::new())),
        role: role.to_string(),
    }, event_rx))
}

// ─── Human-Readable Formatter ───────────────────────────────────

fn format_message(msg: &AgentMessage) -> String {
    let from = &msg.from_agent.display_name;
    let short_from = &msg.from_agent.short_id();
    let to = if msg.to_agent.is_empty() { "ALL" } else { &msg.to_agent };

    match msg.protocol {
        MessageProtocol::Heartbeat => {
            let status = msg.payload_str("status").unwrap_or("?");
            let load = msg.payload_str("load").unwrap_or("?");
            format!("  💚 [{}] heartbeat: {} (load {})", short_from, status, load)
        }
        MessageProtocol::TaskAssignment => {
            let task = msg.payload_str("task").unwrap_or("?");
            format!("  📋 [{}] → [{}] TASK: {}", from, to, task)
        }
        MessageProtocol::StatusReport => {
            let status = msg.payload_str("status").unwrap_or("?");
            let pct = msg.payload_i64("percent").unwrap_or(0);
            let note = msg.payload_str("note").unwrap_or("");
            if note.is_empty() {
                format!("  📊 [{}] STATUS: {} ({}%)", from, status, pct)
            } else {
                format!("  📊 [{}] STATUS: {} ({}%) — {}", from, status, pct, note)
            }
        }
        MessageProtocol::DataExchange => {
            let text = msg.payload_str("text");
            if let Some(t) = text {
                format!("  💬 [{}]: \"{}\"", from, t)
            } else {
                format!("  📦 [{}] → [{}] DATA exchange", from, to)
            }
        }
        MessageProtocol::IntentNegotiation => {
            let action = msg.payload_str("action").unwrap_or("?");
            format!("  🤝 [{}] INTENT: {}", from, action)
        }
        MessageProtocol::HumanHandoff => {
            let reason = msg.payload_str("reason").unwrap_or("?");
            let summary = msg.payload_str("summary").unwrap_or("");
            format!("  🚨 [{}] HUMAN NEEDED: {} — {}", from, reason, summary)
        }
    }
}

// ─── Visual Separator ───────────────────────────────────────────

fn separator() {
    println!("{}", "─".repeat(60));
}

fn header(title: &str) {
    separator();
    println!("  {}", title);
    separator();
}

// ─── Main ───────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Parse mode
    match args.get(1).map(|s| s.as_str()) {
        Some("demo") => run_demo().await,
        Some(name) => run_interactive(name, &args[2..]).await,
        None => {
            println!("Usage:");
            println!("  cargo run --example agent_chat -- demo         # Auto 3-agent demo");
            println!("  cargo run --example agent_chat -- <name>       # Interactive mode");
            println!("  cargo run --example agent_chat -- <name> <addr> # Connect to peer");
            println!();
            println!("Demo roles:");
            println!("  Alice (Coordinator) — assigns tasks, orchestrates");
            println!("  Rustacean (Worker)   — does code review work");
            println!("  Bridge (Reviewer)    — reviews results, reports to human");
            Ok(())
        }
    }
}

// ─── Demo Mode (3 agents in 1 process) ─────────────────────────

async fn run_demo() -> Result<(), Box<dyn Error>> {
    // Minimal logging for demo
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .init();

    header("🤖 Walkie Talkie — 3-Agent Collaboration Demo");
    println!("  Layer 0: P2P + E2EE (libp2p + X25519 + ChaCha20)");
    println!("  Layer 1: Agent Identity (Ed25519 DID)");
    println!("  Layer 2: Structured Messaging (6 message types)");
    println!();

    // Create 3 agents
    println!("[SETUP] Creating 3 agents...");

    let (alice, mut alice_rx) = create_agent("Alice", &["coordinate", "strategy"], "Coordinator").await?;
    let (rustacean, _rustacean_rx) = create_agent("Rustacean", &["code-review", "crypto", "p2p"], "Worker").await?;
    let (bridge, _bridge_rx) = create_agent("Bridge", &["product", "review", "human-handoff"], "Reviewer").await?;

    println!();
    println!("  Alice (Coordinator)     did:{}", alice.short_id());
    println!("  🦀 Rustacean (Worker)      did:{}", rustacean.short_id());
    println!("  🌉 Bridge (Reviewer)       did:{}", bridge.short_id());
    println!();

    // Start listening
    println!("[SETUP] Starting P2P networks...");
    alice.network.listen("/ip4/127.0.0.1/tcp/0").await?;
    rustacean.network.listen("/ip4/127.0.0.1/tcp/0").await?;
    bridge.network.listen("/ip4/127.0.0.1/tcp/0").await?;

    // Wait for Listening events to get actual addresses
    let mut alice_listen_addr = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if let Ok(P2PEvent::Listening { address }) = alice_rx.try_recv() {
            let addr_str = address.to_string();
            if addr_str.contains("127.0.0.1") || addr_str.contains("0.0.0.0") {
                let local_addr = addr_str.replace("0.0.0.0", "127.0.0.1");
                alice_listen_addr = Some(local_addr);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let alice_addr = alice_listen_addr.unwrap_or_else(|| {
        // Fallback: construct from local_peer_id
        format!("/ip4/127.0.0.1/tcp/0/p2p/{}", alice.network.local_peer_id())
    });
    println!("  Alice listening on: {}", alice_addr);
    println!();

    // Connect all agents to (hub topology)
    println!("[SETUP] Connecting agents (star topology)...");

    // Connect Rustacean and Bridge to Alice
    rustacean.network.dial(&alice_addr).await?;
    bridge.network.dial(&alice_addr).await?;

    // Wait for connections
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("[SETUP] Network established ✓");
    println!();

    // ═══════════════════════════════════════════════════════════
    // SCENARIO: Alice orchestrates a code review via Rustacean,
    //           Bridge reviews the result and reports to human.
    // ═══════════════════════════════════════════════════════════

    header("📋 SCENARIO: Code Review Task");

    // Track messages across all agents
    let all_messages = Arc::new(Mutex::new(Vec::new()));
    let task_id = Arc::new(Mutex::new(None::<String>));
    let result_received = Arc::new(Mutex::new(false));

    // Clone for task closure
    let all_msgs1 = all_messages.clone();
    let _task_id1 = task_id.clone();
    let _result_received1 = result_received.clone();

    // --- Alice sends heartbeat ---
    println!();
    println!("[STEP 1] Alice broadcasts heartbeat");
    let hb = AgentMessage::heartbeat(&alice.identity, "online", 0.0);
    alice.broadcast_msg(&hb).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Alice assigns task to Rustacean ---
    println!("[STEP 2] Alice assigns code-review task to Rustacean");
    let task_msg = AgentMessage::task(
        &alice.identity,
        "code-review",
        serde_json::json!({
            "target": "src/crypto/mod.rs",
            "focus": ["security", "performance"],
            "deadline_ms": 10000
        }),
    )
    .to(&rustacean.identity.agent_id)
    .priority(chorus_core::protocol::Priority::HIGH);

    let tid = task_msg.id.clone();
    *task_id.lock().await = Some(tid.as_str().to_string());
    alice.broadcast_msg(&task_msg).await?;
    all_msgs1.lock().await.push(task_msg.summary());
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Rustacean receives task, sends status ---
    println!("[STEP 3] 🦀 Rustacean acknowledges, starts working");
    let status1 = AgentMessage::status(
        &rustacean.identity,
        "in_progress",
        0,
        "Received task, starting analysis of crypto module",
    )
    .to(&alice.identity.agent_id)
    .reply_to(&tid);
    rustacean.broadcast_msg(&status1).await?;
    all_msgs1.lock().await.push(status1.summary());
    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- Rustacean sends progress ---
    println!("[STEP 4] 🦀 Rustacean reports 50% progress");
    let status2 = AgentMessage::status(
        &rustacean.identity,
        "in_progress",
        50,
        "Checking encryption layer... nonce reuse concern found",
    )
    .to(&alice.identity.agent_id)
    .reply_to(&tid);
    rustacean.broadcast_msg(&status2).await?;
    all_msgs1.lock().await.push(status2.summary());
    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- Rustacean completes, sends result ---
    println!("[STEP 5] 🦀 Rustacean completes, sends result");
    let result = AgentMessage::data(
        &rustacean.identity,
        "code-review-result",
        serde_json::json!({
            "file": "src/crypto/mod.rs",
            "issues": [
                {
                    "line": 49,
                    "severity": "info",
                    "message": "Consider using HKDF for key derivation instead of raw DH output"
                },
                {
                    "line": 51,
                    "severity": "warning",
                    "message": "Counter wraps at u64::MAX — add overflow check for long sessions"
                }
            ],
            "verdict": "pass",
            "summary": "2 findings: 1 info, 1 warning. Code is production-ready with minor improvements."
        }),
    )
    .to(&alice.identity.agent_id)
    .reply_to(&tid);
    rustacean.broadcast_msg(&result).await?;
    all_msgs1.lock().await.push(result.summary());
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Rustacean final status ---
    let status_done = AgentMessage::status(
        &rustacean.identity,
        "completed",
        100,
        "Code review complete",
    )
    .to(&alice.identity.agent_id)
    .reply_to(&tid);
    rustacean.broadcast_msg(&status_done).await?;
    all_msgs1.lock().await.push(status_done.summary());
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Alice forwards result to Bridge for review ---
    println!("[STEP 6] Alice forwards result to Bridge for human review");
    let review_task = AgentMessage::task(
        &alice.identity,
        "human-review",
        serde_json::json!({
            "original_task": "code-review",
            "worker": rustacean.display_name(),
            "verdict": "pass",
            "findings_count": 2
        }),
    )
    .to(&bridge.identity.agent_id)
    .reply_to(&tid);
    alice.broadcast_msg(&review_task).await?;
    all_msgs1.lock().await.push(review_task.summary());
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Bridge reviews and reports to human ---
    println!("[STEP 7] 🌉 Bridge reviews and escalates to human");
    let handoff = AgentMessage::human_handoff(
        &bridge.identity,
        "review_complete",
        "Code review passed. 2 minor findings for human review.",
        serde_json::json!({
            "code_reviewer": rustacean.display_name(),
            "verdict": "pass",
            "action_required": "approve or request changes"
        }),
    )
    .reply_to(&tid);
    bridge.broadcast_msg(&handoff).await?;
    all_msgs1.lock().await.push(handoff.summary());
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Bridge final summary ---
    println!("[STEP 8] 🌉 Bridge sends final summary");
    let summary = AgentMessage::text(
        &bridge.identity,
        "📋 Task Complete: Code review of crypto/mod.rs\n  ✅ Reviewer: Rustacean\n  ✅ Verdict: PASS\n  ⚠️  2 findings (1 info, 1 warning)\n  👤 Awaiting human approval",
    );
    bridge.broadcast_msg(&summary).await?;
    all_msgs1.lock().await.push(summary.summary());
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ═══════════════════════════════════════════════════════════
    // RESULTS
    // ═══════════════════════════════════════════════════════════

    header("📊 HUMAN VIEW — Agent Collaboration Timeline");

    let msgs = all_msgs1.lock().await;
    for (i, msg) in msgs.iter().enumerate() {
        println!("{:>2}. {}", i + 1, msg);
    }

    println!();
    header("✅ DEMO COMPLETE");

    println!("  3 Agents × 6 Message Types × 8 Steps");
    println!("  Layer 0: P2P mesh via libp2p Gossipsub");
    println!("  Layer 1: Ed25519 DID identity verified");
    println!("  Layer 2: Task → Status → Result → Handoff");
    println!();
    println!("  💡 This is what the human sees in Layer 3:");
    println!("     A timeline of agent interactions, with ability to intervene.");
    println!();

    // Cleanup
    alice.network.shutdown()?;
    rustacean.network.shutdown()?;
    bridge.network.shutdown()?;

    Ok(())
}

// ─── Interactive Mode ───────────────────────────────────────────

async fn run_interactive(name: &str, peers: &[String]) -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let role = match name {
        "Alice" => ("Coordinator", vec!["coordinate", "strategy"]),
        "Rustacean" => ("Worker", vec!["code-review", "crypto", "p2p"]),
        "Bridge" => ("Reviewer", vec!["product", "review", "human-handoff"]),
        _ => ("Custom", vec!["general"]),
    };

    let (agent, mut rx) = create_agent(name, &role.1, role.0).await?;

    println!("=== 🤖 Agent Chat — {} ({}) ===", name, role.0);
    println!("  DID: {}", agent.identity.agent_id);
    println!("  Capabilities: {:?}", agent.identity.capabilities);
    println!();

    // Listen
    agent.network.listen("/ip4/0.0.0.0/tcp/0").await?;

    // Connect to peers
    for peer_addr in peers {
        println!("  Connecting to {}...", peer_addr);
        agent.network.dial(peer_addr).await?;
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Print human-readable view
    header(&format!("🤖 {} is now online", name));
    println!("  Type 'help' for commands");
    println!();

    // Event loop
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();

    loop {
        tokio::select! {
            // Handle P2P events
            event = rx.recv() => {
                if let Some(event) = event {
                    match event {
                        P2PEvent::Listening { address } => {
                            println!("  📡 Listening on: {}", address);
                        }
                        P2PEvent::PeerConnected { peer_id } => {
                            println!("  🔗 Peer connected: {}", peer_id);
                        }
                        P2PEvent::PeerDisconnected { peer_id } => {
                            println!("  ❌ Peer disconnected: {}", peer_id);
                        }
                        P2PEvent::RawMessage { from: _, data } => {
                            if let Ok(msg) = AgentMessage::from_json_bytes(&data) {
                                println!("{}", format_message(&msg));
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Handle stdin
            line = lines.next_line() => {
                match line {
                    Ok(Some(input)) if !input.trim().is_empty() => {
                        let input = input.trim();
                        let parts: Vec<&str> = input.splitn(2, ' ').collect();
                        match parts[0] {
                            "help" => {
                                println!("Commands:");
                                println!("  task <agent> <name> [json]  — Assign task");
                                println!("  status <status> [pct] [note] — Send status");
                                println!("  text <message>              — Send text");
                                println!("  data <schema> <json>        — Send data");
                                println!("  handoff <reason> <summary>  — Escalate to human");
                                println!("  hb [load]                   — Send heartbeat");
                                println!("  agents                      — List connected peers");
                                println!("  quit                        — Exit");
                            }
                            "task" => {
                                if parts.len() < 3 {
                                    println!("Usage: task <agent> <name> [json]");
                                    continue;
                                }
                                let msg = AgentMessage::task(
                                    &agent.identity, parts[1], serde_json::json!({})
                                );
                                if parts.len() > 3 {
                                    // rebuild with extra json
                                }
                                agent.broadcast_msg(&msg).await?;
                                println!("  📋 Task sent: {}", parts[1]);
                            }
                            "status" => {
                                let status = parts.get(1).unwrap_or(&"ok");
                                let pct: u8 = parts.get(2).unwrap_or(&"100").parse().unwrap_or(100);
                                let note = parts.get(3).unwrap_or(&"");
                                let msg = AgentMessage::status(&agent.identity, status, pct, note);
                                agent.broadcast_msg(&msg).await?;
                                println!("  📊 Status sent: {} ({}%)", status, pct);
                            }
                            "text" => {
                                let text = parts.get(1).unwrap_or(&"");
                                let msg = AgentMessage::text(&agent.identity, text);
                                agent.broadcast_msg(&msg).await?;
                                println!("  💬 Text sent");
                            }
                            "hb" => {
                                let load: f32 = parts.get(1).unwrap_or(&"0.0").parse().unwrap_or(0.0);
                                let msg = AgentMessage::heartbeat(&agent.identity, "online", load);
                                agent.broadcast_msg(&msg).await?;
                                println!("  💚 Heartbeat sent (load {})", load);
                            }
                            "agents" => {
                                let peers = agent.network.list_peers().await?;
                                println!("  Connected peers: {}", peers.len());
                                for p in &peers {
                                    println!("    - {}", p);
                                }
                            }
                            "quit" => {
                                println!("  Shutting down...");
                                agent.network.shutdown()?;
                                break;
                            }
                            _ => {
                                println!("  Unknown command. Type 'help'.");
                            }
                        }
                    }
                    _ => break,
                }
            }
        }
    }

    Ok(())
}
