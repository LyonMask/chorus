//! 🦀 chorus — Chorus P2P CLI
//!
//! chorus start [--port PORT] [--name NAME] [--relay] [--json]
//! REPL: help | connect | status | chat | peers | quit

use std::collections::HashMap;
use std::sync::Arc;

use chorus_core::identity::IdentityBuilder;
use chorus_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Global flag: when true, output JSON lines instead of human-readable text.
static JSON_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Helper: output a JSON line if in JSON mode, otherwise output normal text.
fn output(json: Option<&str>, text: &str) {
    if JSON_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        if let Some(j) = json {
            println!("{}", j);
        } else {
            println!("{}", serde_json::json!({"type": "info", "text": text}));
        }
    } else {
        println!("{}", text);
    }
}

#[derive(Parser)]
#[command(name = "chorus", version, about = "Chorus P2P CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Start {
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        relay: bool,
        #[arg(long)]
        no_repl: bool,
        #[arg(long = "relay-peer")]
        relay_peers: Vec<String>,
        /// Output JSON lines instead of human-readable text (for MCP/programmatic use).
        #[arg(long)]
        json: bool,
    },
}

struct State {
    net: Arc<P2PNetwork>,
    agent_id: String,
    display_name: String,
    did_map: Arc<std::sync::Mutex<HashMap<String, libp2p::PeerId>>>,
    pid_map: Arc<std::sync::Mutex<HashMap<String, String>>>,
    listen_addr: Arc<std::sync::Mutex<String>>,
}

impl State {
    fn peer_id(&self, did: &str) -> anyhow::Result<libp2p::PeerId> {
        self.did_map
            .lock()
            .unwrap()
            .get(did)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("DID '{}' not connected", did))
    }
    fn label(&self, pid: &libp2p::PeerId) -> String {
        self.pid_map
            .lock()
            .unwrap()
            .get(&pid.to_string())
            .cloned()
            .unwrap_or_else(|| {
                let s = pid.to_string();
                if s.len() > 12 {
                    format!("{}…", &s[..12])
                } else {
                    s
                }
            })
    }
}

fn load_or_create_identity(
    name: &str,
) -> anyhow::Result<(chorus_core::identity::AgentIdentity, Arc<SigningKey>)> {
    let dir = dirs::home_dir().unwrap_or_default().join(".chorus");
    std::fs::create_dir_all(&dir)?;
    let seed_path = dir.join("identity.seed");
    let sk = if seed_path.exists() {
        let b = std::fs::read(&seed_path)?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&b[..32]);
        SigningKey::from_bytes(&seed)
    } else {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        std::fs::write(&seed_path, seed)?;
        SigningKey::from_bytes(&seed)
    };
    let identity = IdentityBuilder::new(name)
        .version("0.1.0-alpha")
        .build_with_key(&sk)?;
    Ok((identity, Arc::new(sk)))
}

async fn pump_events(
    _net: &P2PNetwork,
    ev: &mut tokio::sync::mpsc::UnboundedReceiver<P2PEvent>,
    did_map: &Arc<std::sync::Mutex<HashMap<String, libp2p::PeerId>>>,
    pid_map: &Arc<std::sync::Mutex<HashMap<String, String>>>,
    listen_addr: &Arc<std::sync::Mutex<String>>,
) {
    while let Some(ev) = ev.recv().await {
        match ev {
            P2PEvent::Listening { address } => {
                *listen_addr.lock().unwrap() = address.to_string();
                output(
                    Some(&serde_json::json!({"type":"listening","address":address.to_string()}).to_string()),
                    &format!("🔗 Listening: {}", address),
                );
            }
            P2PEvent::PeerConnected { ref peer_id } => output(
                Some(&serde_json::json!({"type":"peer_connected","peer_id":peer_id.to_string()}).to_string()),
                &format!("🟢 Connected: {}", peer_id),
            ),
            P2PEvent::PeerDisconnected { ref peer_id } => output(
                Some(&serde_json::json!({"type":"peer_disconnected","peer_id":peer_id.to_string()}).to_string()),
                &format!("🔴 Disconnected: {}", peer_id),
            ),
            P2PEvent::SessionEstablished { ref peer_id } => output(
                Some(&serde_json::json!({"type":"session_established","peer_id":peer_id.to_string()}).to_string()),
                &format!("🔐 E2EE: {}", peer_id),
            ),
            P2PEvent::EncryptedMessage {
                ref from,
                ref plaintext,
            } => {
                let text = String::from_utf8_lossy(plaintext).to_string();
                println!("💬 [{}] {}", from, text);
                if JSON_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                    println!("{}", serde_json::json!({"type":"message","from":from.to_string(),"text":text}));
                }
            }
            P2PEvent::AgentIdentified {
                ref peer_id,
                ref identity,
            } => {
                pid_map
                    .lock()
                    .unwrap()
                    .insert(peer_id.to_string(), identity.agent_id.clone());
                did_map
                    .lock()
                    .unwrap()
                    .insert(identity.agent_id.clone(), *peer_id);
                println!("🪪 {} ({})", identity.display_name, identity.agent_id);
                if JSON_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                    println!("{}", serde_json::json!({
                        "type":"agent_identified",
                        "peer_id":peer_id.to_string(),
                        "did":identity.agent_id.clone(),
                        "display_name":identity.display_name.clone(),
                        "capabilities":identity.capabilities.clone()
                    }));
                }
            }
            P2PEvent::DirectResponse {
                ref from,
                ref response,
            } => {
                let st = match response.status {
                    chorus_core::p2p::DirectResponseStatus::Ok => "OK".into(),
                    chorus_core::p2p::DirectResponseStatus::Error(ref e) => e.clone(),
                    chorus_core::p2p::DirectResponseStatus::Busy => "Busy".into(),
                };
                println!("📨 [{}]: {}", from, st);
            }
            P2PEvent::SessionFailed {
                ref peer_id,
                ref reason,
            } => println!("❌ KeyExchange [{}]: {}", peer_id, reason),
            P2PEvent::PeerDiscovered {
                ref peer_id,
                ref addresses,
            } => {
                for addr in addresses {
                    println!("🔍 Discovered: {} @ {}", peer_id, addr);
                }
            }
            P2PEvent::RelayReservationAccepted { ref relay_peer_id } => {
                println!("🔌 Relay reservation accepted: {}", relay_peer_id);
            }
            P2PEvent::RelayConnectionUpgraded { ref peer_id } => {
                println!("⚡ Direct connection upgraded: {}", peer_id);
            }
            P2PEvent::StructuredMessage { from: _, ref message } => {
                println!(
                    "📋 [{}] {} → {}: {}",
                    message.protocol.tag(),
                    message.from_agent.display_name,
                    if message.to_agent.is_empty() { "ALL".into() } else { message.to_agent.clone() },
                    message.summary(),
                );
            }
            _ => {}
        }
    }
}

fn print_help() {
    println!("connect <multiaddr>       Connect to peer");
    println!("status                    Show node info + peers");
    println!("chat <did> <message>      Send encrypted message");
    println!("peers                     List connected peers");
    println!("quit                      Exit");
}

async fn repl(
    net: Arc<P2PNetwork>,
    mut ev: tokio::sync::mpsc::UnboundedReceiver<P2PEvent>,
    agent_id: String,
    display_name: String,
    did_map: Arc<std::sync::Mutex<HashMap<String, libp2p::PeerId>>>,
    pid_map: Arc<std::sync::Mutex<HashMap<String, String>>>,
    listen_addr: Arc<std::sync::Mutex<String>>,
) {
    let net2 = net.clone();
    let dm2 = did_map.clone();
    let pm2 = pid_map.clone();
    let la2 = listen_addr.clone();
    tokio::spawn(async move {
        pump_events(&net2, &mut ev, &dm2, &pm2, &la2).await;
    });

    println!("\n🦀 chorus REPL — DID: {}", agent_id);
    println!("   Type 'help' for commands\n");

    let s = State {
        net,
        agent_id,
        display_name,
        did_map,
        pid_map,
        listen_addr,
    };
    let reader = BufReader::new(tokio::io::stdin());
    let mut lines = reader.lines();
    loop {
        print!("chorus> ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            _ => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        match parts[0] {
            "help" => print_help(),
            "quit" | "exit" | "q" => {
                let _ = s.net.shutdown();
                break;
            }
            "connect" => {
                if parts.len() < 2 {
                    eprintln!("Usage: connect <multiaddr>");
                    continue;
                }
                match s.net.dial(parts[1]).await {
                    Ok(()) => println!("✅ Dial sent"),
                    Err(e) => eprintln!("❌ {}", e),
                }
            }
            "status" => {
                let peers = s.net.list_peers().await.unwrap_or_default();
                let addr = s.listen_addr.lock().unwrap().clone();
                println!("\n DID: {}", s.agent_id);
                println!(" Name: {}", s.display_name);
                println!(" PeerId: {}", s.net.local_peer_id());
                println!(" Listening: {}", if addr.is_empty() { "-" } else { &addr });
                println!(" Peers: {}", peers.len());
                for p in &peers {
                    println!("   {} ({})", s.label(p), p);
                }
                println!();
            }
            "chat" => {
                if parts.len() < 3 {
                    eprintln!("Usage: chat <did> <message>");
                    continue;
                }
                let did = parts[1];
                let msg = parts[2];
                match s.peer_id(did) {
                    Ok(pid) => {
                        if let Err(e) = s.net.send_encrypted(pid, msg.as_bytes().to_vec()).await {
                            eprintln!("❌ {}", e);
                        } else {
                            println!("✅ Sent {} bytes", msg.len());
                        }
                    }
                    Err(e) => eprintln!("❌ {}", e),
                }
            }
            "peers" => match s.net.list_peers().await {
                Ok(peers) => {
                    for p in &peers {
                        println!("  {} ({})", s.label(p), p);
                    }
                }
                Err(e) => eprintln!("❌ {}", e),
            },
            _ => eprintln!("Unknown command. Type 'help'."),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,libp2p=warn".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Start {
            port,
            name,
            relay,
            no_repl,
            relay_peers,
            json,
        } => {
            JSON_MODE.store(json, std::sync::atomic::Ordering::Relaxed);
            let display = name.unwrap_or_else(|| {
                hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "chorus-node".into())
            });
            let (identity, _signing_key) = load_or_create_identity(&display)?;
            if JSON_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                println!(
                    "{}",
                    serde_json::json!({
                        "type":"identity_ready",
                        "did":identity.agent_id,
                        "display_name":display.clone()
                    })
                );
            }
            println!("🪪 {}", identity.agent_id);
            println!("👤 {}", display);

            let cfg = P2PConfig {
                listen_on: vec![format!("/ip4/0.0.0.0/tcp/{}", port)],
                agent_identity: Some(identity.clone()),
                auto_key_exchange: true,
                relay_server: relay,
                relay_peers,
                ..Default::default()
            };

            let (net, ev) = P2PNetwork::new(cfg)?;
            if no_repl {
                println!("🌍 Daemon mode — press Ctrl+C to stop");
                println!("🔑 PeerId: {}", net.local_peer_id());
                let _net2 = Arc::new(net);
                let mut ev2 = ev;
                tokio::spawn(async move {
                    while let Some(e) = ev2.recv().await {
                        match &e {
                            P2PEvent::Listening { address } => {
                                println!("🎧 Listening: {}", address);
                            }
                            P2PEvent::PeerConnected { peer_id } => {
                                println!("🟢 Connected: {}", peer_id);
                            }
                            P2PEvent::RelayReservationAccepted { relay_peer_id } => {
                                println!("🔌 Relay reservation: {}", relay_peer_id);
                            }
                            P2PEvent::RelayConnectionUpgraded { peer_id } => {
                                println!("⚡ Direct upgrade: {}", peer_id);
                            }
                            _ => {}
                        }
                    }
                    eprintln!("Event channel closed, shutting down.");
                });

                tokio::signal::ctrl_c().await.ok();
            } else {
                repl(
                    Arc::new(net),
                    ev,
                    identity.agent_id.clone(),
                    display,
                    Arc::new(std::sync::Mutex::new(HashMap::new())),
                    Arc::new(std::sync::Mutex::new(HashMap::new())),
                    Arc::new(std::sync::Mutex::new(String::new())),
                )
                .await;
            }
        }
    }
    Ok(())
}
