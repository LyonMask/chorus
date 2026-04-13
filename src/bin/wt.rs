//! 🦀 wt — Walkie Talkie CLI
//!
//! cargo run --bin wt -- start [--port PORT] [--name NAME]
//! Then in REPL: help | connect | status | chat | advertise | request | attest | peers | quit

use std::collections::HashMap;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use tokio::io::{AsyncBufReadExt, BufReader};
use walkie_talkie_core::identity::IdentityBuilder;
use walkie_talkie_core::p2p::{DirectPayload, DirectRequest, P2PConfig, P2PEvent, P2PNetwork};
use walkie_talkie_core::resource::{now_ms, ResourceAdvertisement, ResourceRequest, ResourceSpec};

#[derive(Parser)]
#[command(name = "wt", version, about = "Walkie Talkie P2P CLI")]
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
    },
}

struct State {
    net: Arc<P2PNetwork>,
    agent_id: String,
    display_name: String,
    signing_key: Arc<SigningKey>,
    did_map: Arc<std::sync::Mutex<HashMap<String, libp2p::PeerId>>>,
    pid_map: Arc<std::sync::Mutex<HashMap<String, String>>>,
    listen_addr: Arc<std::sync::Mutex<String>>,
}

impl State {
    fn peer_id(&self, did: &str) -> anyhow::Result<libp2p::PeerId> {
        self.did_map.lock().unwrap().get(did).cloned()
            .ok_or_else(|| anyhow::anyhow!("DID '{}' not connected", did))
    }
    fn label(&self, pid: &libp2p::PeerId) -> String {
        self.pid_map.lock().unwrap().get(&pid.to_string()).cloned().unwrap_or_else(|| {
            let s = pid.to_string();
            if s.len() > 12 { format!("{}…", &s[..12]) } else { s }
        })
    }
}

fn load_or_create_identity(name: &str) -> anyhow::Result<(walkie_talkie_core::identity::AgentIdentity, Arc<SigningKey>)> {
    let dir = dirs::home_dir().unwrap_or_default().join(".wt");
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
        std::fs::write(&seed_path, &seed)?;
        SigningKey::from_bytes(&seed)
    };
    let identity = IdentityBuilder::new(name).version("0.3.0").build_with_key(&sk)?;
    Ok((identity, Arc::new(sk)))
}

async fn pump_events(_net: &P2PNetwork, ev: &mut tokio::sync::mpsc::UnboundedReceiver<P2PEvent>,
                     did_map: &Arc<std::sync::Mutex<HashMap<String, libp2p::PeerId>>>,
                     pid_map: &Arc<std::sync::Mutex<HashMap<String, String>>>,
                     listen_addr: &Arc<std::sync::Mutex<String>>) {
    while let Some(ev) = ev.recv().await {
        match ev {
            P2PEvent::Listening { address } => {
                *listen_addr.lock().unwrap() = address.to_string();
                println!("🔗 Listening: {}", address);
            }
            P2PEvent::PeerConnected { ref peer_id } => println!("🟢 Connected: {}", peer_id),
            P2PEvent::PeerDisconnected { ref peer_id } => println!("🔴 Disconnected: {}", peer_id),
            P2PEvent::SessionEstablished { ref peer_id } => println!("🔐 E2EE: {}", peer_id),
            P2PEvent::EncryptedMessage { ref from, ref plaintext } =>
                println!("💬 [{}] {}", from, String::from_utf8_lossy(plaintext)),
            P2PEvent::AgentIdentified { ref peer_id, ref identity } => {
                pid_map.lock().unwrap().insert(peer_id.to_string(), identity.agent_id.clone());
                did_map.lock().unwrap().insert(identity.agent_id.clone(), *peer_id);
                println!("🪪 {} ({})", identity.display_name, identity.agent_id);
            }
            P2PEvent::IdentityAttestationVerified { ref peer_id, ref did } => {
                pid_map.lock().unwrap().insert(peer_id.to_string(), did.clone());
                did_map.lock().unwrap().insert(did.clone(), *peer_id);
                println!("✅ Attestation OK: {}", did);
            }
            P2PEvent::ResourceOfferReceived { ref peer_id, ref offer } =>
                println!("📦 Offer from {}: cpu={}, mem={}MB", peer_id, offer.cpu_amount, offer.memory_amount_mb),
            P2PEvent::ResourceSessionStarted { .. } => println!("✅ Session started"),
            P2PEvent::ResourceReleased { contribution_delta, .. } =>
                println!("📤 Released Δ={:.4}", contribution_delta),
            P2PEvent::DirectResponse { ref from, ref response } => {
                let st = match response.status {
                    walkie_talkie_core::p2p::DirectResponseStatus::Ok => "OK".into(),
                    walkie_talkie_core::p2p::DirectResponseStatus::Error(ref e) => e.clone(),
                    walkie_talkie_core::p2p::DirectResponseStatus::Busy => "Busy".into(),
                };
                println!("📨 [{}]: {}", from, st);
            }
            P2PEvent::SessionFailed { ref peer_id, ref reason } =>
                println!("❌ KeyExchange [{}]: {}", peer_id, reason),
            P2PEvent::PeerDiscovered { ref peer_id, ref addresses } =>
                for addr in addresses { println!("🔍 Discovered: {} @ {}", peer_id, addr); }
            _ => {}
        }
    }
}

fn print_help() {
    println!("connect <multiaddr>       Connect to peer");
    println!("status                    Show node info");
    println!("chat <did> <message>      Send encrypted msg");
    println!("advertise [cpu=N mem=M]   Publish resources");
    println!("request <did> [cpu=N mem=M] Request resources");
    println!("attest <did>              Send attestation");
    println!("peers                     List peers");
    println!("quit                      Exit");
}

async fn repl(net: Arc<P2PNetwork>, mut ev: tokio::sync::mpsc::UnboundedReceiver<P2PEvent>,
              agent_id: String, display_name: String, signing_key: Arc<SigningKey>,
              did_map: Arc<std::sync::Mutex<HashMap<String, libp2p::PeerId>>>,
              pid_map: Arc<std::sync::Mutex<HashMap<String, String>>>,
              listen_addr: Arc<std::sync::Mutex<String>>) {

    let net2 = net.clone();
    let did_map2 = did_map.clone();
    let pid_map2 = pid_map.clone();
    let la2 = listen_addr.clone();
    tokio::spawn(async move { pump_events(&net2, &mut ev, &did_map2, &pid_map2, &la2).await; });

    println!("\n🦀 wt REPL — DID: {}", agent_id);
    println!("   Type 'help' for commands\n");

    let s = State { net, agent_id, display_name, signing_key, did_map, pid_map, listen_addr };
    let reader = BufReader::new(tokio::io::stdin());
    let mut lines = reader.lines();
    loop {
        print!("wt> ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let line = match lines.next_line().await { Ok(Some(l)) => l, _ => break };
        let line = line.trim().to_string();
        if line.is_empty() { continue; }
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        match parts[0] {
            "help" => print_help(),
            "quit" | "exit" | "q" => { let _ = s.net.shutdown(); break; }
            "connect" => {
                if parts.len() < 2 { eprintln!("Usage: connect <multiaddr>"); continue; }
                match s.net.dial(parts[1]).await { Ok(()) => println!("✅ Dial sent"), Err(e) => eprintln!("❌ {}", e) }
            }
            "status" => {
                let peers = s.net.list_peers().await.unwrap_or_default();
                let addr = s.listen_addr.lock().unwrap().clone();
                println!("\n DID: {}", s.agent_id);
                println!(" Name: {}", s.display_name);
                println!(" PeerId: {}", s.net.local_peer_id());
                println!(" Listening: {}", if addr.is_empty() { "-" } else { &addr });
                println!(" Peers: {}", peers.len());
                for p in &peers { println!("   {} ({})", s.label(p), p); }
                println!();
            }
            "chat" => {
                let rest = match line.find(' ').and_then(|i| line[i+1..].find(' ')) {
                    Some(pos) => &line[pos+2..],
                    None => { eprintln!("Usage: chat <did> <message>"); continue; }
                };
                let did = parts[1];
                let msg = rest;
                match s.peer_id(did) {
                    Ok(pid) => {
                        if let Err(e) = s.net.send_encrypted(pid, msg.as_bytes().to_vec()).await { eprintln!("❌ {}", e); }
                        else { println!("✅ Sent"); }
                    }
                    Err(e) => eprintln!("❌ {}", e),
                }
            }
            "advertise" => {
                let mut cpu: f32 = 1.0; let mut mem: u64 = 512;
                for p in parts[1..].iter() {
                    if let Some(v) = p.strip_prefix("cpu=") { cpu = v.parse().unwrap_or(1.0); }
                    if let Some(v) = p.strip_prefix("mem=") { mem = v.parse().unwrap_or(512); }
                }
                let ad = ResourceAdvertisement {
                    agent_id: s.agent_id.clone(), sequence: 1, timestamp: now_ms(),
                    spec: ResourceSpec { cpu_cores: cpu as u16, total_memory_mb: mem, max_bandwidth_up_mbps: 10, total_storage_bytes: 0 },
                    cpu_offer: cpu, memory_offer_mb: mem, bandwidth_offer: 10, storage_offer: 0,
                    features: vec![], signing_pubkey: vec![], signature: vec![],
                };
                if let Err(e) = s.net.update_resource_ad(ad).await { eprintln!("❌ {}", e); }
                else { println!("📦 Advertised"); }
            }
            "request" => {
                if parts.len() < 2 { eprintln!("Usage: request <did> [cpu=N mem=M]"); continue; }
                let mut cpu: f32 = 0.5; let mut mem: u64 = 256;
                // Parse optional params from parts[1] which may contain "did cpu=N mem=M"
                let rest = line[line.find(' ').unwrap()..].trim_start();
                let (did_str, rest) = match rest.split_once(' ') {
                    Some((d, r)) => (d, r),
                    None => (rest, ""),
                };
                for p in rest.split_whitespace() {
                    if let Some(v) = p.strip_prefix("cpu=") { cpu = v.parse().unwrap_or(0.5); }
                    if let Some(v) = p.strip_prefix("mem=") { mem = v.parse().unwrap_or(256); }
                }
                match s.peer_id(did_str) {
                    Ok(pid) => {
                        let mut req = ResourceRequest::new(s.agent_id.clone());
                        req.min_cpu = cpu;
                        req.min_memory_mb = mem;
                        req.duration_ms = 300_000;
                        match s.net.request_resource(pid, req).await {
                            Ok(_) => println!("✅ Request sent"),
                            Err(e) => eprintln!("❌ {}", e),
                        }
                    }
                    Err(e) => eprintln!("❌ {}", e),
                }
            }
            "attest" => {
                if parts.len() < 2 { eprintln!("Usage: attest <did>"); continue; }
                match s.peer_id(parts[1]) {
                    Ok(pid) => {
                        let att = walkie_talkie_core::trust::peer_binding::IdentityAttestation::sign(
                            &s.agent_id, &pid.to_string(), &s.signing_key,
                        );
                        let req = DirectRequest {
                            request_id: 0,
                            payload: DirectPayload::IdentityAttestation { attestation_json: serde_json::to_vec(&att).unwrap_or_default() },
                        };
                        if let Err(e) = s.net.send_direct_request(pid, req).await { eprintln!("❌ {}", e); }
                        else { println!("🔑 Attestation sent"); }
                    }
                    Err(e) => eprintln!("❌ {}", e),
                }
            }
            "peers" => {
                match s.net.list_peers().await {
                    Ok(peers) => { for p in &peers { println!("  {} ({})", s.label(p), p); } }
                    Err(e) => eprintln!("❌ {}", e),
                }
            }
            _ => eprintln!("Unknown. Type 'help'."),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info,libp2p=warn".parse().unwrap()))
        .with_target(false).init();

    let cli = Cli::parse();
    match cli.command {
        Command::Start { port, name } => {
            let display = name.unwrap_or_else(|| {
                hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_else(|_| "wt-node".into())
            });
            let (identity, signing_key) = load_or_create_identity(&display)?;
            println!("🪪 {}", identity.agent_id);
            println!("👤 {}", display);

            let mut cfg = P2PConfig::default();
            cfg.listen_on = vec![format!("/ip4/0.0.0.0/tcp/{}", port)];
            cfg.agent_identity = Some(identity.clone());
            cfg.auto_key_exchange = true;

            let (net, ev) = P2PNetwork::new(cfg)?;
            repl(Arc::new(net), ev, identity.agent_id.clone(), display, signing_key,
                 Arc::new(std::sync::Mutex::new(HashMap::new())),
                 Arc::new(std::sync::Mutex::new(HashMap::new())),
                 Arc::new(std::sync::Mutex::new(String::new()))).await;
        }
    }
    Ok(())
}
