//! gateway_demo — P2P + Gateway HTTP combined for testing
//!
//! Usage: cargo run --example gateway_demo -- --port 9900 --http-port 8080 --name TestNode

use clap::Parser;
use std::sync::Arc;
use walkie_talkie_core::gateway::{create_router, AppState};
use walkie_talkie_core::identity::IdentityBuilder;
use walkie_talkie_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};

#[derive(Parser)]
#[command(name = "gateway_demo")]
struct Cli {
    #[arg(long, default_value = "0")]
    port: u16,
    #[arg(long, default_value = "8080")]
    http_port: u16,
    #[arg(long)]
    name: Option<String>,
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
    let name = cli
        .name
        .unwrap_or_else(|| hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default());

    let (identity, sk) = {
        let seed_path = std::path::PathBuf::from(
            std::env::var("WT_IDENTITY_DIR").unwrap_or_else(|_| ".wt".into()),
        );
        std::fs::create_dir_all(&seed_path)?;
        let seed_file = seed_path.join("identity.seed");
        let seed = if seed_file.exists() {
            let mut buf = vec![0u8; 32];
            buf.copy_from_slice(&std::fs::read(&seed_file)?);
            buf
        } else {
            let mut buf = vec![0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
            std::fs::write(&seed_file, &buf)?;
            buf
        };
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap());
        let id = IdentityBuilder::new(&name).build_with_key(&sk)?;
        (id, sk)
    };

    println!("🪪 {}", identity.agent_id);
    println!("👤 {}", name);

    let cfg = P2PConfig {
        listen_on: vec![format!("/ip4/0.0.0.0/tcp/{}", cli.port)],
        agent_identity: Some(identity.clone()),
        auto_key_exchange: true,
        signing_key: Some(Arc::new(sk)),
        ..Default::default()
    };

    let (net, mut ev) = P2PNetwork::new(cfg)?;
    let net = Arc::new(net);

    let state = AppState::with_p2p(net.clone());
    let app = create_router(state);

    // Event pump
    let net2 = net.clone();
    tokio::spawn(async move {
        while let Some(e) = ev.recv().await {
            match &e {
                P2PEvent::Listening { address } => println!("🎧 Listening: {}", address),
                P2PEvent::PeerConnected { peer_id } => println!("🟢 Connected: {}", peer_id),
                P2PEvent::PeerDisconnected { peer_id } => println!("🔴 Disconnected: {}", peer_id),
                P2PEvent::SessionEstablished { peer_id } => println!("🔐 E2EE: {}", peer_id),
                P2PEvent::EncryptedMessage { from, plaintext } => {
                    println!("💬 [{}] {}", from, String::from_utf8_lossy(plaintext));
                }
                P2PEvent::AgentIdentified { peer_id, identity } => {
                    println!("🪪 {} → {}", peer_id, identity.display_name);
                }
                _ => {}
            }
        }
    });

    // REPL thread
    let net3 = net.clone();
    std::thread::spawn(move || {
        use std::io::{BufRead, Write};
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        println!("\n🦀 Gateway Demo — Type 'help' or 'quit'\n");
        let mut rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                _ => break,
            };
            let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
            match parts[0] {
                "quit" | "exit" | "q" => break,
                "peers" => {
                    let r = rt.block_on(net3.list_peers());
                    println!("Peers: {:?}", r);
                }
                "resources" => {
                    let r = rt.block_on(net3.list_resources());
                    println!("Resources: {:?}", r);
                }
                "chat" if parts.len() >= 3 => {
                    // parts[1] = peer_id, parts[2] = message
                    let pid_str = parts[1];
                    let msg = parts[2];
                    match pid_str.parse::<libp2p::PeerId>() {
                        Ok(pid) => {
                            let r = rt.block_on(net3.send_encrypted(pid, msg.as_bytes().to_vec()));
                            match r {
                                Ok(()) => println!("✅ Sent {} bytes", msg.len()),
                                Err(e) => println!("❌ {}", e),
                            }
                        }
                        Err(_) => println!("❌ Invalid PeerId"),
                    }
                }
                _ => println!("Unknown: {}", parts[0]),
            }
            print!("gw> ");
            stdout.flush().ok();
        }
    });

    let addr = format!("0.0.0.0:{}", cli.http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("🌐 Gateway HTTP: http://{}", addr);

    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
