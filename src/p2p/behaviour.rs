//! Composite libp2p network behaviour.

use libp2p::{
    gossipsub, identify, mdns, ping,
    swarm::NetworkBehaviour,
};

/// libp2p behaviour combining Gossipsub, Identify, Ping, and mDNS.
#[derive(NetworkBehaviour)]
pub struct WalkieBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}
