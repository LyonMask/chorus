//! Composite libp2p network behaviour.

use libp2p::{
    gossipsub, identify, mdns, ping,
    request_response,
    swarm::NetworkBehaviour,
};

use super::direct::DirectCodec;

/// libp2p behaviour combining Gossipsub, Identify, Ping, mDNS, and Direct channel.
#[derive(NetworkBehaviour)]
pub struct WalkieBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub direct: request_response::Behaviour<DirectCodec>,
}
