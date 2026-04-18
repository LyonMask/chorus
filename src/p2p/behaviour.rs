//! Composite libp2p network behaviour.

use libp2p::{dcutr, gossipsub, identify, mdns, ping, relay, request_response, swarm::NetworkBehaviour};

use super::direct::DirectCodec;

/// libp2p behaviour combining Gossipsub, Identify, Ping, mDNS, Relay (client + server), DCUtR, and Direct channel.
#[derive(NetworkBehaviour)]
pub struct WalkieBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub relay: relay::client::Behaviour,
    pub relay_srv: relay::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub direct: request_response::Behaviour<DirectCodec>,
}
