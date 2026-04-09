//! FFI Bindings for Node.js (napi-rs)

use crate::crypto::CryptoLayer;
use crate::p2p::P2PNetwork;
use napi_derive::napi;

#[napi]
pub struct P2PClient {
    inner: P2PNetwork,
}
