//! FFI Bindings for Node.js (napi-rs)

use crate::{CryptoLayer, P2PNetwork};
use napi_derive::napi;

#[napi]
pub struct P2PClient {
    inner: P2PNetwork,
}

#[napi]
impl P2PClient {
    #[napi(constructor)]
    pub fn new() -> napi::Result<Self> {
        let inner = tokio::runtime::Runtime::new()
            .map_err(|e| napi::Error::from_reason(e.to_string()))?
            .block_on(P2PNetwork::new())
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;

        Ok(Self { inner })
    }

    #[napi]
    pub async fn connect(&mut self, addr: String) -> napi::Result<String> {
        // TODO: 实现
        Err(napi::Error::from_reason("Not implemented"))
    }

    #[napi]
    pub async fn send_message(
        &mut self,
        peer_id: String,
        message: napi::bindgen_prelude::Buffer,
    ) -> napi::Result<()> {
        // TODO: 实现
        Err(napi::Error::from_reason("Not implemented"))
    }
}
