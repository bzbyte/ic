//! Eth specific processing.

use ic_types::eth::{EthExecutionPayload, EthPayload};

use execution_layer::engine_api::{
    auth::{Auth, JwtKey},
    http::HttpJsonRpc,
    BlockByNumberQuery, PayloadAttributes, PayloadAttributesV1, LATEST_TAG,
};
use execution_layer::ForkchoiceState;
use sensitive_url::SensitiveUrl;
use std::sync::Arc;
use tokio::runtime::Runtime;
use types::{Address, ExecutionBlockHash, Hash256, MainnetEthSpec};

pub const JWT_SECRET: [u8; 32] = [0u8; 32];

/// Builds the Eth payload to be included in the block proposal.
pub trait EthPayloadBuilder: Send + Sync {
    fn get_payload(&self) -> Result<Option<EthPayload>, String>;
}

/// Delivers the finalized transactions to Eth execution layer.
pub trait EthMessageRouting: Send + Sync {
    fn deliver_batch(&self, batch: Vec<EthExecutionPayload>);
}

/// JSON RPC client implementation of the engine API.
pub struct EthStubImpl {
    rpc_client: HttpJsonRpc,
    runtime: Runtime,
}

impl EthStubImpl {
    pub fn new(url: &str) -> Self {
        let rpc_url = SensitiveUrl::parse(url).unwrap();
        Self {
            rpc_client: HttpJsonRpc::new(rpc_url, None).unwrap(),
            runtime: tokio::runtime::Runtime::new().unwrap(),
        }
    }
}

impl EthPayloadBuilder for EthStubImpl {
    fn get_payload(&self) -> Result<Option<EthPayload>, String> {
        Err("todo".to_string())
    }
}

impl EthMessageRouting for EthStubImpl {
    fn deliver_batch(&self, _batch: Vec<EthExecutionPayload>) {
        // TODO: ...
    }
}

pub fn build_eth_stubs() -> (Arc<dyn EthPayloadBuilder>, Arc<dyn EthMessageRouting>) {
    let stub = Arc::new(EthStubImpl::new("http://localhost:8551"));
    (stub.clone(), stub)
}
