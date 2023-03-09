//! Eth specific processing.

use ic_types::eth::{EthExecutionPayload, EthPayload};

use std::sync::Arc;

/// Builds the Eth payload to be included in the block proposal.
pub trait EthPayloadBuilder: Send + Sync {
    fn get_payload(&self) -> Result<Option<EthPayload>, String>;
}

/// JSON RPC client implementation of the engine API.
pub struct EthPayloadBuilderImpl;

impl EthPayloadBuilder for EthPayloadBuilderImpl {
    fn get_payload(&self) -> Result<Option<EthPayload>, String> {
        // TODO: ...
        Ok(None)
    }
}

/// Delivers the finalized transactions to Eth execution layer.
pub trait EthMessageRouting: Send + Sync {
    fn deliver_batch(&self, batch: Vec<EthExecutionPayload>);
}

/// JSON RPC client implementation of the engine API.
pub struct EthMessageRoutingImpl;

impl EthMessageRouting for EthMessageRoutingImpl {
    fn deliver_batch(&self, _batch: Vec<EthExecutionPayload>) {
        // TODO: ...
    }
}

pub fn new_eth_payload_builder() -> Arc<dyn EthPayloadBuilder> {
    Arc::new(EthPayloadBuilderImpl)
}

pub fn new_eth_message_routing() -> Arc<dyn EthMessageRouting> {
    Arc::new(EthMessageRoutingImpl)
}
