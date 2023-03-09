//! Eth specific processing.

use ic_types::eth::EthPayload;

use std::sync::Arc;

pub trait EthPayloadBuilder: Send + Sync {
    fn get_payload(&self) -> Result<Option<EthPayload>, String>;
}

/// TODO: JSON RPC client for Engine API, fethces the transactions
/// to be included in the block proposal.
pub struct EthPayloadBuilderImpl;

impl EthPayloadBuilder for EthPayloadBuilderImpl {
    fn get_payload(&self) -> Result<Option<EthPayload>, String> {
        Ok(None)
    }
}

pub fn new_eth_payload_builder() -> Arc<dyn EthPayloadBuilder> {
    Arc::new(EthPayloadBuilderImpl)
}
