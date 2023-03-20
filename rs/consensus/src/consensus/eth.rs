//! Eth specific processing.

use ic_logger::{info, ReplicaLogger};
use ic_types::eth::{EthExecutionDelivery, EthPayload};
use std::sync::Arc;

const GETH_BRIDGE_GET_PAYLOAD: &str = "http://127.0.0.1:8552/get_payload";
const GETH_BRIDGE_EXECUTE_PAYLOAD: &str = "http://127.0.0.1:8552/execute_payload";

/// Builds the Eth payload to be included in the block proposal.
pub trait EthPayloadBuilder: Send + Sync {
    fn get_payload(&self) -> Result<Option<EthPayload>, String>;
}

/// Delivers the finalized transactions to Eth execution layer.
pub trait EthMessageRouting: Send + Sync {
    fn deliver_batch(&self, batch: Vec<EthExecutionDelivery>);
}

/// Interface to geth bridge
pub struct GethBridgeStub {
    log: ReplicaLogger,
}

impl GethBridgeStub {
    pub fn new(log: ReplicaLogger) -> Self {
        Self { log }
    }
}

impl EthPayloadBuilder for GethBridgeStub {
    fn get_payload(&self) -> Result<Option<EthPayload>, String> {
        let execution_payload = reqwest::blocking::get(GETH_BRIDGE_GET_PAYLOAD)
            .unwrap()
            .bytes()
            .unwrap()
            .to_vec();
        info!(
            self.log,
            "GethBridgeStub::get_payload(): received payload({}), len {:?}",
            GETH_BRIDGE_GET_PAYLOAD,
            execution_payload.len()
        );

        Ok(Some(EthPayload(execution_payload)))
    }
}

impl EthMessageRouting for GethBridgeStub {
    fn deliver_batch(&self, batch: Vec<EthExecutionDelivery>) {
        let client = reqwest::blocking::Client::new();
        for entry in batch {
            client
                .post(GETH_BRIDGE_EXECUTE_PAYLOAD)
                .body(entry.payload.0.clone())
                .send()
                .unwrap();
            info!(
                self.log,
                "GethBridgeStub::deliver_batch({}): sent payload, height = {:?}, len {:?}",
                GETH_BRIDGE_EXECUTE_PAYLOAD,
                entry.height,
                entry.payload.0.len()
            );
        }
    }
}

pub fn build_eth_stubs(
    log: ReplicaLogger,
) -> (Arc<dyn EthPayloadBuilder>, Arc<dyn EthMessageRouting>) {
    let stub = Arc::new(GethBridgeStub::new(log));
    (stub.clone(), stub)
}
