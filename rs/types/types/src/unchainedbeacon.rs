//! Eth specific defines.

use serde::{Deserialize, Serialize};

/// Eth payload included in the DFN blocks.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthPayload {
    /// Serialized ExecutionPayload
    pub execution_payload: Vec<u8>,

    /// Timestamp to use during delivery.
    pub timestamp: u64,
}

pub type Payload = Option<EthPayload>;

/// Post consensus(finalized) info passed to the Eth execution layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnchainedBeaconDelivery {
    /// Consensus block height that materialized.
    pub height: u64,
}
