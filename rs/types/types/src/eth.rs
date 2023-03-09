//! Eth specific defines.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthTransaction;

/// Eth payload included in the DFN blocks.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthPayload {
    /// Transactions included in the block.
    txns: Vec<EthTransaction>,
}

pub type Payload = Option<EthPayload>;

impl EthPayload {
    pub fn new() -> Self {
        Self {
            txns: Default::default(),
        }
    }
}

/// Post consensus(finalized) info passed to the Eth execution layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthExecutionPayload {
    /// DFN block height this payload is from.
    pub height: u64,

    /// The eth payload from the finalized block.
    pub payload: EthPayload,
}
