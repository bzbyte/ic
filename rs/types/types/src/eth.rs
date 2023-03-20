//! Eth specific defines.

use serde::{Deserialize, Serialize};

/// Eth payload included in the DFN blocks.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthPayload(pub Vec<u8>);

pub type Payload = Option<EthPayload>;

/// Post consensus(finalized) info passed to the Eth execution layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthExecutionDelivery {
    /// DFN block height this payload is from.
    pub height: u64,

    /// The eth payload from the finalized block.
    pub payload: EthPayload,
}
