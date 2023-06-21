//! Eth specific defines.

use serde::{Deserialize, Serialize};

/// Post consensus(finalized) info passed to the Eth execution layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnchainedBeaconDelivery {
    /// Consensus block height that materialized.
    pub height: u64,
}
