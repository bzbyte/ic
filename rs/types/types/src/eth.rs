//! Eth specific defines.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthTransaction;

/// Per-block Eth payload
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthPayload {
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
