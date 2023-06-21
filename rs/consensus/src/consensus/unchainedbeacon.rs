//! Unchained beacon:
//
//      A stream of signatures on monotonically increasing consensus height.
//      The consensus height increases independent of the execution height.
//      Execution clients can thus use the unchained beacon to co-ordinate any
//      block building/execution API without risking a circular dependency for
//      liveness.
//
//      The hash of the consensus height is signed and published. The primary
//      use case being threshold identity based encryption for encrypted
//      mem-pools
//
//      The map type is
//          Key:   ConsensusHeight,
//          Value: (ExecHeight, Hash(ConensusHeight/Stateroot), Option<BLSSignature>)
use crate::consensus::certificationmap::CertificationMap;
use ic_crypto_sha::Sha256;
use ic_interfaces_state_manager::{StateManager, StateReader};
use ic_logger::{debug, info, ReplicaLogger};
use ic_types::{
    consensus::certification::Certification, crypto::CryptoHash,
    unchainedbeacon::UnchainedBeaconDelivery, CryptoHashOfPartialState, Height,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

struct UnchainedBeaconClient {
    log: ReplicaLogger,
    certification_pending: Arc<CertificationMap>,
    state_manager: Arc<dyn StateManager<State = CryptoHashOfPartialState>>,
    state_reader: Arc<dyn StateReader<State = CryptoHashOfPartialState>>,
}

impl UnchainedBeaconClient {
    fn new(log: ReplicaLogger) -> Self {
        let certification_pending =
            Arc::new(CertificationMap::new("unchained_beacon", log.clone()));
        Self {
            log,
            state_manager: certification_pending.clone(),
            state_reader: certification_pending.clone(),
            certification_pending,
        }
    }
}

/// Message delivery for the unchained beacon. Messsages are the current consensus height
pub trait UCBMessageRouting: Send + Sync {
    /// Deliver a batch of transactions to the ETH execution layer
    fn deliver_batch(&self, batch: Vec<UnchainedBeaconDelivery>);
    /// Deliver early notarization hint for optimistic block building
    fn notarization_hint(&self, hint: UnchainedBeaconDelivery);
}

impl UCBMessageRouting for UnchainedBeaconClient {
    fn deliver_batch(&self, batch: Vec<UnchainedBeaconDelivery>) {
        for entry in batch {
            let consensus_height = Height::from(entry.height);
            let mut hasher = Sha256::new();
            hasher.write(&entry.height.to_be_bytes());
            let consensus_height_hash = hasher.finish().to_vec();
            self.certification_pending.queue_certification(
                consensus_height,
                Height::from(0),
                CryptoHashOfPartialState::from(CryptoHash(consensus_height_hash)),
            );
        }
    }

    fn notarization_hint(&self, hint: UnchainedBeaconDelivery) {
        // not used
    }
}

/// Top level context to drive ethereum consensus
pub struct UnchainedBeacon {
    /// message routing for unchained beacon, the messages are the consensus certified height
    pub ub_message_routing: Arc<dyn UCBMessageRouting>,
    /// state manager for the certifier to interact with
    pub ub_state_manager: Arc<dyn StateManager<State = CryptoHashOfPartialState>>,
    /// state reader for the http layer to interact with
    pub ub_state_reader: Arc<dyn StateReader<State = CryptoHashOfPartialState>>,
}

impl UnchainedBeacon {
    /// build a new ethereum execution
    fn new(
        ub_message_routing: Arc<dyn UCBMessageRouting>,
        ub_state_manager: Arc<dyn StateManager<State = CryptoHashOfPartialState>>,
        ub_state_reader: Arc<dyn StateReader<State = CryptoHashOfPartialState>>,
    ) -> Self {
        Self {
            ub_message_routing,
            ub_state_manager,
            ub_state_reader,
        }
    }
}

/// Builds a minimal unchained beacon stack to be used with threshold encryption
pub fn build_unchained_beacon(log: ReplicaLogger) -> UnchainedBeacon {
    let unchained_beacon = Arc::new(UnchainedBeaconClient::new(log));
    UnchainedBeacon::new(
        unchained_beacon.clone(),
        unchained_beacon.state_manager.clone(),
        unchained_beacon.state_reader.clone(),
    )
}
