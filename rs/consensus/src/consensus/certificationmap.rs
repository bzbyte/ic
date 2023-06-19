/// Certification Map:
///
///    Implements StateManager + StateReader interfaces for launching certifier
///    instances.
///
///    In memory map to save certification context.
///
///    We are implementing 3 certification,
///      - wasm state certification
///         - Eth state certification
///         - Unchained beacon certification
///
///    The wasm certification is the base certification and other two
///    certification are implemented as new type idiom. The wrapped types track
///    disjoint elements like ethereum execution height and unchained beacon
///    identities.
///
///    The certification map is common in-memory abstraction to track wrapped items are
///    - Eligible for Certification
///    - Pending Certification and
///    - Certified
///
///    This is a in-memory map and acts as frontend cache to persistent
///    certification mempool.
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_interfaces_state_manager::{StateManager, StateReader};
use ic_logger::{debug, ReplicaLogger};
use ic_types::{consensus::certification::Certification, CryptoHashOfPartialState, Height};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

const CERTIFICATE_RETENTION_COUNT: usize = 1024;

pub(crate) struct CertificationMap {
    tag: String,
    log: ReplicaLogger,
    certification_pending:
        Mutex<BTreeMap<Height, (Height, CryptoHashOfPartialState, Option<Certification>)>>,
}

impl CertificationMap {
    pub fn new(tag: &str, log: ReplicaLogger) -> Self {
        Self {
            tag: tag.to_string(),
            log,
            certification_pending: Default::default(),
        }
    }
}

// -- Helpers for implementing the Batch Delivery trait --//
impl CertificationMap {
    // Delivery of state that has been certified by 2/3's of validators
    pub fn add_certification(&self, certification: Certification) {
        let mut certification_map = self.certification_pending.lock().expect("Lock acq");
        let consensus_height = certification.height;
        // Accept the first certificate if the hash matches
        if let Some((execution_height, state_root, cert_entry)) =
            certification_map.get_mut(&consensus_height)
        {
            if *state_root != certification.signed.content.hash {
                panic!(
                    "Invalid {} state root certification Expected {:?} Got {:?}",
                    self.tag, certification.signed.content.hash, state_root
                );
            }
            if cert_entry.is_none() {
                debug!(
                    self.log,
                    "{} Certification {:?} consensus height {}, Exec height {}",
                    self.tag,
                    certification,
                    consensus_height,
                    execution_height
                );
                cert_entry.replace(certification);
            }
        }
    }

    // Delivery of post-consensus un-certified state
    pub fn queue_certification(
        &self,
        consensus_height: Height,
        execution_height: Height,
        state_root: CryptoHashOfPartialState,
    ) {
        let mut certification_map = self.certification_pending.lock().expect("Lock acq");
        let len = certification_map.len();
        if len >= CERTIFICATE_RETENTION_COUNT {
            (0..(len - CERTIFICATE_RETENTION_COUNT)).for_each(|_| {
                let _drain = certification_map.pop_first();
            });
        }

        /* only request for certification for the first state root at given height */
        let _ = certification_map.entry(consensus_height).or_insert((
            execution_height,
            state_root,
            None,
        ));
    }
}

impl StateManager for CertificationMap {
    fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)> {
        self.certification_pending
            .lock()
            .expect("Lock acq")
            .iter()
            .filter_map(
                |(consensus_height, (_execution_height, state_root, certification))| {
                    match certification {
                        Some(_) => None,
                        None => Some((Height::from(*consensus_height), state_root.clone())),
                    }
                },
            )
            .collect()
    }

    fn deliver_state_certification(&self, certification: Certification) {
        self.add_certification(certification)
    }

    fn get_state_hash_at(
        &self,
        _height: ic_types::Height,
    ) -> Result<ic_types::CryptoHashOfState, ic_interfaces_state_manager::StateHashError> {
        todo!()
    }

    fn fetch_state(
        &self,
        _height: ic_types::Height,
        _root_hash: ic_types::CryptoHashOfState,
        _cup_interval_length: ic_types::Height,
    ) {
        todo!()
    }

    fn list_state_heights(
        &self,
        _cert_mask: ic_interfaces_state_manager::CertificationMask,
    ) -> Vec<ic_types::Height> {
        todo!()
    }

    fn remove_states_below(&self, _height: ic_types::Height) {
        todo!()
    }

    fn remove_inmemory_states_below(&self, _height: ic_types::Height) {
        todo!()
    }

    fn commit_and_certify(
        &self,
        _state: Self::State,
        _height: ic_types::Height,
        _scope: ic_interfaces_state_manager::CertificationScope,
    ) {
        todo!()
    }

    fn take_tip(&self) -> (ic_types::Height, Self::State) {
        todo!()
    }

    fn take_tip_at(
        &self,
        _height: ic_types::Height,
    ) -> ic_interfaces_state_manager::StateManagerResult<Self::State> {
        todo!()
    }

    fn report_diverged_checkpoint(&self, _height: ic_types::Height) {
        todo!()
    }
}

impl StateReader for CertificationMap {
    type State = CryptoHashOfPartialState;

    fn get_state_at(
        &self,
        _height: ic_types::Height,
    ) -> ic_interfaces_state_manager::StateManagerResult<
        ic_interfaces_state_manager::Labeled<Arc<Self::State>>,
    > {
        todo!()
    }

    fn get_latest_state(&self) -> ic_interfaces_state_manager::Labeled<Arc<Self::State>> {
        todo!()
    }

    fn latest_state_height(&self) -> ic_types::Height {
        self.certification_pending
            .lock()
            .expect("Lock acq")
            .last_key_value()
            .map_or(Height::from(0), |(height, _)| *height)
    }

    fn latest_certified_height(&self) -> ic_types::Height {
        self.certification_pending
            .lock()
            .expect("Lock acq")
            .iter()
            .rev()
            .find(|(_hc, (_he, _hash, certification))| certification.is_some())
            .map_or(Height::from(0), |(hc, (_, _, _))| *hc)
    }

    fn read_certified_state(
        &self,
        _paths: &LabeledTree<()>,
    ) -> Option<(
        Arc<Self::State>,
        MixedHashTree,
        ic_types::consensus::certification::Certification,
    )> {
        let cert_pending = self.certification_pending.lock().expect("Lock acq");
        let (_hc, (_he, hash, certification)) = cert_pending
            .iter()
            .rev()
            .find(|(_hc, (_he, _hash, certification))| certification.is_some())?;
        Some((
            Arc::from(hash.clone()),
            MixedHashTree::Empty,
            certification.as_ref().expect("Certification").clone(),
        ))
    }
}
