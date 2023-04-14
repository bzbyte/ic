//! Eth specific processing.

use bzb_execution_layer::engine_api::{
    auth::{Auth, JwtKey},
    ethspec::MainnetEthSpec,
    execution_payload::Hash256,
    http::HttpJsonRpc,
    json_structures::{ExecutionBlockHash, JsonExecutionPayloadV1},
    sensitive_url::SensitiveUrl,
    Address, BlockByNumberQuery, ForkchoiceState, GetJsonPayloadResponse, PayloadAttributes,
    PayloadAttributesV1, LATEST_TAG,
};
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_interfaces_state_manager::{StateManager, StateReader};
use ic_logger::{debug, info, ReplicaLogger};
use ic_types::{
    consensus::certification::Certification,
    crypto::CryptoHash,
    eth::{EthExecutionDelivery, EthPayload},
    CryptoHashOfPartialState, Height,
};

use std::{
    collections::BTreeMap,
    ops::Deref,
    sync::{Arc, Mutex},
};
use tokio::runtime::Runtime;

/// TODO: A zero secret used for IPC with geth. This needs to change
/// a. Get must expose a random secret
/// b. This client must consume the random secret
pub const JWT_SECRET: [u8; 32] = [0u8; 32];

/// Builds the Eth payload to be included in the block proposal.
pub trait EthPayloadBuilder: Send + Sync {
    /// Get a payload from the Ethereum block builder currently the execution engine i.e. No MEV
    fn get_payload(&self) -> Result<Option<EthPayload>, String>;
}

/// Delivers the finalized transactions to Eth execution layer.
pub trait EthMessageRouting: Send + Sync {
    /// Deliver a batch of transactions to the ETH execution layer
    fn deliver_batch(&self, batch: Vec<EthExecutionDelivery>);
}

type CertificationMap = BTreeMap<Height, (Height, CryptoHashOfPartialState, Option<Certification>)>;

#[derive(Clone, Copy)]
struct EthExecutionState {
    fork_choice_state: ForkchoiceState,
    timestamp: u64,
}

/// JSON RPC client implementation of the engine API.
pub struct EthExecutionClient {
    rpc_client: HttpJsonRpc,
    runtime: Runtime,
    log: ReplicaLogger,
    certification_pending: Arc<Mutex<CertificationMap>>,
    state: Arc<Mutex<EthExecutionState>>,
}

impl EthExecutionClient {
    fn new(url: &str, log: ReplicaLogger) -> Self {
        let rpc_auth = Auth::new(JwtKey::from_slice(&JWT_SECRET).unwrap(), None, None);
        let rpc_url = SensitiveUrl::parse(url).unwrap();
        let rpc_client = HttpJsonRpc::new_with_auth(rpc_url, rpc_auth, None).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let block = runtime.block_on(async {
            rpc_client
                .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                .await
                .unwrap()
                .unwrap()
        });
        let state = Mutex::new(EthExecutionState {
            fork_choice_state: ForkchoiceState {
                head_block_hash: block.block_hash,
                safe_block_hash: block.block_hash,
                finalized_block_hash: ExecutionBlockHash::zero(),
            },
            timestamp: block.timestamp,
        });
        let state = Arc::from(state);
        Self {
            rpc_client,
            runtime,
            log,
            certification_pending: Default::default(),
            state,
        }
    }

    fn add_finalized_height(
        &self,
        consensus_height: Height,
        execution_height: Height,
        state_root: CryptoHashOfPartialState,
    ) {
        let mut certification_map = self.certification_pending.lock().unwrap();
        let _ = certification_map.entry(consensus_height).or_insert((
            execution_height,
            state_root,
            None,
        ));
    }

    fn add_certification(&self, certification: Certification) {
        let mut certification_map = self.certification_pending.lock().unwrap();
        let consensus_height = certification.height;
        // Accept the first certificate if the hash matches
        if let Some((execution_height, state_root, cert_entry)) =
            certification_map.get_mut(&consensus_height)
        {
            if *state_root != certification.signed.content.hash {
                panic!(
                    "Invalid ETH state root certification Expected {:?} Got {:?}",
                    certification.signed.content.hash, state_root
                );
            }
            if cert_entry.is_none() {
                info!(
                    self.log,
                    "Eth Certification {:?} consensus height {}, Exec height {}",
                    certification,
                    consensus_height,
                    execution_height
                );
                cert_entry.replace(certification);
            }
        }
    }

    #[allow(unused)]
    fn update_head(&self, head_block_hash: ExecutionBlockHash, timestamp: u64) {
        let mut state = self.state.lock().unwrap();
        state.fork_choice_state.head_block_hash = head_block_hash;
        state.fork_choice_state.safe_block_hash = head_block_hash;
        state.timestamp = timestamp;
    }

    fn get_state(&self) -> EthExecutionState {
        self.state.lock().unwrap().deref().clone()
    }

    fn update_finalized_block(&self, finalized_block_hash: ExecutionBlockHash, timestamp: u64) {
        let mut state = self.state.lock().unwrap();
        state.fork_choice_state.head_block_hash = finalized_block_hash;
        state.fork_choice_state.safe_block_hash = finalized_block_hash;
        state.fork_choice_state.finalized_block_hash = finalized_block_hash;
        state.timestamp = timestamp;
    }
}

impl EthPayloadBuilder for EthExecutionClient {
    fn get_payload(&self) -> Result<Option<EthPayload>, String> {
        self.runtime.block_on(async {
            let execution_state = self.get_state();
            let attr = Some(PayloadAttributes::V1(PayloadAttributesV1 {
                timestamp: execution_state.timestamp + 1,
                prev_randao: Hash256::zero(),
                suggested_fee_recipient: Address::repeat_byte(0),
            }));
            let fork_choice_result = self
                .rpc_client
                .forkchoice_updated_v2(execution_state.fork_choice_state, attr)
                .await
                .unwrap();
            debug!(
                self.log,
                "EthStubImpl::get_payload(): fork choice: {:?}", fork_choice_result
            );

            let json_payload = self
                .rpc_client
                .get_json_payload_v1::<MainnetEthSpec>(fork_choice_result.payload_id.unwrap())
                .await
                .unwrap();
            debug!(
                self.log,
                "EthStubImpl::get_payload(): eth_payload: {:?}", json_payload
            );

            let timestamp = if let GetJsonPayloadResponse::V1(
                JsonExecutionPayloadV1 {
                    block_hash: _head_block_hash,
                    timestamp,
                    ..
                },
                _x,
            ) = &json_payload
            {
                *timestamp
            } else {
                panic!("Only Mainnet Spec supported");
            };

            let execution_payload = bincode::serialize(&json_payload).unwrap();
            Ok(Some(EthPayload {
                execution_payload,
                timestamp,
            }))
        })
    }
}

impl EthMessageRouting for EthExecutionClient {
    fn deliver_batch(&self, batch: Vec<EthExecutionDelivery>) {
        self.runtime.block_on(async {
            for entry in batch {
                let json_payload: GetJsonPayloadResponse<MainnetEthSpec> =
                    bincode::deserialize(&entry.payload.execution_payload).unwrap();

                let (state_root, eth_block_number, finalized_block_hash, timestamp) =
                    match &json_payload {
                        GetJsonPayloadResponse::V1(
                            JsonExecutionPayloadV1 {
                                state_root,
                                block_number,
                                block_hash: finalized_block_hash,
                                timestamp,
                                ..
                            },
                            _x,
                        ) => (
                            state_root.as_bytes().to_vec(),
                            *block_number,
                            *finalized_block_hash,
                            *timestamp,
                        ),
                        _ => panic!("Only V1 structures supported"),
                    };
                let new_payload = self
                    .rpc_client
                    .new_payload_v1(json_payload.into())
                    .await
                    .unwrap();
                debug!(
                    self.log,
                    "EthStubImpl::deliver_batch(): new_payload: {:?}", new_payload
                );

                self.add_finalized_height(
                    Height::from(entry.height),
                    Height::from(eth_block_number),
                    CryptoHashOfPartialState::from(CryptoHash(state_root)),
                );
                self.update_finalized_block(finalized_block_hash, timestamp);
            }
        })
    }
}

impl StateReader for EthExecutionClient {
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
            .unwrap()
            .last_key_value()
            .map_or(Height::from(0), |(height, _)| *height)
    }

    fn latest_certified_height(&self) -> ic_types::Height {
        self.certification_pending
            .lock()
            .unwrap()
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
        let cert_pending = self.certification_pending.lock().unwrap();
        let (_hc, (_he, hash, certification)) = cert_pending
            .iter()
            .rev()
            .find(|(_hc, (_he, _hash, certification))| certification.is_some())?;
        Some((
            Arc::from(hash.clone()),
            MixedHashTree::Empty,
            certification.as_ref().unwrap().clone(),
        ))
    }
}

impl StateManager for EthExecutionClient {
    fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)> {
        self.certification_pending
            .lock()
            .unwrap()
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

/// Top level context to drive ethereum consensus
pub struct EthExecution {
    /// the payload builder
    pub eth_payload_builder: Arc<dyn EthPayloadBuilder>,
    /// message routing for the execution engine
    pub eth_message_routing: Arc<dyn EthMessageRouting>,
    /// state manager for the certifier to interact with
    pub eth_state_manager: Arc<dyn StateManager<State = CryptoHashOfPartialState>>,
    /// state reader for the http layer to interact with
    pub eth_state_reader: Arc<dyn StateReader<State = CryptoHashOfPartialState>>,
}

impl EthExecution {
    /// build a new ethereum execution
    fn new(
        eth_payload_builder: Arc<dyn EthPayloadBuilder>,
        eth_message_routing: Arc<dyn EthMessageRouting>,
        eth_state_manager: Arc<dyn StateManager<State = CryptoHashOfPartialState>>,
        eth_state_reader: Arc<dyn StateReader<State = CryptoHashOfPartialState>>,
    ) -> Self {
        Self {
            eth_payload_builder,
            eth_message_routing,
            eth_state_manager,
            eth_state_reader,
        }
    }
}

/// Builds a minimal ethereum stack to be used with certified consensus
pub fn build_eth(log: ReplicaLogger) -> EthExecution {
    let eth = Arc::new(EthExecutionClient::new("http://localhost:8551", log));
    EthExecution::new(eth.clone(), eth.clone(), eth.clone(), eth)
}
