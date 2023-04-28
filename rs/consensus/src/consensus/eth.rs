//! Eth specific processing.

use bzb_execution_layer::engine_api::{
    auth::{Auth, JwtKey},
    ethspec::MainnetEthSpec,
    execution_payload::Hash256,
    http::HttpJsonRpc,
    json_structures::{ExecutionBlockHash, JsonExecutionPayloadV1},
    sensitive_url::SensitiveUrl,
    Address, BlockByNumberQuery, Error, ForkchoiceState, ForkchoiceUpdatedResponse,
    GetJsonPayloadResponse, PayloadAttributes, PayloadAttributesV1, LATEST_TAG,
};
use core::fmt::Debug;
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
    fn get_payload(&self, height: Height) -> Result<Option<EthPayload>, String>;
}

/// Delivers the finalized transactions to Eth execution layer.
pub trait EthMessageRouting: Send + Sync {
    /// Deliver a batch of transactions to the ETH execution layer
    fn deliver_batch(&self, batch: Vec<EthExecutionDelivery>);
    /// Deliver early notarization hint for optimistic block building
    fn notarization_hint(&self, hint: EthExecutionDelivery);
}

type CertificationMap = BTreeMap<Height, (Height, CryptoHashOfPartialState, Option<Certification>)>;
const CERTIFICATE_RETENTION_COUNT: usize = 1024;

#[derive(Clone, Copy)]
struct EthExecutionState {
    fork_choice_state: ForkchoiceState,
    head_timestamp: u64,
    head_height: Height,
    finalized_timestamp: u64,
    finalized_height: Height,
}

/// JSON RPC client implementation of the engine API.
pub struct EthExecutionClient {
    rpc_client: HttpJsonRpc,
    runtime: Runtime,
    log: ReplicaLogger,
    certification_pending: Arc<Mutex<CertificationMap>>,
    state: Arc<Mutex<EthExecutionState>>,
}

enum BlockProcessing {
    Notarization,
    Finalization,
}

impl Debug for BlockProcessing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Notarization => write!(f, "Notarization"),
            Self::Finalization => write!(f, "Finalization"),
        }
    }
}

impl EthExecutionClient {
    fn new(url: &str, log: ReplicaLogger) -> Self {
        let jwt = JwtKey::from_slice(&JWT_SECRET).expect("Valid jwt secret");
        let rpc_auth = Auth::new(jwt, None, None);
        let rpc_url = SensitiveUrl::parse(url).expect("expect a correctly formatted rpc url");
        let rpc_client = HttpJsonRpc::new_with_auth(rpc_url, rpc_auth, None)
            .expect("Connection to execution client needed to continue");
        let runtime =
            tokio::runtime::Runtime::new().expect("Runtime needed for issuing execution layer API");
        let (head_block, safe_block, finalized_block) = runtime.block_on(async {
            let head_block = rpc_client
                .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                .await
                .expect("Head block must be known")
                .expect("Head block must be known");
            let finalized_block = rpc_client
                .get_block_by_number(BlockByNumberQuery::Tag("finalized"))
                .await
                .expect("RPC to query finalized block must succeed");
            let safe_block = rpc_client
                .get_block_by_number(BlockByNumberQuery::Tag("safe"))
                .await
                .expect("RPC to query safe block must succeed");
            (head_block, safe_block, finalized_block)
        });

        info!(log, "HEAD {head_block:?}");
        info!(log, "FINAL {finalized_block:?}");
        info!(log, "SAFE {safe_block:?}");

        let state = Mutex::new(EthExecutionState {
            fork_choice_state: ForkchoiceState {
                head_block_hash: head_block.block_hash,
                safe_block_hash: safe_block.map_or(ExecutionBlockHash::zero(), |safe_block| {
                    safe_block.block_hash
                }),
                finalized_block_hash: finalized_block
                    .map_or(ExecutionBlockHash::zero(), |finalized_block| {
                        finalized_block.block_hash
                    }),
            },
            head_timestamp: head_block.timestamp,
            head_height: Height::from(head_block.block_number),
            finalized_timestamp: finalized_block.map_or(0, |block| block.timestamp),
            finalized_height: Height::from(finalized_block.map_or(0, |block| block.block_number)),
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

    /* once we get finalization for a eth block we have to queue it for certification.
     * Finalization is expected to grow strictly monotonically and thus never expected to
     * diverge. This is the "fast finality" guaratee to top-level clients and we should
     * maintian that invariant here. So.
     *
     * 1. We only accept finalizations for the next expected finalization height.
     * 2. finalization request less than the expected height are either "repeats" of the same
     *    blocks or divergences. In both cases we don't accept the finalization
     *
     *  Only exception to the above rule is the zeroth/genesis block.
     *  */
    async fn process_block(
        &self,
        execution_delivery: EthExecutionDelivery,
        processing: BlockProcessing,
    ) -> Result<(), String> {
        let mut execution_state = self.state.lock().expect("Lock acquisition failed");

        let json_payload: GetJsonPayloadResponse<MainnetEthSpec> =
            bincode::deserialize(&execution_delivery.payload.execution_payload)
                .map_err(|e| e.to_string())?;
        /* TODO: simplify this wrapping */
        let (state_root, execution_height, block_hash, timestamp) = match &json_payload {
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
                Height::from(*block_number),
                *finalized_block_hash,
                *timestamp,
            ),
            _ => panic!("Only V1 structures supported"),
        };
        let consensus_height = Height::from(execution_delivery.height);

        let curr_height = match &processing {
            BlockProcessing::Finalization => execution_state.finalized_height.get(),
            BlockProcessing::Notarization => execution_state.head_height.get(),
        };

        let expected_height = Height::from(
            curr_height
                .checked_add(1)
                .expect("Height must be u64 bound"),
        );
        if execution_height != expected_height {
            info!(
                self.log,
                 "process_block: {processing:?} REJECT transition {expected_height:?} got {execution_height:?}"
            );
            return Err("Height out of bound".into());
        }
        info!(self.log, "process_block:  {processing:?} ACCEPT transition {expected_height:?} got {execution_height:?}");

        /* execute the finalized block */
        let _new_payload = self
            .rpc_client
            .new_payload_v1(json_payload.into())
            .await
            .map_err(|e| format!("{e:?}"))?;

        match &processing {
            BlockProcessing::Finalization => {
                /* queue the state root for certification */
                let _ = self.queue_certification(
                    consensus_height,
                    execution_height,
                    CryptoHashOfPartialState::from(CryptoHash(state_root)),
                );

                /* update the finalized block - reorg the head if needed */
                self.update_finalized_block(
                    &mut execution_state,
                    block_hash,
                    timestamp,
                    execution_height,
                )
                .await;
            }
            BlockProcessing::Notarization => {
                self.update_head_block(
                    &mut execution_state,
                    block_hash,
                    timestamp,
                    execution_height,
                )
                .await;
            }
        };
        Ok(())
    }

    fn queue_certification(
        &self,
        consensus_height: Height,
        execution_height: Height,
        state_root: CryptoHashOfPartialState,
    ) {
        let mut certification_map = self
            .certification_pending
            .lock()
            .expect("Certification lock acquisition");
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

    fn add_certification(&self, certification: Certification) {
        let mut certification_map = self.certification_pending.lock().expect("Lock acquisition");
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
                debug!(
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

    /* State update functions */
    async fn update_head_block(
        &self,
        execution_state: &mut EthExecutionState,
        head_block_hash: ExecutionBlockHash,
        head_timestamp: u64,
        head_height: Height,
    ) {
        execution_state.fork_choice_state.head_block_hash = head_block_hash;
        execution_state.head_timestamp = head_timestamp;
        execution_state.head_height = head_height;
        self.forkchoice_updated_v2(&execution_state)
            .await
            .expect("Consensus layer should be in sync with execution layer");
    }

    async fn update_finalized_block(
        &self,
        execution_state: &mut EthExecutionState,
        finalized_block_hash: ExecutionBlockHash,
        finalized_timestamp: u64,
        finalized_height: Height,
    ) {
        execution_state.fork_choice_state.safe_block_hash = finalized_block_hash;
        execution_state.fork_choice_state.finalized_block_hash = finalized_block_hash;
        execution_state.finalized_height = finalized_height;
        execution_state.finalized_timestamp = finalized_timestamp;

        /* the finalization is for a past propoasl.
         * 1. The past proposal was our proposal then our optmistic execution need not be reset.
         * Check if the finalized block is on the canonical chain
         * The only way to do this currently is attempt a fork choice update
         *
         * */
        if execution_state.finalized_height < execution_state.head_height
            && self.forkchoice_updated_v2(&execution_state).await.is_ok()
        {
            return;
        }

        info!(self.log, "Fork not on canonical chain head need to reset");
        self.update_head_block(
            execution_state,
            finalized_block_hash,
            finalized_timestamp,
            finalized_height,
        )
        .await
    }

    async fn forkchoice_updated_v2(
        &self,
        execution_state: &EthExecutionState,
    ) -> Result<ForkchoiceUpdatedResponse, Error> {
        let attr = Some(PayloadAttributes::V1(PayloadAttributesV1 {
            timestamp: execution_state.head_timestamp + 1,
            prev_randao: Hash256::zero(),
            suggested_fee_recipient: Address::repeat_byte(0),
        }));
        info!(
            self.log,
            "ENTER finalized block get_payload: {:?}",
            execution_state.fork_choice_state.head_block_hash,
        );
        let fork_choice_result = self
            .rpc_client
            .forkchoice_updated_v2(execution_state.fork_choice_state, attr)
            .await;
        info!(
            self.log,
            "EthStubImpl::get_payload(): fork choice: {:?}", fork_choice_result
        );
        fork_choice_result
    }
}

impl EthPayloadBuilder for EthExecutionClient {
    fn get_payload(&self, height: Height) -> Result<Option<EthPayload>, String> {
        self.runtime.block_on(async {
            let mut execution_state = self.state.lock().expect("Execution lock acquisition");
            let fork_choice_result = self
                .forkchoice_updated_v2(&execution_state)
                .await
                .map_err(|e| format!("{e:?}"))?;
            let payload_id = fork_choice_result
                .payload_id
                .ok_or("Failed to get Payload Id")?;
            let json_payload = self
                .rpc_client
                .get_json_payload_v1::<MainnetEthSpec>(payload_id)
                .await
                .map_err(|e| format!("{e:?}"))?;
            info!(
                self.log,
                "EthStubImpl::get_payload(): eth_payload: {:?}", json_payload
            );

            let (head_block_hash, timestamp, block_number) = if let GetJsonPayloadResponse::V1(
                JsonExecutionPayloadV1 {
                    block_hash: head_block_hash,
                    timestamp,
                    block_number,
                    ..
                },
                _x,
            ) = &json_payload
            {
                (*head_block_hash, *timestamp, *block_number)
            } else {
                panic!("Only Mainnet Spec supported");
            };

            info!(
                self.log,
                "EXIT newblock get_payload {:?} Height {height:?}", head_block_hash
            );

            let execution_payload =
                bincode::serialize(&json_payload).expect("Serializable payload");
            let _payload_status = self
                .rpc_client
                .new_payload_v1(json_payload.into())
                .await
                .map_err(|e| format!("{e:?}"))?;
            self.update_head_block(
                &mut execution_state,
                head_block_hash,
                timestamp,
                Height::from(block_number),
            )
            .await;
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
                let e = self
                    .process_block(entry, BlockProcessing::Finalization)
                    .await;
                if let Err(e) = e {
                    info!(self.log, "notarization hint deliver failed {e:?}");
                }
            }
        })
    }

    fn notarization_hint(&self, hint: EthExecutionDelivery) {
        self.runtime.block_on(async {
            let e = self
                .process_block(hint, BlockProcessing::Notarization)
                .await;
            if let Err(e) = e {
                info!(self.log, "notarization hint deliver failed {e:?}");
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
            .expect("certification lock acquisition")
            .last_key_value()
            .map_or(Height::from(0), |(height, _)| *height)
    }

    fn latest_certified_height(&self) -> ic_types::Height {
        self.certification_pending
            .lock()
            .expect("Certification lock acquisition")
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
        let cert_pending = self
            .certification_pending
            .lock()
            .expect("Certification lock acquisition");
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

impl StateManager for EthExecutionClient {
    fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)> {
        self.certification_pending
            .lock()
            .expect("Certification lock acquisition")
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
