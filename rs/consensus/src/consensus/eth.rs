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
use ic_logger::{debug, ReplicaLogger};
use ic_types::{
    crypto::{CryptoHash, CryptoHashOf},
    eth::{EthExecutionDelivery, EthPayload},
    Height
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
    fn get_payload(&self) -> Result<Option<EthPayload>, String>;
}

/// Delivers the finalized transactions to Eth execution layer.
pub trait EthMessageRouting: Send + Sync {
    /// Deliver a batch of transactions to the ETH execution layer
    fn deliver_batch(&self, batch: Vec<EthExecutionDelivery>);
}

/// JSON RPC client implementation of the engine API.
pub struct EthExecutionClient {
    rpc_client: HttpJsonRpc,
    runtime: Runtime,
    log: ReplicaLogger,
    certification_pending: Arc<Mutex<BTreeMap<u64, Hash256>>>,
}

impl EthExecutionClient {
    fn new(url: &str, log: ReplicaLogger) -> Self {
        let rpc_auth = Auth::new(JwtKey::from_slice(&JWT_SECRET).unwrap(), None, None);
        let rpc_url = SensitiveUrl::parse(url).unwrap();
        let rpc_client = HttpJsonRpc::new_with_auth(rpc_url, rpc_auth, None).unwrap();
        Self {
            rpc_client,
            runtime: tokio::runtime::Runtime::new().unwrap(),
            log,
            certification_pending: Default::default(),
        }
    }
}

impl EthPayloadBuilder for EthExecutionClient {
    fn get_payload(&self) -> Result<Option<EthPayload>, String> {
        self.runtime.block_on(async {
            /*
            self.rpc_client.upcheck().await.unwrap();
            let capabilities = self.rpc_client.exchange_capabilities().await.unwrap();
            info!(
                self.log,
                "EthStubImpl::get_payload(): Caps: {:?}", capabilities
            );*/

            let block = self
                .rpc_client
                .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                .await
                .unwrap()
                .unwrap();
            debug!(
                self.log,
                "EthStubImpl::get_payload(): latest block: {:?}", block
            );

            let fork_choice = ForkchoiceState {
                head_block_hash: block.block_hash,
                safe_block_hash: block.block_hash,
                finalized_block_hash: ExecutionBlockHash::zero(),
            };
            let attr = Some(PayloadAttributes::V1(PayloadAttributesV1 {
                timestamp: block.timestamp + 1,
                prev_randao: Hash256::zero(),
                suggested_fee_recipient: Address::repeat_byte(0),
            }));
            let fork_choice_result = self
                .rpc_client
                .forkchoice_updated_v2(fork_choice, attr)
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
            let execution_payload = bincode::serialize(&json_payload).unwrap();
            Ok(Some(EthPayload {
                execution_payload,
                timestamp: block.timestamp + 2,
            }))
        })
    }
}

impl EthMessageRouting for EthExecutionClient {
    fn deliver_batch(&self, batch: Vec<EthExecutionDelivery>) {
        let certification_map = self.certification_pending.clone();
        self.runtime.block_on(async {
            /*
            self.rpc_client.upcheck().await.unwrap();
            let capabilities = self.rpc_client.exchange_capabilities().await.unwrap();
            info!(
                self.log,
                "EthStubImpl::deliver_batch(): Caps: {:?}", capabilities
            ); */

            for entry in batch {
                debug!(
                    self.log,
                    "EthStubImpl::deliver_batch(): height: {:?}", entry.height
                );
                let json_payload: GetJsonPayloadResponse<MainnetEthSpec> =
                    bincode::deserialize(&entry.payload.execution_payload).unwrap();

                if let GetJsonPayloadResponse::V1(
                    JsonExecutionPayloadV1 {
                        state_root,
                        block_number,
                        ..
                    },
                    _x,
                ) = &json_payload
                {
                    let _ = certification_map.lock().and_then(|mut m| Ok(m.insert(*block_number, *state_root)));
                    println!("FRZ  state_root {state_root:? } block_number {block_number:?} dfn height {0:?}", entry.height);
                }
                let new_payload = self
                    .rpc_client
                    .new_payload_v1(json_payload.into())
                    .await
                    .unwrap();
                debug!(
                    self.log,
                    "EthStubImpl::deliver_batch(): new_payload: {:?}", new_payload
                );

                let next_fork_choice = ForkchoiceState {
                    head_block_hash: new_payload.latest_valid_hash.unwrap(),
                    safe_block_hash: new_payload.latest_valid_hash.unwrap(),
                    finalized_block_hash: ExecutionBlockHash::zero(),
                };

                let attr = Some(PayloadAttributes::V1(PayloadAttributesV1 {
                    timestamp: entry.payload.timestamp,
                    prev_randao: Hash256::zero(),
                    suggested_fee_recipient: Address::repeat_byte(0),
                }));

                self.rpc_client
                    .forkchoice_updated_v2(next_fork_choice, attr)
                    .await
                    .unwrap();
            }
        })
    }
}

impl StateReader for EthExecutionClient {
    type State = EthExecutionClient;

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
        todo!()
    }

    fn latest_certified_height(&self) -> ic_types::Height {
        todo!()
    }

    fn read_certified_state(
        &self,
        _paths: &LabeledTree<()>,
    ) -> Option<(
        Arc<Self::State>,
        MixedHashTree,
        ic_types::consensus::certification::Certification,
    )> {
        todo!()
    }
}

impl StateManager for EthExecutionClient {
    fn list_state_hashes_to_certify(
        &self,
    ) -> Vec<(ic_types::Height, ic_types::CryptoHashOfPartialState)> {
        self.certification_pending
            .lock()
            .unwrap()
            .iter()
            .map(|(height, state_root)| {
                let state_root = CryptoHash(state_root.as_bytes().to_vec());
                (Height::from(*height), CryptoHashOf::from(state_root).into())
            })
            .collect()
    }

    fn deliver_state_certification(
        &self,
        certification: ic_types::consensus::certification::Certification,
    ) {
        println!("Received Ethereum state certification {:?}", certification);
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
    pub eth_state_manager: Arc<dyn StateManager<State=EthExecutionClient>>
}

impl EthExecution {
    /// build a new ethereum execution
    pub fn new(eth_payload_builder: Arc<dyn EthPayloadBuilder>, eth_message_routing: Arc<dyn EthMessageRouting>, eth_state_manager: Arc<dyn StateManager<State=EthExecutionClient>>) -> Self { Self { eth_payload_builder, eth_message_routing, eth_state_manager } }
}


/// Builds a minimal ethereum stack to be used with certified consensus
pub fn build_eth(
    log: ReplicaLogger,
) -> EthExecution
{
    let eth = Arc::new(EthExecutionClient::new("http://localhost:8551", log));
    EthExecution::new(eth.clone(), eth.clone(), eth)
}
