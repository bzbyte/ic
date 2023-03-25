//! Eth specific processing.

use bzb_execution_layer::engine_api::{
    auth::{Auth, JwtKey},
    ethspec::MainnetEthSpec,
    execution_payload::Hash256,
    http::HttpJsonRpc,
    json_structures::ExecutionBlockHash,
    sensitive_url::SensitiveUrl,
    Address, BlockByNumberQuery, ForkchoiceState, GetJsonPayloadResponse, PayloadAttributes,
    PayloadAttributesV1, LATEST_TAG,
};
use ic_logger::{debug, ReplicaLogger};
use ic_types::eth::{EthExecutionDelivery, EthPayload};
use std::sync::Arc;
use tokio::runtime::Runtime;

pub const JWT_SECRET: [u8; 32] = [0u8; 32];

/// Builds the Eth payload to be included in the block proposal.
pub trait EthPayloadBuilder: Send + Sync {
    fn get_payload(&self) -> Result<Option<EthPayload>, String>;
}

/// Delivers the finalized transactions to Eth execution layer.
pub trait EthMessageRouting: Send + Sync {
    fn deliver_batch(&self, batch: Vec<EthExecutionDelivery>);
}

/// JSON RPC client implementation of the engine API.
pub struct EthStubImpl {
    rpc_client: HttpJsonRpc,
    runtime: Runtime,
    log: ReplicaLogger,
}

impl EthStubImpl {
    pub fn new(url: &str, log: ReplicaLogger) -> Self {
        let rpc_auth = Auth::new(JwtKey::from_slice(&JWT_SECRET).unwrap(), None, None);
        let rpc_url = SensitiveUrl::parse(url).unwrap();
        let rpc_client = HttpJsonRpc::new_with_auth(rpc_url, rpc_auth, None).unwrap();
        Self {
            rpc_client,
            runtime: tokio::runtime::Runtime::new().unwrap(),
            log,
        }
    }
}

impl EthPayloadBuilder for EthStubImpl {
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

impl EthMessageRouting for EthStubImpl {
    fn deliver_batch(&self, batch: Vec<EthExecutionDelivery>) {
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

pub fn build_eth_stubs(
    log: ReplicaLogger,
) -> (Arc<dyn EthPayloadBuilder>, Arc<dyn EthMessageRouting>) {
    let stub = Arc::new(EthStubImpl::new("http://localhost:8551", log));
    (stub.clone(), stub)
}
