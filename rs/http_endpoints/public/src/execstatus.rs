//! Module that deals with requests to /api/v2/execstatus
use crate::{common, state_reader_executor::StateReaderExecutor, EndpointService};
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::{Body, Response};
use ic_consensus::consensus::eth::EthExecutionClient;
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{warn, ReplicaLogger};
use ic_types::{
    messages::{Blob, HttpExecStatusResponse, ReplicaHealthStatus},
    replica_version::REPLICA_BINARY_HASH,
    ReplicaVersion, SubnetId,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{
    limit::concurrency::GlobalConcurrencyLimitLayer, util::BoxCloneService, BoxError, Service,
    ServiceBuilder,
};

const MAX_STATUS_CONCURRENT_REQUESTS: usize = 100;
const IC_API_VERSION: &str = "0.18.0";
#[derive(Clone)]
pub(crate) struct ExecStatusService {
    log: ReplicaLogger,
    state_read_executor: Arc<dyn StateReader<State = EthExecutionClient>>,
}

impl ExecStatusService {
    pub(crate) fn new_service(
        log: ReplicaLogger,
        state_read_executor: Arc<dyn StateReader<State = EthExecutionClient>>,
    ) -> EndpointService {
        let base_service = Self {
            log,
            state_read_executor,
        };
        BoxCloneService::new(
            ServiceBuilder::new()
                .layer(GlobalConcurrencyLimitLayer::new(
                    MAX_STATUS_CONCURRENT_REQUESTS,
                ))
                .service(base_service),
        )
    }
}

impl Service<Request<Body>> for ExecStatusService {
    type Response = Response<Body>;
    type Error = BoxError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _unused: Request<Body>) -> Self::Future {
        let log = self.log.clone();
        let response = HttpExecStatusResponse {
            ic_api_version: IC_API_VERSION.to_string(),
            // For test networks, and networks that we still reset
            // rather often, let them indicate the root public key
            // in /api/v2/status, so that agents can fetch them.
            // This is convenient, but of course NOT SECURE.
            //
            // USE WITH EXTREME CAUTION.
            impl_version: Some(ReplicaVersion::default().to_string()),
            impl_hash: REPLICA_BINARY_HASH.get().map(|s| s.to_string()),
            certified_height: Some(self.state_read_executor.latest_certified_height()),
        };
        Box::pin(async move { Ok(common::cbor_response(&response).0) })
    }
}
