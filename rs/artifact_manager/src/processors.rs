//! The tokio thread based implementation of `ArtifactProcessor`

use crate::clients;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use ic_interfaces::{
    artifact_manager::{ArtifactPoolDescriptor, ArtifactProcessor, ProcessingResult},
    artifact_pool::UnvalidatedArtifact,
    canister_http::*,
    certification,
    certification::{Certifier, MutableCertificationPool},
    consensus::Consensus,
    consensus_pool::{ChangeAction as ConsensusAction, ConsensusPoolCache, MutableConsensusPool},
    dkg::{ChangeAction as DkgChangeAction, Dkg, MutableDkgPool},
    ecdsa::{Ecdsa, EcdsaChangeAction, MutableEcdsaPool},
    gossip_pool::GossipPool,
    ingress_manager::IngressHandler,
    ingress_pool::{ChangeAction as IngressAction, MutableIngressPool},
    time_source::{SysTimeSource, TimeSource},
};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::*,
    artifact_kind::*,
    consensus::{certification::CertificationMessage, dkg, ConsensusMessage},
    malicious_flags::MaliciousFlags,
    messages::SignedIngress,
    NodeId,
};
use ic_types::{canister_http::CanisterHttpResponseShare, consensus::HasRank};
use prometheus::{histogram_opts, labels, Histogram, IntCounter};
use std::sync::{
    atomic::{AtomicBool, Ordering::SeqCst},
    Arc, RwLock,
};
use std::thread::{Builder as ThreadBuilder, JoinHandle};
use std::time::Duration;

/// Metrics for a client artifact processor.
struct ArtifactProcessorMetrics {
    /// The processing time histogram.
    processing_time: Histogram,
    /// The processing interval histogram.
    processing_interval: Histogram,
    /// The last update time.
    last_update: std::time::Instant,
}

impl ArtifactProcessorMetrics {
    /// The constructor creates a `ArtifactProcessorMetrics` instance.
    fn new(metrics_registry: MetricsRegistry, client: String) -> Self {
        let processing_time = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "artifact_manager_client_processing_time_seconds",
                "Artifact manager client processing time, in seconds",
                vec![
                    0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0, 2.2, 2.5, 5.0, 8.0,
                    10.0, 15.0, 20.0, 50.0,
                ],
                labels! {"client".to_string() => client.clone()}
            ))
            .unwrap(),
        );
        let processing_interval = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "artifact_manager_client_processing_interval_seconds",
                "Duration between Artifact manager client processing, in seconds",
                vec![
                    0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0, 2.2, 2.5, 5.0, 8.0,
                    10.0, 15.0, 20.0, 50.0,
                ],
                labels! {"client".to_string() => client}
            ))
            .unwrap(),
        );

        Self {
            processing_time,
            processing_interval,
            last_update: std::time::Instant::now(),
        }
    }

    fn with_metrics<T, F: FnOnce() -> T>(&mut self, run: F) -> T {
        self.processing_interval
            .observe((std::time::Instant::now() - self.last_update).as_secs_f64());
        let _timer = self.processing_time.start_timer();
        let result = run();
        self.last_update = std::time::Instant::now();
        result
    }
}

/// Manages the life cycle of the client specific artifact processor thread.
/// Also serves as the front end to enqueue requests to the processor thread.
pub struct ArtifactProcessorManager<Artifact: ArtifactKind + 'static> {
    /// To send the process requests
    sender: Sender<UnvalidatedArtifact<Artifact::Message>>,
    /// Handle for the processing thread
    handle: Option<JoinHandle<()>>,
    /// To signal processing thread to exit.
    /// TODO: handle.abort() does not seem to work as expected
    shutdown: Arc<AtomicBool>,
}

impl<Artifact: ArtifactKind + 'static> ArtifactProcessorManager<Artifact> {
    pub fn new<S: Fn(AdvertSendRequest<Artifact>) + Send + 'static>(
        time_source: Arc<SysTimeSource>,
        metrics_registry: MetricsRegistry,
        client: Box<dyn ArtifactProcessor<Artifact>>,
        send_advert: S,
    ) -> Self
    where
        <Artifact as ic_types::artifact::ArtifactKind>::Message: Send,
    {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let shutdown = Arc::new(AtomicBool::new(false));

        // Spawn the processor thread
        let shutdown_cl = shutdown.clone();
        let handle = ThreadBuilder::new()
            .name(format!("{}_Processor", Artifact::TAG))
            .spawn(move || {
                Self::process_messages(
                    time_source,
                    client,
                    Box::new(send_advert),
                    receiver,
                    shutdown_cl,
                );
            })
            .unwrap();

        Self {
            sender,
            handle: Some(handle),
            shutdown,
        }
    }

    pub fn on_artifact(&self, artifact: UnvalidatedArtifact<Artifact::Message>) {
        self.sender
            .send(artifact)
            .unwrap_or_else(|err| panic!("Failed to send request: {:?}", err));
    }

    // The artifact processor thread loop
    #[allow(clippy::too_many_arguments)]
    fn process_messages<S: Fn(AdvertSendRequest<Artifact>) + Send + 'static>(
        time_source: Arc<SysTimeSource>,
        client: Box<dyn ArtifactProcessor<Artifact>>,
        send_advert: Box<S>,
        receiver: Receiver<UnvalidatedArtifact<Artifact::Message>>,
        shutdown: Arc<AtomicBool>,
    ) {
        let mut last_on_state_change_result = ProcessingResult::StateUnchanged;
        while !shutdown.load(SeqCst) {
            // TODO: assess impact of continued processing in same
            // iteration if StateChanged
            let recv_timeout = match last_on_state_change_result {
                ProcessingResult::StateChanged => Duration::from_millis(0),
                ProcessingResult::StateUnchanged => {
                    Duration::from_millis(ARTIFACT_MANAGER_TIMER_DURATION_MSEC)
                }
            };
            let recv_artifact = receiver.recv_timeout(recv_timeout);
            let batched_artifacts = match recv_artifact {
                Ok(artifact) => {
                    let mut artifacts = vec![artifact];
                    while let Ok(artifact) = receiver.try_recv() {
                        artifacts.push(artifact);
                    }
                    artifacts
                }
                Err(RecvTimeoutError::Timeout) => vec![],
                Err(RecvTimeoutError::Disconnected) => return,
            };
            time_source.update_time().ok();
            let (adverts, on_state_change_result) =
                client.process_changes(time_source.as_ref(), batched_artifacts);
            adverts.into_iter().for_each(&send_advert);
            last_on_state_change_result = on_state_change_result;
        }
    }
}

impl<Artifact: ArtifactKind + 'static> Drop for ArtifactProcessorManager<Artifact> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.shutdown.store(true, SeqCst);
            handle.join().unwrap();
        }
    }
}

/// Periodic duration of `PollEvent` in milliseconds.
const ARTIFACT_MANAGER_TIMER_DURATION_MSEC: u64 = 200;

/// *Consensus* `OnStateChange` client.
pub struct ConsensusProcessor<PoolConsensus> {
    /// The *Consensus* pool.
    consensus_pool: Arc<RwLock<PoolConsensus>>,
    /// The *Consensus* client.
    client: Box<dyn Consensus>,
    /// The invalidated artifacts counter.
    invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<PoolConsensus: MutableConsensusPool + Send + Sync + 'static>
    ConsensusProcessor<PoolConsensus>
{
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Consensus + 'static,
        G: ArtifactPoolDescriptor<ConsensusArtifact, PoolConsensus> + 'static,
        S: Fn(AdvertSendRequest<ConsensusArtifact>) + Send + 'static,
    >(
        send_advert: S,
        (consensus, consensus_gossip): (C, G),
        time_source: Arc<SysTimeSource>,
        consensus_pool: Arc<RwLock<PoolConsensus>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::ConsensusClient<PoolConsensus, G>,
        ArtifactProcessorManager<ConsensusArtifact>,
    ) {
        let client = Self {
            consensus_pool: consensus_pool.clone(),
            client: Box::new(consensus),
            invalidated_artifacts: metrics_registry.int_counter(
                "consensus_invalidated_artifacts",
                "The number of invalidated consensus artifacts",
            ),
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            Box::new(client),
            send_advert,
        );
        (
            clients::ConsensusClient::new(consensus_pool, consensus_gossip),
            manager,
        )
    }
}

impl<PoolConsensus: MutableConsensusPool + Send + Sync + 'static>
    ArtifactProcessor<ConsensusArtifact> for ConsensusProcessor<PoolConsensus>
{
    /// The method processes changes in the *Consensus* pool and ingress pool.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<ConsensusMessage>>,
    ) -> (Vec<AdvertSendRequest<ConsensusArtifact>>, ProcessingResult) {
        {
            let mut consensus_pool = self.consensus_pool.write().unwrap();
            for artifact in artifacts {
                debug!(
                    tag => "consensus_trace",
                    self.log,
                    "process_change::artifact {}",
                    serde_json::to_string(&artifact).unwrap()
                );
                consensus_pool.insert(artifact)
            }
        }
        let mut adverts = Vec::new();
        let change_set = {
            let consensus_pool = self.consensus_pool.read().unwrap();
            self.client.on_state_change(&*consensus_pool)
        };
        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        for change_action in change_set.iter() {
            debug!(
                tag => "consensus_trace",
                self.log,
                "process_change::change_action {}",
                serde_json::to_string(&change_action).unwrap()
            );
            match change_action {
                ConsensusAction::AddToValidated(to_add) => {
                    adverts.push(ConsensusArtifact::message_to_advert_send_request(
                        to_add,
                        ArtifactDestination::AllPeersInSubnet,
                    ));
                    if let ConsensusMessage::BlockProposal(p) = to_add {
                        let rank = p.clone().content.decompose().1.rank();
                        debug!(
                            self.log,
                            "Added proposal {:?} of rank {:?} to artifact pool", p, rank
                        );
                    }
                }
                ConsensusAction::MoveToValidated(to_move) => {
                    adverts.push(ConsensusArtifact::message_to_advert_send_request(
                        to_move,
                        ArtifactDestination::AllPeersInSubnet,
                    ));
                    if let ConsensusMessage::BlockProposal(p) = to_move {
                        let rank = p.clone().content.decompose().1.rank();
                        debug!(
                            self.log,
                            "Moved proposal {:?} of rank {:?} to artifact pool", p, rank
                        );
                    }
                }
                ConsensusAction::RemoveFromValidated(_) => {}
                ConsensusAction::RemoveFromUnvalidated(_) => {}
                ConsensusAction::PurgeValidatedBelow(_) => {}
                ConsensusAction::PurgeUnvalidatedBelow(_) => {}
                ConsensusAction::HandleInvalid(artifact, s) => {
                    self.invalidated_artifacts.inc();
                    warn!(self.log, "Invalid artifact {} {:?}", s, artifact);
                }
            }
        }
        debug!(
            tag => "consensus_trace",
            self.log,
            "process_change::apply_changes {}",
            serde_json::to_string(&time_source.get_relative_time()).unwrap()
        );

        self.consensus_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);

        (adverts, changed)
    }
}

/// The ingress `OnStateChange` client.
pub struct IngressProcessor<PoolIngress> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<PoolIngress>>,
    /// The ingress handler.
    client: Arc<dyn IngressHandler + Send + Sync>,
    /// Our node id
    node_id: NodeId,
}

impl<PoolIngress: MutableIngressPool + Send + Sync + 'static> IngressProcessor<PoolIngress> {
    #[allow(clippy::too_many_arguments)]
    pub fn build<S: Fn(AdvertSendRequest<IngressArtifact>) + Send + 'static>(
        send_advert: S,
        time_source: Arc<SysTimeSource>,
        ingress_pool: Arc<RwLock<PoolIngress>>,
        ingress_handler: Arc<dyn IngressHandler + Send + Sync>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
        node_id: NodeId,
        malicious_flags: MaliciousFlags,
    ) -> (
        clients::IngressClient<PoolIngress>,
        ArtifactProcessorManager<IngressArtifact>,
    ) {
        let client = Self {
            ingress_pool: ingress_pool.clone(),
            client: ingress_handler,
            node_id,
        };
        let manager = ArtifactProcessorManager::new(
            time_source.clone(),
            metrics_registry,
            Box::new(client),
            send_advert,
        );
        (
            clients::IngressClient::new(time_source, ingress_pool, log, malicious_flags),
            manager,
        )
    }
}

impl<PoolIngress: MutableIngressPool + Send + Sync + 'static> ArtifactProcessor<IngressArtifact>
    for IngressProcessor<PoolIngress>
{
    /// The method processes changes in the ingress pool.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<SignedIngress>>,
    ) -> (Vec<AdvertSendRequest<IngressArtifact>>, ProcessingResult) {
        {
            let mut ingress_pool = self.ingress_pool.write().unwrap();
            for artifact in artifacts {
                ingress_pool.insert(artifact)
            }
        }
        let change_set = {
            let pool = self.ingress_pool.read().unwrap();
            self.client.on_state_change(&*pool)
        };

        let mut adverts = Vec::new();
        for change_action in change_set.iter() {
            match change_action {
                IngressAction::MoveToValidated((
                    message_id,
                    source_node_id,
                    size,
                    attribute,
                    integrity_hash,
                )) => {
                    if *source_node_id == self.node_id {
                        adverts.push(AdvertSendRequest {
                            advert: Advert {
                                size: *size,
                                id: message_id.clone(),
                                attribute: attribute.clone(),
                                integrity_hash: integrity_hash.clone(),
                            },
                            dest: ArtifactDestination::AllPeersInSubnet,
                        });
                    }
                }
                IngressAction::RemoveFromUnvalidated(_)
                | IngressAction::RemoveFromValidated(_)
                | IngressAction::PurgeBelowExpiry(_) => {}
            }
        }
        self.ingress_pool
            .write()
            .unwrap()
            .apply_changeset(change_set);
        (adverts, ProcessingResult::StateUnchanged)
    }
}

/// Certification `OnStateChange` client.
pub struct CertificationProcessor<PoolCertification> {
    /// The *Consensus* pool cache.
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    /// The certification pool.
    certification_pool: Arc<RwLock<PoolCertification>>,
    /// The certifier.
    client: Box<dyn Certifier>,
    /// The invalidated artifacts counter.
    //invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<PoolCertification: MutableCertificationPool + Send + Sync + 'static>
    CertificationProcessor<PoolCertification>
{
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Certifier + 'static,
        G: ArtifactPoolDescriptor<CertificationArtifact, PoolCertification> + 'static,
        S: Fn(AdvertSendRequest<CertificationArtifact>) + Send + 'static,
    >(
        send_advert: S,
        (certifier, certifier_gossip): (C, G),
        time_source: Arc<SysTimeSource>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        certification_pool: Arc<RwLock<PoolCertification>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::CertificationClient<PoolCertification, G>,
        ArtifactProcessorManager<CertificationArtifact>,
    ) {
        let client = Self {
            consensus_pool_cache: consensus_pool_cache.clone(),
            certification_pool: certification_pool.clone(),
            client: Box::new(certifier),
            // invalidated_artifacts: metrics_registry.int_counter(
            //     "certification_invalidated_artifacts",
            //     "The number of invalidated certification artifacts",
            // ),
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            Box::new(client),
            send_advert,
        );
        (
            clients::CertificationClient::new(certification_pool, certifier_gossip),
            manager,
        )
    }
}

impl<PoolCertification: MutableCertificationPool + Send + Sync + 'static>
    ArtifactProcessor<CertificationArtifact> for CertificationProcessor<PoolCertification>
{
    /// The method processes changes in the certification pool.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<CertificationMessage>>,
    ) -> (
        Vec<AdvertSendRequest<CertificationArtifact>>,
        ProcessingResult,
    ) {
        {
            let mut certification_pool = self.certification_pool.write().unwrap();
            for artifact in artifacts {
                certification_pool.insert(artifact.message)
            }
        }
        let mut adverts = Vec::new();
        let change_set = self.client.on_state_change(
            self.consensus_pool_cache.as_ref(),
            self.certification_pool.clone(),
        );
        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        for action in change_set.iter() {
            match action {
                certification::ChangeAction::AddToValidated(msg) => {
                    adverts.push(CertificationArtifact::message_to_advert_send_request(
                        msg,
                        ArtifactDestination::AllPeersInSubnet,
                    ))
                }
                certification::ChangeAction::MoveToValidated(msg) => {
                    adverts.push(CertificationArtifact::message_to_advert_send_request(
                        msg,
                        ArtifactDestination::AllPeersInSubnet,
                    ))
                }
                certification::ChangeAction::HandleInvalid(msg, reason) => {
                    //self.invalidated_artifacts.inc();
                    warn!(
                        self.log,
                        "Invalid certification message ({:?}): {:?}", reason, msg
                    );
                }
                _ => {}
            }
        }
        self.certification_pool
            .write()
            .unwrap()
            .apply_changes(change_set);
        (adverts, changed)
    }
}

/// Execution Certification `OnStateChange` client.
pub struct ExecCertificationProcessor<PoolCertification> {
    /// The *Consensus* pool cache.
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    /// The certification pool.
    certification_pool: Arc<RwLock<PoolCertification>>,
    /// The certifier.
    client: Box<dyn Certifier>,
    /// The invalidated artifacts counter.
    //invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<PoolCertification: MutableCertificationPool + Send + Sync + 'static>
    ExecCertificationProcessor<PoolCertification>
{
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Certifier + 'static,
        G: ArtifactPoolDescriptor<ExecCertificationArtifact, PoolCertification> + 'static,
        S: Fn(AdvertSendRequest<ExecCertificationArtifact>) + Send + 'static,
    >(
        send_advert: S,
        (certifier, certifier_gossip): (C, G),
        time_source: Arc<SysTimeSource>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        certification_pool: Arc<RwLock<PoolCertification>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::ExecCertificationClient<PoolCertification, G>,
        ArtifactProcessorManager<ExecCertificationArtifact>,
    ) {
        let client = Self {
            consensus_pool_cache: consensus_pool_cache.clone(),
            certification_pool: certification_pool.clone(),
            client: Box::new(certifier),
            // invalidated_artifacts: metrics_registry.int_counter(
            //     "certification_invalidated_artifacts",
            //     "The number of invalidated certification artifacts",
            // ),
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            Box::new(client),
            send_advert,
        );
        (
            clients::ExecCertificationClient::new(certification_pool, certifier_gossip),
            manager,
        )
    }
}

impl<PoolCertification: MutableCertificationPool + Send + Sync + 'static>
    ArtifactProcessor<ExecCertificationArtifact> for ExecCertificationProcessor<PoolCertification>
{
    /// The method processes changes in the certification pool.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<CertificationMessage>>,
    ) -> (
        Vec<AdvertSendRequest<ExecCertificationArtifact>>,
        ProcessingResult,
    ) {
        {
            let mut certification_pool = self.certification_pool.write().unwrap();
            for artifact in artifacts {
                certification_pool.insert(artifact.message)
            }
        }
        let mut adverts = Vec::new();
        let change_set = self.client.on_state_change(
            self.consensus_pool_cache.as_ref(),
            self.certification_pool.clone(),
        );
        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        for action in change_set.iter() {
            match action {
                certification::ChangeAction::AddToValidated(msg) => {
                    adverts.push(ExecCertificationArtifact::message_to_advert_send_request(
                        msg,
                        ArtifactDestination::AllPeersInSubnet,
                    ))
                }
                certification::ChangeAction::MoveToValidated(msg) => {
                    adverts.push(ExecCertificationArtifact::message_to_advert_send_request(
                        msg,
                        ArtifactDestination::AllPeersInSubnet,
                    ))
                }
                certification::ChangeAction::HandleInvalid(msg, reason) => {
                    //self.invalidated_artifacts.inc();
                    warn!(
                        self.log,
                        "Invalid certification message ({:?}): {:?}", reason, msg
                    );
                }
                _ => {}
            }
        }
        self.certification_pool
            .write()
            .unwrap()
            .apply_changes(change_set);
        (adverts, changed)
    }
}

/// Distributed key generation (DKG) `OnStateChange` client.
pub struct DkgProcessor<PoolDkg> {
    /// The DKG pool, protected by a read-write lock and automatic reference
    /// counting.
    dkg_pool: Arc<RwLock<PoolDkg>>,
    /// The DKG client.
    client: Box<dyn Dkg>,
    /// The invalidated artifacts counter.
    invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<PoolDkg: MutableDkgPool + Send + Sync + 'static> DkgProcessor<PoolDkg> {
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Dkg + 'static,
        G: ArtifactPoolDescriptor<DkgArtifact, PoolDkg> + 'static,
        S: Fn(AdvertSendRequest<DkgArtifact>) + Send + 'static,
    >(
        send_advert: S,
        (dkg, dkg_gossip): (C, G),
        time_source: Arc<SysTimeSource>,
        dkg_pool: Arc<RwLock<PoolDkg>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::DkgClient<PoolDkg, G>,
        ArtifactProcessorManager<DkgArtifact>,
    ) {
        let client = Self {
            dkg_pool: dkg_pool.clone(),
            client: Box::new(dkg),
            invalidated_artifacts: metrics_registry.int_counter(
                "dkg_invalidated_artifacts",
                "The number of invalidated DKG artifacts",
            ),
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            Box::new(client),
            send_advert,
        );
        (clients::DkgClient::new(dkg_pool, dkg_gossip), manager)
    }
}

impl<PoolDkg: MutableDkgPool + Send + Sync + 'static> ArtifactProcessor<DkgArtifact>
    for DkgProcessor<PoolDkg>
{
    /// The method processes changes in the DKG pool.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<dkg::Message>>,
    ) -> (Vec<AdvertSendRequest<DkgArtifact>>, ProcessingResult) {
        {
            let mut dkg_pool = self.dkg_pool.write().unwrap();
            for artifact in artifacts {
                dkg_pool.insert(artifact)
            }
        }
        let mut adverts = Vec::new();
        let change_set = {
            let dkg_pool = self.dkg_pool.read().unwrap();
            let change_set = self.client.on_state_change(&*dkg_pool);
            for change_action in change_set.iter() {
                match change_action {
                    DkgChangeAction::AddToValidated(to_add) => {
                        adverts.push(DkgArtifact::message_to_advert_send_request(
                            to_add,
                            ArtifactDestination::AllPeersInSubnet,
                        ))
                    }
                    DkgChangeAction::MoveToValidated(message) => {
                        adverts.push(DkgArtifact::message_to_advert_send_request(
                            message,
                            ArtifactDestination::AllPeersInSubnet,
                        ))
                    }
                    DkgChangeAction::HandleInvalid(msg, reason) => {
                        self.invalidated_artifacts.inc();
                        warn!(self.log, "Invalid DKG message ({:?}): {:?}", reason, msg);
                    }
                    _ => (),
                }
            }
            change_set
        };
        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        self.dkg_pool.write().unwrap().apply_changes(change_set);
        (adverts, changed)
    }
}

/// ECDSA `OnStateChange` client.
pub struct EcdsaProcessor<PoolEcdsa> {
    ecdsa_pool: Arc<RwLock<PoolEcdsa>>,
    client: Box<dyn Ecdsa>,
    ecdsa_pool_update_duration: Histogram,
    log: ReplicaLogger,
}

impl<PoolEcdsa: MutableEcdsaPool + Send + Sync + 'static> EcdsaProcessor<PoolEcdsa> {
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Ecdsa + 'static,
        G: ArtifactPoolDescriptor<EcdsaArtifact, PoolEcdsa> + 'static,
        S: Fn(AdvertSendRequest<EcdsaArtifact>) + Send + 'static,
    >(
        send_advert: S,
        (ecdsa, ecdsa_gossip): (C, G),
        time_source: Arc<SysTimeSource>,
        ecdsa_pool: Arc<RwLock<PoolEcdsa>>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> (
        clients::EcdsaClient<PoolEcdsa, G>,
        ArtifactProcessorManager<EcdsaArtifact>,
    ) {
        let ecdsa_pool_update_duration = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "ecdsa_pool_update_duration_seconds",
                "Time to apply changes to ECDSA artifact pool, in seconds",
                vec![
                    0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0, 2.2, 2.5, 5.0, 8.0,
                    10.0, 15.0, 20.0, 50.0,
                ]
            ))
            .unwrap(),
        );

        let client = Self {
            ecdsa_pool: ecdsa_pool.clone(),
            client: Box::new(ecdsa),
            ecdsa_pool_update_duration,
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            Box::new(client),
            send_advert,
        );
        (clients::EcdsaClient::new(ecdsa_pool, ecdsa_gossip), manager)
    }
}

impl<PoolEcdsa: MutableEcdsaPool + Send + Sync + 'static> ArtifactProcessor<EcdsaArtifact>
    for EcdsaProcessor<PoolEcdsa>
{
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<EcdsaMessage>>,
    ) -> (Vec<AdvertSendRequest<EcdsaArtifact>>, ProcessingResult) {
        {
            let mut ecdsa_pool = self.ecdsa_pool.write().unwrap();
            for artifact in artifacts {
                ecdsa_pool.insert(artifact)
            }
        }

        let mut adverts = Vec::new();
        let change_set = {
            let ecdsa_pool = self.ecdsa_pool.read().unwrap();
            let change_set = self.client.on_state_change(&*ecdsa_pool);

            for change_action in change_set.iter() {
                match change_action {
                    // 1. Notify all peers for ecdsa messages received directly by us
                    // 2. For relayed ecdsa support messages: don't notify any peers.
                    // 3. For other relayed messages: still notify peers.
                    EcdsaChangeAction::AddToValidated(msg) => {
                        adverts.push(EcdsaArtifact::message_to_advert_send_request(
                            msg,
                            ArtifactDestination::AllPeersInSubnet,
                        ))
                    }
                    EcdsaChangeAction::MoveToValidated(msg_id) => {
                        if let Some(msg) = ecdsa_pool.unvalidated().get(msg_id) {
                            match msg {
                                EcdsaMessage::EcdsaDealingSupport(_) => (),
                                _ => adverts.push(EcdsaArtifact::message_to_advert_send_request(
                                    &msg,
                                    ArtifactDestination::AllPeersInSubnet,
                                )),
                            }
                        } else {
                            warn!(
                                self.log,
                                "EcdsaProcessor::MoveToValidated(): artifact not found: {:?}",
                                msg_id
                            );
                        }
                    }
                    EcdsaChangeAction::RemoveValidated(_) => {}
                    EcdsaChangeAction::RemoveUnvalidated(_) => {}
                    EcdsaChangeAction::HandleInvalid(_, _) => {}
                }
            }
            change_set
        };

        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        let _timer = self.ecdsa_pool_update_duration.start_timer();
        self.ecdsa_pool.write().unwrap().apply_changes(change_set);
        (adverts, changed)
    }
}

pub struct CanisterHttpProcessor<PoolCanisterHttp> {
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    canister_http_pool: Arc<RwLock<PoolCanisterHttp>>,
    client: Arc<RwLock<dyn CanisterHttpPoolManager + Sync + 'static>>,
    log: ReplicaLogger,
}

impl<
        PoolCanisterHttp: MutableCanisterHttpPool + GossipPool<CanisterHttpArtifact> + Send + Sync + 'static,
    > CanisterHttpProcessor<PoolCanisterHttp>
{
    pub fn build<
        C: CanisterHttpPoolManager + Sync + 'static,
        G: ArtifactPoolDescriptor<CanisterHttpArtifact, PoolCanisterHttp> + Send + Sync + 'static,
        S: Fn(AdvertSendRequest<CanisterHttpArtifact>) + Send + 'static,
    >(
        send_advert: S,
        (pool_manager, canister_http_gossip): (C, G),
        time_source: Arc<SysTimeSource>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        canister_http_pool: Arc<RwLock<PoolCanisterHttp>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::CanisterHttpClient<PoolCanisterHttp, G>,
        ArtifactProcessorManager<CanisterHttpArtifact>,
    ) {
        let client = Self {
            consensus_pool_cache: consensus_pool_cache.clone(),
            canister_http_pool: canister_http_pool.clone(),
            client: Arc::new(RwLock::new(pool_manager)),
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            Box::new(client),
            send_advert,
        );
        (
            clients::CanisterHttpClient::new(canister_http_pool, canister_http_gossip),
            manager,
        )
    }
}

impl<PoolCanisterHttp: MutableCanisterHttpPool + Send + Sync + 'static>
    ArtifactProcessor<CanisterHttpArtifact> for CanisterHttpProcessor<PoolCanisterHttp>
{
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<CanisterHttpResponseShare>>,
    ) -> (
        Vec<AdvertSendRequest<CanisterHttpArtifact>>,
        ProcessingResult,
    ) {
        {
            let mut pool = self.canister_http_pool.write().unwrap();
            for artifact in artifacts {
                pool.insert(artifact);
            }
        }

        let mut adverts = Vec::new();
        let change_set = {
            let canister_http_pool = self.canister_http_pool.read().unwrap();
            let change_set = self
                .client
                .write()
                .unwrap()
                .on_state_change(self.consensus_pool_cache.as_ref(), &*canister_http_pool);

            for change_action in change_set.iter() {
                match change_action {
                    CanisterHttpChangeAction::AddToValidated(share, _) => {
                        adverts.push(CanisterHttpArtifact::message_to_advert_send_request(
                            share,
                            ArtifactDestination::AllPeersInSubnet,
                        ))
                    }
                    CanisterHttpChangeAction::MoveToValidated(msg_id) => {
                        if let Some(msg) = canister_http_pool.lookup_unvalidated(msg_id) {
                            adverts.push(CanisterHttpArtifact::message_to_advert_send_request(
                                &msg,
                                ArtifactDestination::AllPeersInSubnet,
                            ))
                        } else {
                            warn!(
                                self.log,
                                "CanisterHttpProcessor::MoveToValidated(): artifact not found: {:?}",
                                msg_id
                            );
                        }
                    }
                    CanisterHttpChangeAction::RemoveContent(_) => {}
                    CanisterHttpChangeAction::RemoveValidated(_) => {}
                    CanisterHttpChangeAction::RemoveUnvalidated(_) => {}
                    CanisterHttpChangeAction::HandleInvalid(_, _) => {}
                }
            }
            change_set
        };

        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        self.canister_http_pool
            .write()
            .unwrap()
            .apply_changes(change_set);
        (adverts, changed)
    }
}
