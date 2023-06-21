//! The module contains implementations of the 'ArtifactClient' trait for all
//! P2P clients that require consensus over their artifacts.

use ic_interfaces::{
    artifact_manager::ArtifactClient,
    artifact_pool::{
        ArtifactPoolError, PriorityFnAndFilterProducer, ReplicaVersionMismatch, ValidatedPoolReader,
    },
};
use ic_types::{
    artifact::*,
    artifact_kind::*,
    canister_http::*,
    chunkable::*,
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, ConsensusMessage,
        HasVersion,
    },
    malicious_flags::MaliciousFlags,
    messages::SignedIngress,
    single_chunked::*,
    ReplicaVersion,
};
use std::sync::{Arc, RwLock};

/// The *Consensus* `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct ConsensusClient<Pool, T> {
    /// The *Consensus* pool, protected by a read-write lock and automatic
    /// reference counting.
    pool: Arc<RwLock<Pool>>,
    /// The `ConsensusGossip` client.
    priority_fn_and_filter: T,
}

impl<Pool, T> ConsensusClient<Pool, T> {
    /// The constructor creates a `ConsensusClient` instance.
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: T) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

/// The function checks if the version of the given artifact matches the default
/// protocol version and returns an error if it does not.
fn check_protocol_version<T: HasVersion>(artifact: &T) -> Result<(), ReplicaVersionMismatch> {
    let version = artifact.version();
    let expected_version = ReplicaVersion::default();
    if version != &expected_version {
        Err(ReplicaVersionMismatch {
            expected: expected_version,
            artifact: version.clone(),
        })
    } else {
        Ok(())
    }
}

impl<
        Pool: ValidatedPoolReader<ConsensusArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<ConsensusArtifact, Pool> + 'static,
    > ArtifactClient<ConsensusArtifact> for ConsensusClient<Pool, T>
{
    /// The method checks if the protocol version in the *Consensus* message is
    /// correct.
    ///
    /// If the version is correct, the message is returned in an
    /// `ArtifactAcceptance` enum.
    fn check_artifact_acceptance(&self, msg: &ConsensusMessage) -> Result<(), ArtifactPoolError> {
        check_protocol_version(msg)?;
        Ok(())
    }

    /// The method returns `true` if and only if the *Consensus* pool contains
    /// the given *Consensus* message ID.
    fn has_artifact(&self, msg_id: &ConsensusMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the *Consensus* message with the given ID from the
    /// *Consensus* pool if available.
    fn get_validated_by_identifier(&self, msg_id: &ConsensusMessageId) -> Option<ConsensusMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the *Consensus* message filter.
    fn get_filter(&self) -> ConsensusMessageFilter {
        self.priority_fn_and_filter.get_filter()
    }

    /// The method returns all adverts for validated *Consensus* artifacts.
    fn get_all_validated_by_filter(
        &self,
        filter: &ConsensusMessageFilter,
    ) -> Vec<Advert<ConsensusArtifact>> {
        self.pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter)
            .map(|msg| ConsensusArtifact::message_to_advert(&msg))
            .collect()
    }

    /// The method returns the priority function.
    fn get_priority_function(&self) -> PriorityFn<ConsensusMessageId, ConsensusMessageAttribute> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }

    /// The method returns the chunk tracker for the given *Consensus* message
    /// ID.
    fn get_chunk_tracker(&self, _id: &ConsensusMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Consensus)
    }
}

/// The ingress `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct IngressClient<Pool, T> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    pool: Arc<RwLock<Pool>>,
    priority_fn_and_filter: T,
    #[allow(dead_code)]
    malicious_flags: MaliciousFlags,
}

impl<Pool, T> IngressClient<Pool, T> {
    /// The constructor creates an `IngressClient` instance.
    pub fn new(
        pool: Arc<RwLock<Pool>>,
        priority_fn_and_filter: T,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
            malicious_flags,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<IngressArtifact> + Send + Sync + 'static,
        T: PriorityFnAndFilterProducer<IngressArtifact, Pool> + 'static,
    > ArtifactClient<IngressArtifact> for IngressClient<Pool, T>
{
    /// The method checks if the ingress pool contains an ingress message with
    /// the given ID.
    fn has_artifact(&self, msg_id: &IngressMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the `SignedIngress` message with the given ingress
    /// message ID from the ingress pool (if available).
    fn get_validated_by_identifier(&self, msg_id: &IngressMessageId) -> Option<SignedIngress> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the priority function.
    fn get_priority_function(&self) -> PriorityFn<IngressMessageId, IngressMessageAttribute> {
        let pool = self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(&pool)
    }

    /// The method returns a new chunk tracker for (single-chunked) ingress
    /// messages, ignoring the given ingress message ID.
    fn get_chunk_tracker(&self, _id: &IngressMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Ingress)
    }
}

/// The certification `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct CertificationClient<Pool, T> {
    /// The certification pool, protected by a read-write lock and automatic
    /// reference counting.
    pool: Arc<RwLock<Pool>>,
    /// The `PriorityFnAndFilterProducer` client.
    priority_fn_and_filter: T,
}

impl<Pool, T> CertificationClient<Pool, T> {
    /// The constructor creates a `CertificationClient` instance.
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: T) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<CertificationArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<CertificationArtifact, Pool> + 'static,
    > ArtifactClient<CertificationArtifact> for CertificationClient<Pool, T>
{
    /// The method checks if the certification pool contains a certification
    /// message with the given ID.
    fn has_artifact(&self, msg_id: &CertificationMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the `CertificationMessage` for the given
    /// certification message ID if available.
    fn get_validated_by_identifier(
        &self,
        msg_id: &CertificationMessageId,
    ) -> Option<CertificationMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the certification message filter.
    fn get_filter(&self) -> CertificationMessageFilter {
        self.priority_fn_and_filter.get_filter()
    }

    /// The method returns all adverts for validated certification messages.
    fn get_all_validated_by_filter(
        &self,
        filter: &CertificationMessageFilter,
    ) -> Vec<Advert<CertificationArtifact>> {
        self.pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter)
            .map(|msg| CertificationArtifact::message_to_advert(&msg))
            .collect()
    }

    /// The method returns the priority function.
    fn get_priority_function(
        &self,
    ) -> PriorityFn<CertificationMessageId, CertificationMessageAttribute> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }

    /// The method returns a new (single-chunked) certification tracker,
    /// ignoring the certification message ID.
    fn get_chunk_tracker(&self, _id: &CertificationMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Certification)
    }
}

/// The execution certification `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct ExecCertificationClient<Pool, T> {
    /// The certification pool, protected by a read-write lock and automatic
    /// reference counting.
    pool: Arc<RwLock<Pool>>,
    /// The `PriorityFnAndFilterProducer` client.
    priority_fn_and_filter: T,
}

impl<Pool, T> ExecCertificationClient<Pool, T> {
    /// The constructor creates a `CertificationClient` instance.
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: T) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<ExecCertificationArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<ExecCertificationArtifact, Pool> + 'static,
    > ArtifactClient<ExecCertificationArtifact> for ExecCertificationClient<Pool, T>
{
    /// The method checks if the certification pool contains a certification
    /// message with the given ID.
    fn has_artifact(&self, msg_id: &ExecCertificationMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the `CertificationMessage` for the given
    /// certification message ID if available.
    fn get_validated_by_identifier(
        &self,
        msg_id: &ExecCertificationMessageId,
    ) -> Option<ExecCertificationMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the certification message filter.
    fn get_filter(&self) -> CertificationMessageFilter {
        self.priority_fn_and_filter.get_filter()
    }

    /// The method returns all adverts for validated certification messages.
    fn get_all_validated_by_filter(
        &self,
        filter: &CertificationMessageFilter,
    ) -> Vec<Advert<ExecCertificationArtifact>> {
        self.pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter)
            .map(|msg| ExecCertificationArtifact::message_to_advert(&msg))
            .collect()
    }

    /// The method returns the priority function.
    fn get_priority_function(
        &self,
    ) -> PriorityFn<ExecCertificationMessageId, ExecCertificationMessageAttribute> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }

    /// The method returns a new (single-chunked) certification tracker,
    /// ignoring the certification message ID.
    fn get_chunk_tracker(
        &self,
        _id: &ExecCertificationMessageId,
    ) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::ExecCertification)
    }
}

/// The unchained beacon certification `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct UCBCertificationClient<Pool, T> {
    /// The certification pool, protected by a read-write lock and automatic
    /// reference counting.
    pool: Arc<RwLock<Pool>>,
    /// The `PriorityFnAndFilterProducer` client.
    priority_fn_and_filter: T,
}

impl<Pool, T> UCBCertificationClient<Pool, T> {
    /// The constructor creates a `CertificationClient` instance.
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: T) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<UCBCertificationArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<UCBCertificationArtifact, Pool> + 'static,
    > ArtifactClient<UCBCertificationArtifact> for UCBCertificationClient<Pool, T>
{
    /// The method checks if the certification pool contains a certification
    /// message with the given ID.
    fn has_artifact(&self, msg_id: &UCBCertificationMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the `CertificationMessage` for the given
    /// certification message ID if available.
    fn get_validated_by_identifier(
        &self,
        msg_id: &UCBCertificationMessageId,
    ) -> Option<UCBCertificationMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the certification message filter.
    fn get_filter(&self) -> CertificationMessageFilter {
        self.priority_fn_and_filter.get_filter()
    }

    /// The method returns all adverts for validated certification messages.
    fn get_all_validated_by_filter(
        &self,
        filter: &CertificationMessageFilter,
    ) -> Vec<Advert<UCBCertificationArtifact>> {
        self.pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter)
            .map(|msg| UCBCertificationArtifact::message_to_advert(&msg))
            .collect()
    }

    /// The method returns the priority function.
    fn get_priority_function(
        &self,
    ) -> PriorityFn<UCBCertificationMessageId, UCBCertificationMessageAttribute> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }

    /// The method returns a new (single-chunked) certification tracker,
    /// ignoring the certification message ID.
    fn get_chunk_tracker(
        &self,
        _id: &UCBCertificationMessageId,
    ) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::UCBCertification)
    }
}

/// The DKG client.
pub struct DkgClient<Pool, T> {
    /// The DKG pool, protected by a read-write lock and automatic reference
    /// counting.
    pool: Arc<RwLock<Pool>>,
    /// The `DkgGossip` client.
    priority_fn_and_filter: T,
}

impl<Pool, T> DkgClient<Pool, T> {
    /// The constructor creates a `DkgClient` instance.
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: T) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<DkgArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<DkgArtifact, Pool> + 'static,
    > ArtifactClient<DkgArtifact> for DkgClient<Pool, T>
{
    /// The method checks if the protocol version is correct.
    ///
    /// If this is the case, the artifact is returned wrapped in an
    /// `ArtifactAcceptance` enum.
    fn check_artifact_acceptance(&self, msg: &DkgMessage) -> Result<(), ArtifactPoolError> {
        check_protocol_version(msg)?;
        Ok(())
    }

    /// The method checks if the DKG pool contains a DKG message with the given
    /// ID.
    fn has_artifact(&self, msg_id: &DkgMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the validated DKG message for the given DKG message
    /// if available.
    fn get_validated_by_identifier(&self, msg_id: &DkgMessageId) -> Option<DkgMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the priority function.
    fn get_priority_function(&self) -> PriorityFn<DkgMessageId, DkgMessageAttribute> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }

    /// The method returns a new (single-chunked) DKG message tracker.
    fn get_chunk_tracker(&self, _id: &DkgMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Dkg)
    }
}

/// The ECDSA client.
pub struct EcdsaClient<Pool, T> {
    pool: Arc<RwLock<Pool>>,
    priority_fn_and_filter: T,
}

impl<Pool, T> EcdsaClient<Pool, T> {
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: T) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<EcdsaArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<EcdsaArtifact, Pool> + 'static,
    > ArtifactClient<EcdsaArtifact> for EcdsaClient<Pool, T>
{
    fn has_artifact(&self, msg_id: &EcdsaMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    fn get_validated_by_identifier(&self, msg_id: &EcdsaMessageId) -> Option<EcdsaMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    fn get_priority_function(&self) -> PriorityFn<EcdsaMessageId, EcdsaMessageAttribute> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }

    fn get_chunk_tracker(&self, _id: &EcdsaMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Ecdsa)
    }
}

/// The CanisterHttp Client
pub struct CanisterHttpClient<Pool, T> {
    pool: Arc<RwLock<Pool>>,
    priority_fn_and_filter: T,
}

impl<Pool, T> CanisterHttpClient<Pool, T> {
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: T) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<CanisterHttpArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<CanisterHttpArtifact, Pool> + 'static,
    > ArtifactClient<CanisterHttpArtifact> for CanisterHttpClient<Pool, T>
{
    fn has_artifact(&self, msg_id: &CanisterHttpResponseId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    fn get_validated_by_identifier(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    fn get_priority_function(
        &self,
    ) -> PriorityFn<CanisterHttpResponseId, CanisterHttpResponseAttribute> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }

    fn get_chunk_tracker(&self, _id: &CanisterHttpResponseId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::CanisterHttp)
    }
}
