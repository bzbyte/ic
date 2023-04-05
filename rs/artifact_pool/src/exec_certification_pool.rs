use crate::certification_pool::MutablePoolSection;
use crate::height_index::HeightIndex;
use crate::metrics::{PoolMetrics, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED};
use ic_config::artifact_pool::{ArtifactPoolConfig, PersistentPoolBackend};
use ic_interfaces::{
    certification::{CertificationPool, ChangeAction, ChangeSet, MutableCertificationPool},
    gossip_pool::GossipPool,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_types::artifact::ExecCertificationMessageId;
use ic_types::consensus::certification::ExecCertificationMessage;
use ic_types::crypto::crypto_hash;
use ic_types::{
    artifact::CertificationMessageFilter,
    artifact_kind::ExecCertificationArtifact,
    consensus::certification::{
        Certification, CertificationMessage, CertificationMessageHash, CertificationShare,
    },
    consensus::HasHeight,
    Height,
};
use std::collections::HashSet;

/// Certification pool contains 2 types of artifacts: partial and
/// multi-signatures of (height, hash) pairs, where hash corresponds to an
/// execution state.
pub struct ExecCertificationPoolImpl {
    // Unvalidated shares and certifications are stored separately to improve the validation
    // performance by checking for full certifications first.
    unvalidated_shares: HeightIndex<CertificationShare>,
    unvalidated_certifications: HeightIndex<Certification>,

    pub persistent_pool: Box<dyn MutablePoolSection + Send + Sync>,

    unvalidated_pool_metrics: PoolMetrics,
    validated_pool_metrics: PoolMetrics,
}

const POOL_CERTIFICATION: &str = "exec_certification";

impl ExecCertificationPoolImpl {
    pub fn new(
        config: ArtifactPoolConfig,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> Self {
        let persistent_pool = match config.persistent_pool_backend {
            PersistentPoolBackend::Lmdb(lmdb_config) => Box::new(
                crate::lmdb_pool::PersistentHeightIndexedPool::new_certification_pool_with_path(
                    lmdb_config,
                    config.persistent_pool_read_only,
                    "exec_certification",
                    log,
                ),
            ) as Box<_>,
            #[cfg(feature = "rocksdb_backend")]
            PersistentPoolBackend::RocksDB(config) => Box::new(
                crate::rocksdb_pool::PersistentHeightIndexedPool::new_certification_pool(
                    config, log,
                ),
            ) as Box<_>,
            #[allow(unreachable_patterns)]
            cfg => {
                unimplemented!("Configuration {:?} is not supported", cfg)
            }
        };

        ExecCertificationPoolImpl {
            unvalidated_shares: HeightIndex::default(),
            unvalidated_certifications: HeightIndex::default(),
            persistent_pool,
            unvalidated_pool_metrics: PoolMetrics::new(
                metrics_registry.clone(),
                POOL_CERTIFICATION,
                POOL_TYPE_UNVALIDATED,
            ),
            validated_pool_metrics: PoolMetrics::new(
                metrics_registry,
                POOL_CERTIFICATION,
                POOL_TYPE_VALIDATED,
            ),
        }
    }

    fn validated_certifications(&self) -> Box<dyn Iterator<Item = Certification> + '_> {
        self.persistent_pool.certifications().get_all()
    }

    fn insert_validated_certification(&self, certification: Certification) {
        if let Some(existing_certification) = self
            .persistent_pool
            .certifications()
            .get_by_height(certification.height)
            .next()
        {
            if certification != existing_certification {
                panic!("Certifications are not expected to be added more than once per height.");
            }
        } else {
            self.persistent_pool
                .insert(CertificationMessage::Certification(certification))
        }
    }
}

impl MutableCertificationPool for ExecCertificationPoolImpl {
    fn insert(&mut self, msg: CertificationMessage) {
        let height = msg.height();
        match &msg {
            CertificationMessage::CertificationShare(share) => {
                if self.unvalidated_shares.insert(height, share) {
                    self.unvalidated_pool_metrics
                        .received_artifact_bytes
                        .observe(std::mem::size_of_val(share) as f64);
                }
            }
            CertificationMessage::Certification(cert) => {
                if self.unvalidated_certifications.insert(height, cert) {
                    self.unvalidated_pool_metrics
                        .received_artifact_bytes
                        .observe(std::mem::size_of_val(cert) as f64);
                }
            }
        }
    }

    fn apply_changes(&mut self, change_set: ChangeSet) {
        change_set.into_iter().for_each(|action| match action {
            ChangeAction::AddToValidated(msg) => {
                self.validated_pool_metrics
                    .received_artifact_bytes
                    .observe(std::mem::size_of_val(&msg) as f64);
                self.persistent_pool.insert(msg);
            }

            ChangeAction::MoveToValidated(msg) => {
                let height = msg.height();
                match msg {
                    CertificationMessage::CertificationShare(share) => {
                        self.unvalidated_shares.remove(height, &share);
                        self.validated_pool_metrics
                            .received_artifact_bytes
                            .observe(std::mem::size_of_val(&share) as f64);
                        self.persistent_pool
                            .insert(CertificationMessage::CertificationShare(share));
                    }
                    CertificationMessage::Certification(cert) => {
                        self.unvalidated_certifications.remove(height, &cert);
                        self.validated_pool_metrics
                            .received_artifact_bytes
                            .observe(std::mem::size_of_val(&cert) as f64);
                        self.insert_validated_certification(cert);
                    }
                };
            }

            ChangeAction::RemoveFromUnvalidated(msg) => {
                let height = msg.height();
                match msg {
                    CertificationMessage::CertificationShare(share) => {
                        self.unvalidated_shares.remove(height, &share)
                    }
                    CertificationMessage::Certification(cert) => {
                        self.unvalidated_certifications.remove(height, &cert)
                    }
                };
            }

            ChangeAction::RemoveAllBelow(height) => {
                self.unvalidated_shares.remove_all_below(height);
                self.unvalidated_certifications.remove_all_below(height);
                self.persistent_pool.purge_below(height);
            }

            ChangeAction::HandleInvalid(msg, _) => {
                let height = msg.height();
                match msg {
                    CertificationMessage::CertificationShare(share) => {
                        self.unvalidated_shares.remove(height, &share);
                    }
                    CertificationMessage::Certification(cert) => {
                        self.unvalidated_certifications.remove(height, &cert);
                    }
                };
            }
        });
    }
}

// /// Operations that mutates the persistent pool.
// pub trait MutablePoolSection {
//     fn insert(&self, message: CertificationMessage);
//     fn certifications(&self) -> &dyn HeightIndexedPool<Certification>;
//     fn certification_shares(&self) -> &dyn HeightIndexedPool<CertificationShare>;
//     fn purge_below(&self, height: Height);
// }

impl CertificationPool for ExecCertificationPoolImpl {
    fn certification_at_height(&self, height: Height) -> Option<Certification> {
        self.persistent_pool
            .certifications()
            .get_by_height(height)
            .next()
    }

    fn shares_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = CertificationShare> + '_> {
        self.persistent_pool
            .certification_shares()
            .get_by_height(height)
    }

    fn validated_shares(&self) -> Box<dyn Iterator<Item = CertificationShare> + '_> {
        self.persistent_pool.certification_shares().get_all()
    }

    fn unvalidated_shares_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = &CertificationShare> + '_> {
        self.unvalidated_shares.lookup(height)
    }

    fn unvalidated_certifications_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = &Certification> + '_> {
        self.unvalidated_certifications.lookup(height)
    }

    fn all_heights_with_artifacts(&self) -> Vec<Height> {
        let mut heights: Vec<Height> = self
            .unvalidated_shares
            .heights()
            .cloned()
            .chain(self.unvalidated_certifications.heights().cloned())
            .chain(self.validated_shares().map(|share| share.height))
            .chain(
                self.validated_certifications()
                    .map(|certification| certification.height),
            )
            .collect();
        heights.sort_unstable();
        heights.dedup();
        heights
    }

    fn certified_heights(&self) -> HashSet<Height> {
        self.validated_certifications()
            .map(|certification| certification.height)
            .collect()
    }
}

impl GossipPool<ExecCertificationArtifact> for ExecCertificationPoolImpl {
    fn contains(&self, id: &ExecCertificationMessageId) -> bool {
        // TODO: this is a very inefficient implementation as we compute all hashes
        // every time.
        match &id.0.hash {
            CertificationMessageHash::CertificationShare(hash) => {
                self.unvalidated_shares
                    .lookup(id.0.height)
                    .any(|share| &crypto_hash(share) == hash)
                    || self
                        .persistent_pool
                        .certification_shares()
                        .get_by_height(id.0.height)
                        .any(|share| &crypto_hash(&share) == hash)
            }
            CertificationMessageHash::Certification(hash) => {
                self.unvalidated_certifications
                    .lookup(id.0.height)
                    .any(|cert| &crypto_hash(cert) == hash)
                    || self
                        .persistent_pool
                        .certifications()
                        .get_by_height(id.0.height)
                        .any(|cert| &crypto_hash(&cert) == hash)
            }
        }
    }

    fn get_validated_by_identifier(
        &self,
        id: &ExecCertificationMessageId,
    ) -> Option<ExecCertificationMessage> {
        match &id.0.hash {
            CertificationMessageHash::CertificationShare(hash) => self
                .shares_at_height(id.0.height)
                .find(|share| &crypto_hash(share) == hash)
                .map(|share| {
                    ExecCertificationMessage(CertificationMessage::CertificationShare(share))
                }),
            CertificationMessageHash::Certification(hash) => {
                self.certification_at_height(id.0.height).and_then(|cert| {
                    if &crypto_hash(&cert) == hash {
                        Some(ExecCertificationMessage(
                            CertificationMessage::Certification(cert),
                        ))
                    } else {
                        None
                    }
                })
            }
        }
    }

    fn get_all_validated_by_filter(
        &self,
        filter: &CertificationMessageFilter,
    ) -> Box<dyn Iterator<Item = ExecCertificationMessage> + '_> {
        // Return all validated certifications and all shares above the filter
        let min_height = filter.height.get();
        let all_certs = self
            .validated_certifications()
            .filter(move |cert| cert.height > Height::from(min_height))
            .map(|cert| ExecCertificationMessage(CertificationMessage::Certification(cert)));
        let all_shares = self
            .validated_shares()
            .filter(move |share| share.height > Height::from(min_height))
            .map(|share| ExecCertificationMessage(CertificationMessage::CertificationShare(share)));
        Box::new(all_certs.chain(all_shares))
    }
}
