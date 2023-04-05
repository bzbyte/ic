//! Artifact related types.
//!
//! Notably it includes the following definitions and their sub-types:
//!
//! - [`Artifact`]
//! - [`ArtifactTag`]
//! - [`ArtifactId`]
//! - [`ArtifactAttribute`]
//! - [`ArtifactFilter`]
//!
//! An [`ArtifactKind`] trait is provided for convenience to carry multiple type
//! definitions that belong to the same "artifact kind".
//!
//! All [`Artifact`] sub-types must also implement [`ChunkableArtifact`] trait
//! defined in the chunkable module.
use crate::{
    canister_http::{CanisterHttpResponseAttribute, CanisterHttpResponseShare},
    chunkable::{ArtifactChunk, ChunkId, ChunkableArtifact},
    consensus::{certification::CertificationMessageHash, ConsensusMessageHash},
    crypto::{CryptoHash, CryptoHashOf},
    filetree_sync::{FileTreeSyncArtifact, FileTreeSyncId},
    messages::MessageId,
    p2p::GossipAdvert,
    CryptoHashOfState, Height, Time,
};
use derive_more::{AsMut, AsRef, From, TryInto};
use ic_protobuf::p2p::v1 as pb;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    sync::Arc,
};
use strum_macros::{EnumIter, IntoStaticStr};

pub use crate::{
    consensus::{
        certification::{CertificationMessage, ExecCertificationMessage},
        dkg::Message as DkgMessage,
        ecdsa::{EcdsaArtifactId, EcdsaMessage, EcdsaMessageAttribute},
        ConsensusMessage, ConsensusMessageAttribute,
    },
    messages::SignedIngress,
    state_sync::FILE_GROUP_CHUNK_ID_OFFSET,
};

/// The artifact type
#[derive(From, TryInto, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[try_into(owned, ref, ref_mut)]
#[allow(clippy::large_enum_variant)]
pub enum Artifact {
    ConsensusMessage(ConsensusMessage),
    IngressMessage(SignedIngress),
    CertificationMessage(CertificationMessage),
    DkgMessage(DkgMessage),
    EcdsaMessage(EcdsaMessage),
    CanisterHttpMessage(CanisterHttpResponseShare),
    FileTreeSync(FileTreeSyncArtifact),
    StateSync(StateSyncMessage),
    ExecCertificationMessage(ExecCertificationMessage),
}

/// Artifact attribute type.
#[derive(From, TryInto, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[try_into(owned, ref, ref_mut)]
pub enum ArtifactAttribute {
    ConsensusMessage(ConsensusMessageAttribute),
    IngressMessage(IngressMessageAttribute),
    DkgMessage(DkgMessageAttribute),
    CertificationMessage(CertificationMessageAttribute),
    EcdsaMessage(EcdsaMessageAttribute),
    CanisterHttpMessage(CanisterHttpResponseAttribute),
    FileTreeSync(FileTreeSyncAttribute),
    StateSync(StateSyncAttribute),
    ExecCertificationMessage(ExecCertificationMessageAttribute),
}

/// Artifact identifier type.
#[derive(From, TryInto, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[try_into(owned, ref, ref_mut)]
pub enum ArtifactId {
    ConsensusMessage(ConsensusMessageId),
    IngressMessage(IngressMessageId),
    CertificationMessage(CertificationMessageId),
    CanisterHttpMessage(CanisterHttpResponseId),
    DkgMessage(DkgMessageId),
    EcdsaMessage(EcdsaMessageId),
    FileTreeSync(FileTreeSyncId),
    StateSync(StateSyncArtifactId),
    ExecCertificationMessage(ExecCertificationMessageId),
}

/// Artifact tags is used to select an artifact subtype when we do not have
/// Artifact/ArtifactId/ArtifactAttribute. For example, when lookup quota
/// or filters.
#[derive(EnumIter, TryInto, Clone, Copy, Debug, PartialEq, Eq, Hash, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ArtifactTag {
    #[strum(serialize = "canister_http")]
    CanisterHttpArtifact,
    #[strum(serialize = "certification")]
    CertificationArtifact,
    #[strum(serialize = "consensus")]
    ConsensusArtifact,
    #[strum(serialize = "dkg")]
    DkgArtifact,
    #[strum(serialize = "ecdsa")]
    EcdsaArtifact,
    #[strum(serialize = "file_tree_sync")]
    FileTreeSyncArtifact,
    #[strum(serialize = "ingress")]
    IngressArtifact,
    #[strum(serialize = "state_sync")]
    StateSyncArtifact,
    #[strum(serialize = "exec_certification")]
    ExecCertificationArtifact,
}

impl std::fmt::Display for ArtifactTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ArtifactTag::CanisterHttpArtifact => "CanisterHttp",
                ArtifactTag::CertificationArtifact => "Certification",
                ArtifactTag::ConsensusArtifact => "Consensus",
                ArtifactTag::DkgArtifact => "DKG",
                ArtifactTag::EcdsaArtifact => "ECDSA",
                ArtifactTag::FileTreeSyncArtifact => "FileTreeSync",
                ArtifactTag::IngressArtifact => "Ingress",
                ArtifactTag::StateSyncArtifact => "StateSync",
                ArtifactTag::ExecCertificationArtifact => "ExecCertificationArtifact",
            }
        )
    }
}

impl From<&ArtifactId> for ArtifactTag {
    fn from(id: &ArtifactId) -> ArtifactTag {
        match id {
            ArtifactId::CanisterHttpMessage(_) => ArtifactTag::CanisterHttpArtifact,
            ArtifactId::CertificationMessage(_) => ArtifactTag::CertificationArtifact,
            ArtifactId::ConsensusMessage(_) => ArtifactTag::ConsensusArtifact,
            ArtifactId::DkgMessage(_) => ArtifactTag::DkgArtifact,
            ArtifactId::EcdsaMessage(_) => ArtifactTag::EcdsaArtifact,
            ArtifactId::FileTreeSync(_) => ArtifactTag::FileTreeSyncArtifact,
            ArtifactId::IngressMessage(_) => ArtifactTag::IngressArtifact,
            ArtifactId::StateSync(_) => ArtifactTag::StateSyncArtifact,
            ArtifactId::ExecCertificationMessage(_) => ArtifactTag::ExecCertificationArtifact,
        }
    }
}

// This implementation is used to match the artifact with the right client
// in the ArtifactManager, which indexes all clients based on the ArtifactTag.
impl From<&Artifact> for ArtifactTag {
    fn from(id: &Artifact) -> ArtifactTag {
        match id {
            Artifact::ConsensusMessage(_) => ArtifactTag::ConsensusArtifact,
            Artifact::IngressMessage(_) => ArtifactTag::IngressArtifact,
            Artifact::CertificationMessage(_) => ArtifactTag::CertificationArtifact,
            Artifact::DkgMessage(_) => ArtifactTag::DkgArtifact,
            Artifact::EcdsaMessage(_) => ArtifactTag::EcdsaArtifact,
            Artifact::CanisterHttpMessage(_) => ArtifactTag::CanisterHttpArtifact,
            Artifact::FileTreeSync(_) => ArtifactTag::FileTreeSyncArtifact,
            Artifact::StateSync(_) => ArtifactTag::StateSyncArtifact,
            Artifact::ExecCertificationMessage(_) => ArtifactTag::ExecCertificationArtifact,
        }
    }
}

/// A collection of "filters" used by the gossip protocol for each kind
/// of artifact pools. At the moment it only has consensus filter.
/// Note that it is a struct instead of an enum, because we most likely
/// are interested in all filters.
#[derive(AsMut, AsRef, Default, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArtifactFilter {
    pub consensus_filter: ConsensusMessageFilter,
    pub certification_filter: CertificationMessageFilter,
    pub state_sync_filter: StateSyncFilter,
    pub no_filter: (),
}

/// Priority of artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter)]
pub enum Priority {
    /// Drop the advert, the IC doesn't need the corresponding artifact for
    /// making progress.
    Drop,
    /// Stash the advert. Processing of this advert is suspended, it's not going
    /// to be requested even if there is capacity available for download.
    Stash,

    // All downloadable priority classes. Downloads adhere to quota and
    // bandwidth constraints
    /// Low priority adverts to be considered for download, given that there is
    /// enough capacity.
    Later,
    /// Normal priority adverts.
    Fetch,
    /// High priority adverts.
    FetchNow,
}

/// Priority function used by `ArtifactClient`.
pub type PriorityFn<Id, Attribute> =
    Box<dyn Fn(&Id, &Attribute) -> Priority + Send + Sync + 'static>;

/// Wraps individual `PriorityFn`s, used by `ArtifactManager`.
pub type ArtifactPriorityFn =
    Box<dyn Fn(&ArtifactId, &ArtifactAttribute) -> Priority + Send + Sync + 'static>;

/// Related artifact sub-types (Message/Id/Attribute/Filter) are
/// parameterized by a type variable, which is of `ArtifactKind` trait.
/// It is mostly a convenience to pass around a collection of types
/// instead of all of them individually.
pub trait ArtifactKind: Sized {
    const TAG: ArtifactTag;
    type Id;
    type Message;
    type Attribute;
    type Filter: Default;

    /// Returns the advert of the given message.
    fn message_to_advert(msg: &<Self as ArtifactKind>::Message) -> Advert<Self>;

    /// Returns the advert send request to be sent to P2P.
    fn message_to_advert_send_request(
        msg: &<Self as ArtifactKind>::Message,
        dest: ArtifactDestination,
    ) -> AdvertSendRequest<Self> {
        AdvertSendRequest {
            advert: Self::message_to_advert(msg),
            dest,
        }
    }

    /// Checks if the given advert matches what is computed from the message.
    /// Returns the advert derived from artifact on mismatch.
    fn check_advert(
        msg: &<Self as ArtifactKind>::Message,
        advert: &Advert<Self>,
    ) -> Result<(), Advert<Self>>
    where
        Advert<Self>: Eq,
    {
        let computed = Self::message_to_advert(msg);
        if advert == &computed {
            Ok(())
        } else {
            Err(computed)
        }
    }
}

/// A helper type that represents a type-indexed Advert.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Advert<Artifact: ArtifactKind> {
    pub id: Artifact::Id,
    pub attribute: Artifact::Attribute,
    pub size: usize,
    // IntegrityHash is just a CryptoHash
    // We don't polimorphise over different Artifacts because it makes no sense,
    // they are never compared, except in one instance where we compare something
    // in GossipAdvert and Advert<T>, so we can't make a mistake.
    pub integrity_hash: CryptoHash,
}

impl<Artifact: ArtifactKind> From<Advert<Artifact>> for GossipAdvert
where
    Artifact::Id: Into<ArtifactId>,
    Artifact::Attribute: Into<ArtifactAttribute>,
{
    fn from(advert: Advert<Artifact>) -> GossipAdvert {
        GossipAdvert {
            artifact_id: advert.id.into(),
            attribute: advert.attribute.into(),
            size: advert.size,
            integrity_hash: advert.integrity_hash,
        }
    }
}

// This instance is currently not used, but may become handy.
impl<Artifact: ArtifactKind> TryFrom<GossipAdvert> for Advert<Artifact>
where
    ArtifactId: TryInto<Artifact::Id, Error = ArtifactId> + From<Artifact::Id>,
    ArtifactAttribute:
        TryInto<Artifact::Attribute, Error = ArtifactAttribute> + From<Artifact::Attribute>,
{
    type Error = GossipAdvert;
    fn try_from(advert: GossipAdvert) -> Result<Advert<Artifact>, Self::Error> {
        let artifact_id = advert.artifact_id;
        let artifact_attribute = advert.attribute;
        let size = advert.size;
        match (artifact_id.try_into(), artifact_attribute.try_into()) {
            (Ok(id), Ok(attribute)) => Ok(Advert {
                id,
                attribute,
                size,
                integrity_hash: advert.integrity_hash,
            }),
            (Err(artifact_id), Ok(attribute)) => Err(GossipAdvert {
                artifact_id,
                attribute: attribute.into(),
                size,
                integrity_hash: advert.integrity_hash,
            }),
            (Ok(artifact_id), Err(attribute)) => Err(GossipAdvert {
                artifact_id: artifact_id.into(),
                attribute,
                size,
                integrity_hash: advert.integrity_hash,
            }),
            (Err(artifact_id), Err(attribute)) => Err(GossipAdvert {
                artifact_id,
                attribute,
                size,
                integrity_hash: advert.integrity_hash,
            }),
        }
    }
}

/// The type of advert gossip for a particular artifact,
/// as determined by the client
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactDestination {
    /// The client considers the artifact to be critical and
    /// requests all peers be notified. This is the default
    /// class of service provided by the networking layer,
    /// if the optimizations are not enabled.
    AllPeersInSubnet,
}

impl ArtifactDestination {
    pub fn as_str(&self) -> &str {
        match self {
            Self::AllPeersInSubnet => "all_peers_in_subnet",
        }
    }
}

/// Wrapper to generate the advert send requests
pub struct AdvertSendRequest<Artifact: ArtifactKind> {
    pub advert: Advert<Artifact>,
    pub dest: ArtifactDestination,
}

// -----------------------------------------------------------------------------
// Consensus artifacts

/// Consensus message identifier carries both a message hash and a height,
/// which is used by the consensus pool to help lookup.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusMessageId {
    pub hash: ConsensusMessageHash,
    pub height: Height,
}

/// Consensus message filter is by height.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusMessageFilter {
    pub height: Height,
}

// -----------------------------------------------------------------------------
// Ingress artifacts

/// [`IngressMessageId`] includes expiry time in addition to [`MessageId`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IngressMessageId {
    expiry: Time,
    pub message_id: MessageId,
}

impl IngressMessageId {
    /// Create a new IngressMessageId
    pub fn new(expiry: Time, message_id: MessageId) -> Self {
        IngressMessageId { expiry, message_id }
    }

    pub fn expiry(&self) -> Time {
        self.expiry
    }
}

impl std::fmt::Display for IngressMessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}@{:?}", self.message_id, self.expiry)
    }
}

impl std::fmt::Debug for IngressMessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}@{:?}", self.message_id, self.expiry)
    }
}

impl From<&SignedIngress> for IngressMessageId {
    fn from(signed_ingress: &SignedIngress) -> Self {
        IngressMessageId::new(signed_ingress.expiry_time(), signed_ingress.id())
    }
}

impl From<&IngressMessageId> for MessageId {
    fn from(id: &IngressMessageId) -> MessageId {
        id.message_id.clone()
    }
}

/// Dummy definition of ingress message attribute for now.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IngressMessageAttribute;

// Placeholder for now.
impl IngressMessageAttribute {
    pub fn new(_message: &SignedIngress) -> Self {
        IngressMessageAttribute
    }
}

// -----------------------------------------------------------------------------
// Certification artifacts

/// Certification message identifier carries both message hash and a height,
/// which is used by the certification pool to help lookup.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificationMessageId {
    pub hash: CertificationMessageHash,
    pub height: Height,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecCertificationMessageId(pub CertificationMessageId);

/// The certification message attribute used by the priority function.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CertificationMessageAttribute {
    Certification(Height),
    CertificationShare(Height),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecCertificationMessageAttribute(pub CertificationMessageAttribute);

/// Certification message filter is by height.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificationMessageFilter {
    pub height: Height,
}

// -----------------------------------------------------------------------------
// DKG artifacts

/// Identifier of a DKG message.
pub type DkgMessageId = CryptoHashOf<DkgMessage>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgMessageAttribute {
    pub interval_start_height: Height,
}

// -----------------------------------------------------------------------------
// ECDSA artifacts

pub type EcdsaMessageId = EcdsaArtifactId;

// -----------------------------------------------------------------------------
// CanisterHttp artifacts

pub type CanisterHttpResponseId = CryptoHashOf<CanisterHttpResponseShare>;

// ------------------------------------------------------------------------------
// StateSync artifacts.

/// Identifier of a state sync artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateSyncArtifactId {
    pub height: Height,
    pub hash: CryptoHashOfState,
}

/// State sync message.
//
// NOTE: StateSyncMessage is never persisted or transferred over the wire
// (despite the Serialize/Deserialize bounds imposed by P2P interfaces), that's
// why it's fine to include an absolute path into it.
//
// P2P will call get_chunk() on it to get a byte array to send to a peer, and
// this byte array will be read from the FS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSyncMessage {
    pub height: Height,
    pub root_hash: CryptoHashOfState,
    /// Absolute path to the checkpoint root directory.
    pub checkpoint_root: std::path::PathBuf,
    /// The manifest containing the summary of the content.
    pub manifest: crate::state_sync::Manifest,
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub state_sync_file_group: Arc<crate::state_sync::FileGroupChunks>,
}

impl ChunkableArtifact for StateSyncMessage {
    fn get_chunk(self: Box<Self>, _chunk_id: ChunkId) -> Option<ArtifactChunk> {
        #[cfg(not(target_family = "unix"))]
        {
            panic!("This method should only be used when the target OS family is unix.");
        }

        #[cfg(target_family = "unix")]
        {
            use crate::chunkable::ArtifactChunkData;
            use std::os::unix::fs::FileExt;

            let get_single_chunk = |chunk_index: usize| -> Option<Vec<u8>> {
                let chunk = self.manifest.chunk_table.get(chunk_index).cloned()?;
                let path = self
                    .checkpoint_root
                    .join(&self.manifest.file_table[chunk.file_index as usize].relative_path);
                let mut buf = vec![0; chunk.size_bytes as usize];
                let f = std::fs::File::open(path).ok()?;
                f.read_exact_at(&mut buf[..], chunk.offset).ok()?;
                Some(buf)
            };

            let mut payload: Vec<u8> = Vec::new();
            if _chunk_id == crate::state_sync::MANIFEST_CHUNK {
                payload = crate::state_sync::encode_manifest(&self.manifest);
            } else if _chunk_id.get() < FILE_GROUP_CHUNK_ID_OFFSET
                || self.state_sync_file_group.get(&_chunk_id.get()).is_none()
            {
                payload = get_single_chunk((_chunk_id.get() - 1) as usize)?;
            } else {
                let chunk_table_indices = self.state_sync_file_group.get(&_chunk_id.get())?;
                for chunk_table_index in chunk_table_indices {
                    payload.extend(get_single_chunk(*chunk_table_index as usize)?);
                }
            }

            Some(ArtifactChunk {
                chunk_id: _chunk_id,
                witness: Vec::new(),
                artifact_chunk_data: ArtifactChunkData::SemiStructuredChunkData(payload),
            })
        }
    }
}

// We need a custom Hash instance to skip checkpoint_root in order
// for integrity_hash to produce the same result on different nodes.
//
// Clippy gives a warning about having a derived PartialEq but a
// hand-rolled Hash instance. In our case this is acceptable because:
//
// 1. We only use use Hash for integrity check.
//
// 2. Even if we use it for other purposes (e.g. in a HashSet), this
//    is still safe because identical (height, root_hash) should
//    lead to identical checkpoint_root.
#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for StateSyncMessage {
    fn hash<Hasher: std::hash::Hasher>(&self, state: &mut Hasher) {
        self.height.hash(state);
        self.root_hash.hash(state);
        self.manifest.hash(state);
    }
}

/// State sync atrribute.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateSyncAttribute {
    pub height: Height,

    // Note: the root hash is also an attribute so that we can access it from
    // the priority function.
    pub root_hash: CryptoHashOfState,
}

/// State sync filter is by height.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateSyncFilter {
    pub height: Height,
}

// ------------------------------------------------------------------------------
// FileTreeSync artifacts

/// File tree sync attribute.
pub type FileTreeSyncAttribute = String;

// ------------------------------------------------------------------------------
// Conversions

impl From<ArtifactFilter> for pb::ArtifactFilter {
    fn from(filter: ArtifactFilter) -> Self {
        Self {
            consensus_filter: Some(filter.consensus_filter.into()),
            certification_message_filter: Some(filter.certification_filter.into()),
            state_sync_filter: Some(filter.state_sync_filter.into()),
        }
    }
}

impl TryFrom<pb::ArtifactFilter> for ArtifactFilter {
    type Error = ProxyDecodeError;
    fn try_from(filter: pb::ArtifactFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            consensus_filter: try_from_option_field(
                filter.consensus_filter,
                "ArtifactFilter.consensus_filter",
            )?,
            certification_filter: try_from_option_field(
                filter.certification_message_filter,
                "ArtifactFilter.certification_message_filter",
            )?,
            state_sync_filter: try_from_option_field(
                filter.state_sync_filter,
                "ArtifactFilter.state_sync_filter",
            )?,
            no_filter: (),
        })
    }
}

impl From<ConsensusMessageFilter> for pb::ConsensusMessageFilter {
    fn from(filter: ConsensusMessageFilter) -> Self {
        Self {
            height: filter.height.get(),
        }
    }
}

impl TryFrom<pb::ConsensusMessageFilter> for ConsensusMessageFilter {
    type Error = ProxyDecodeError;
    fn try_from(filter: pb::ConsensusMessageFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::from(filter.height),
        })
    }
}

impl From<CertificationMessageFilter> for pb::CertificationMessageFilter {
    fn from(filter: CertificationMessageFilter) -> Self {
        Self {
            height: filter.height.get(),
        }
    }
}

impl TryFrom<pb::CertificationMessageFilter> for CertificationMessageFilter {
    type Error = ProxyDecodeError;
    fn try_from(filter: pb::CertificationMessageFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::from(filter.height),
        })
    }
}

impl From<StateSyncFilter> for pb::StateSyncFilter {
    fn from(filter: StateSyncFilter) -> Self {
        Self {
            height: filter.height.get(),
        }
    }
}

impl TryFrom<pb::StateSyncFilter> for StateSyncFilter {
    type Error = ProxyDecodeError;
    fn try_from(filter: pb::StateSyncFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::from(filter.height),
        })
    }
}
