// Copyright(C) Facebook, Inc. and its affiliates.
use crate::{acs_types::FINMVBAView, primary::Round};
use crypto::{CryptoError, Digest, PublicKey};
use store::StoreError;
use thiserror::Error;

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e);
    };
}

#[macro_export(local_inner_macros)]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            bail!($e);
        }
    };
}

pub type DagResult<T> = Result<T, DagError>;

#[derive(Debug, Error)]
pub enum DagError {
    #[error("Invalid signature")]
    InvalidSignature(#[from] CryptoError),

    #[error("Storage failure: {0}")]
    StoreError(#[from] StoreError),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] Box<bincode::ErrorKind>),

    #[error("Invalid header id")]
    InvalidHeaderId,

    #[error("Invalid meta post dg")]
    InvalidMetaPoSTId,

    #[error("Malformed header {0}")]
    MalformedHeader(Digest),

    #[error("Received message from unknown authority {0}")]
    UnknownAuthority(PublicKey),

    #[error("Authority {0} appears in quorum more than once")]
    AuthorityReuse(PublicKey),

    #[error("Received unexpected vote fo header {0}")]
    UnexpectedVote(Digest),

    #[error("Received certificate without a quorum")]
    CertificateRequiresQuorum,

    #[error("Parents of header {0} are not a quorum")]
    HeaderRequiresQuorum(Digest),

    #[error("Message {0} (round {1}) too old")]
    TooOld(Digest, Round),

    #[error("Message {0} (round {1}) too old compared to {2}")]
    PoSTTooOld(Digest, Round, Round),

    #[error("Equivocated PoST")]
    EquivocationPoST,

    #[error("Equivocated MVBA proposal")]
    EquivocationMVBAProposal,

    #[error("Received a PoST containing an old header (round {0}), expected round > {1}")]
    HeaderTooOld(Round, Round),

    #[error("Received a MVBA message containing an old round {0}, expected round > {1}")]
    MVBAMsgTooOld(Round, Round),

    #[error("Received unexpected post vote for post block {0}")]
    UnexpectedPoSTVote(Digest),

    #[error("Received unexpected mvba vote for mvba proposal {0}")]
    UnexpectedMVBAVote(Digest),

    #[error("This is not my mvba proposal")]
    NotMyMVBAProposal,

    #[error("Pisa {0} (view {1}) too old")]
    PisaViewTooOld(Digest, FINMVBAView),

    #[error("Received invalid message for fallback mode")]
    InvalidFallbackMessage,
}
