// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

use digest::Digest;
// #[cfg(not(test))]
use ed25519_consensus::Signature;
use rand::{rngs::StdRng, SeedableRng};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

#[cfg(not(test))]
use crate::types::Vote;
use crate::{
    acs_types::{
        BinaryValue, CertifiedMVBA, FINMVBAView, MVBAProposal, MVBAVote, MetaPoSTBlockData,
        PisaABAAux, PisaABABval, PoSTBlockVote, MVBA,
    },
    data::Data,
    serde::{ByteRepr, BytesVisitor},
    types::{
        AuthorityIndex, BaseStatement, BlockReference, EpochStatus, RoundNumber, StatementBlock,
        TimestampNs,
    },
};

pub const SIGNATURE_SIZE: usize = 64;
pub const BLOCK_DIGEST_SIZE: usize = 32;
pub const POST_BLOCK_DIGEST_SIZE: usize = 32;
pub const META_POST_BLOCK_DIGEST_SIZE: usize = 32;
pub const RELIABLE_MVBA_DIGEST_SIZE: usize = 32;
pub const PISA_ABA_DIGEST_SIZE: usize = 32;

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Default, Hash)]
pub struct BlockDigest([u8; BLOCK_DIGEST_SIZE]);

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Default, Hash)]
pub struct PoSTBlockDigest([u8; POST_BLOCK_DIGEST_SIZE]);

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Default, Hash)]
pub struct MetaPoSTBlockDigest([u8; META_POST_BLOCK_DIGEST_SIZE]);

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Default, Hash)]
pub struct MVBADigest([u8; RELIABLE_MVBA_DIGEST_SIZE]);

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Default, Hash)]
pub struct PisaABADigest([u8; PISA_ABA_DIGEST_SIZE]);

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct PublicKey(ed25519_consensus::VerificationKey);

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Hash, Debug)]
pub struct SignatureBytes([u8; SIGNATURE_SIZE]);

// Box ensures value is not copied in memory when Signer itself is moved around for better security
#[derive(Serialize, Deserialize, Clone)]
pub struct Signer(Box<ed25519_consensus::SigningKey>);

#[cfg(not(test))]
type BlockHasher = blake2::Blake2b<digest::consts::U32>;

impl BlockDigest {
    #[cfg(not(test))]
    pub fn new(
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: &[BlockReference],
        statements: &[BaseStatement],
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        signature: &SignatureBytes,
    ) -> Self {
        let mut hasher = BlockHasher::default();
        Self::digest_without_signature(
            &mut hasher,
            authority,
            round,
            includes,
            statements,
            meta_creation_time_ns,
            epoch_marker,
        );
        hasher.update(signature);
        Self(hasher.finalize().into())
    }

    #[cfg(test)]
    pub fn new(
        _authority: AuthorityIndex,
        _round: RoundNumber,
        _includes: &[BlockReference],
        _statements: &[BaseStatement],
        _meta_creation_time_ns: TimestampNs,
        _epoch_marker: EpochStatus,
        _signature: &SignatureBytes,
    ) -> Self {
        Default::default()
    }

    /// There is a bit of a complexity around what is considered block digest and what is being signed
    ///
    /// * Block signature covers all the fields in the block, except for signature and reference.digest
    /// * Block digest(e.g. block.reference.digest) covers all the above **and** block signature
    ///
    /// This is not very beautiful, but it allows to optimize block synchronization,
    /// by skipping signature verification for all the descendants of the certified block.
    #[cfg(not(test))]
    fn digest_without_signature(
        hasher: &mut BlockHasher,
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: &[BlockReference],
        statements: &[BaseStatement],
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
    ) {
        authority.crypto_hash(hasher);
        round.crypto_hash(hasher);
        for include in includes {
            include.crypto_hash(hasher);
        }
        for statement in statements {
            match statement {
                BaseStatement::Share(tx) => {
                    [0].crypto_hash(hasher);
                    tx.crypto_hash(hasher);
                }
                BaseStatement::Vote(id, Vote::Accept) => {
                    [1].crypto_hash(hasher);
                    id.crypto_hash(hasher);
                }
                BaseStatement::Vote(id, Vote::Reject(None)) => {
                    [2].crypto_hash(hasher);
                    id.crypto_hash(hasher);
                }
                BaseStatement::Vote(id, Vote::Reject(Some(other))) => {
                    [3].crypto_hash(hasher);
                    id.crypto_hash(hasher);
                    other.crypto_hash(hasher);
                }
                BaseStatement::VoteRange(range) => {
                    [4].crypto_hash(hasher);
                    range.crypto_hash(hasher);
                }
            }
        }
        meta_creation_time_ns.crypto_hash(hasher);
        epoch_marker.crypto_hash(hasher);
    }
}

pub type PoSTBlockHasher = blake2::Blake2b<digest::consts::U32>;
impl PoSTBlockDigest {
    // pub fn new(
    //     stuck_round: RoundNumber,
    //     stuck_block: &Data<StatementBlock>,
    //     seen_blocks: &BTreeMap<AuthorityIndex, BlockReference>,
    //     signature: &SignatureBytes,
    // ) -> Self {
    //     let mut hasher = PoSTBlockHasher::default();
    //     Self::digest_without_signature(&mut hasher, stuck_round, stuck_block, seen_blocks);
    //     hasher.update(signature);
    //     Self(hasher.finalize().into())
    // }

    fn digest_without_signature(
        hasher: &mut PoSTBlockHasher,
        stuck_round: RoundNumber,
        stuck_block: &Data<StatementBlock>,
        seen_blocks: &BTreeMap<AuthorityIndex, BlockReference>,
    ) {
        stuck_round.crypto_hash(hasher);
        stuck_block.reference().digest.crypto_hash(hasher);
        for (authority, block_reference) in seen_blocks {
            authority.crypto_hash(hasher);
            block_reference.crypto_hash(hasher);
        }
    }
}

pub type MetaPoSTBlockHasher = blake2::Blake2b<digest::consts::U32>;
impl MetaPoSTBlockDigest {
    pub fn new(
        stuck_round: RoundNumber,
        stuck_block: &Data<StatementBlock>,
        seen_blocks: &BTreeMap<AuthorityIndex, BlockReference>,
    ) -> Self {
        let mut hasher = MetaPoSTBlockHasher::default();
        Self::digest_without_signature(&mut hasher, stuck_round, stuck_block, seen_blocks);
        Self(hasher.finalize().into())
    }

    fn digest_without_signature(
        hasher: &mut MetaPoSTBlockHasher,
        stuck_round: RoundNumber,
        stuck_block: &Data<StatementBlock>,
        seen_blocks: &BTreeMap<AuthorityIndex, BlockReference>,
    ) {
        stuck_round.crypto_hash(hasher);
        stuck_block.reference().digest.crypto_hash(hasher);
        for (authority, block_reference) in seen_blocks {
            authority.crypto_hash(hasher);
            block_reference.crypto_hash(hasher);
        }
    }
}

pub type MVBAHasher = blake2::Blake2b<digest::consts::U32>;
impl MVBADigest {
    pub fn new(
        authority: AuthorityIndex,
        round: RoundNumber, // the last round agreed by the ACS mode
        mvba: MVBA,
    ) -> Self {
        let mut hasher = MVBAHasher::default();
        Self::digest_without_signature(&mut hasher, authority, round, mvba);
        Self(hasher.finalize().into())
    }

    fn digest_without_signature(
        hasher: &mut MVBAHasher,
        authority: AuthorityIndex,
        round: RoundNumber, // the last round agreed by the ACS mode
        mvba: MVBA,
    ) {
        authority.crypto_hash(hasher);
        round.crypto_hash(hasher);
        mvba.crypto_hash(hasher);
    }
}

pub type PisaABAHasher = blake2::Blake2b<digest::consts::U32>;
impl PisaABADigest {
    pub fn new(
        view: FINMVBAView,
        p1: BinaryValue,
        p2: BinaryValue,
        authority: AuthorityIndex,
    ) -> Self {
        let mut hasher = PisaABAHasher::default();
        Self::digest_without_signature(&mut hasher, view, p1, p2, authority);
        Self(hasher.finalize().into())
    }

    fn digest_without_signature(
        hasher: &mut PisaABAHasher,
        view: FINMVBAView,
        p1: BinaryValue,
        p2: BinaryValue,
        authority: AuthorityIndex,
    ) {
        view.mvba_round.crypto_hash(hasher);
        view.aba_round.crypto_hash(hasher);
        p1.crypto_hash(hasher);
        p2.crypto_hash(hasher);
        authority.crypto_hash(hasher);
    }
}
pub trait AsBytes {
    // This is pretty much same as AsRef<[u8]>
    //
    // We need this separate trait because we want to impl CryptoHash
    // for primitive types(u64, etc) and types like XxxDigest that implement AsRef<[u8]>.
    //
    // Rust unfortunately does not allow to impl trait for AsRef<[u8]> and primitive types like u64.
    //
    // While AsRef<[u8]> is not implemented for u64, it seem to be reserved in compiler,
    // so `impl CryptoHash for u64` and `impl<T: AsRef<[u8]>> CryptoHash for T` collide.
    fn as_bytes(&self) -> &[u8];
}

impl<const N: usize> AsBytes for [u8; N] {
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

pub trait CryptoHash {
    fn crypto_hash(&self, state: &mut impl Digest);
}

impl CryptoHash for u64 {
    fn crypto_hash(&self, state: &mut impl Digest) {
        state.update(self.to_be_bytes());
    }
}

impl CryptoHash for u128 {
    fn crypto_hash(&self, state: &mut impl Digest) {
        state.update(self.to_be_bytes());
    }
}

impl<T: AsBytes> CryptoHash for T {
    fn crypto_hash(&self, state: &mut impl Digest) {
        state.update(self.as_bytes());
    }
}

impl PublicKey {
    pub fn verify_meta_post_block_with_signature(
        &self,
        meta_post_block: &MetaPoSTBlockData,
        signature: &SignatureBytes,
    ) -> Result<(), ed25519_consensus::Error> {
        let mut hasher = MetaPoSTBlockHasher::default();
        MetaPoSTBlockDigest::digest_without_signature(
            &mut hasher,
            meta_post_block.stuck_round(),
            meta_post_block.stuck_block(),
            meta_post_block.seen_blocks(),
        );
        let digest: [u8; META_POST_BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        self.0
            .verify(&Signature::from(signature.0), digest.as_ref())
    }

    pub fn verify_post_block_vote(
        &self,
        post_block_vote: &PoSTBlockVote,
    ) -> Result<(), ed25519_consensus::Error> {
        let signature = Signature::from(post_block_vote.signature().0);
        let mut hasher = PoSTBlockHasher::default();
        PoSTBlockDigest::digest_without_signature(
            &mut hasher,
            post_block_vote.meta_post_block.stuck_round(),
            post_block_vote.meta_post_block.stuck_block(),
            post_block_vote.meta_post_block.seen_blocks(),
        );
        let digest: [u8; POST_BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        self.0.verify(&signature, digest.as_ref())
    }

    pub fn verify_mvba_proposal(
        &self,
        mvba_proposal: &MVBAProposal,
    ) -> Result<(), ed25519_consensus::Error> {
        let signature = Signature::from(mvba_proposal.signature.0);
        let mut hasher = MVBAHasher::default();
        MVBADigest::digest_without_signature(
            &mut hasher,
            mvba_proposal.authority,
            mvba_proposal.round,
            mvba_proposal.proposal.clone(),
        );
        let digest: [u8; RELIABLE_MVBA_DIGEST_SIZE] = hasher.finalize().into();
        self.0.verify(&signature, digest.as_ref())
    }

    pub fn verify_mvba_vote(&self, mvba_vote: &MVBAVote) -> Result<(), ed25519_consensus::Error> {
        let signature = Signature::from(mvba_vote.signature.0);
        let mut hasher = MVBAHasher::default();
        MVBADigest::digest_without_signature(
            &mut hasher,
            mvba_vote.mvba_proposal.authority,
            mvba_vote.mvba_proposal.round,
            mvba_vote.mvba_proposal.proposal.clone(),
        );
        let digest: [u8; RELIABLE_MVBA_DIGEST_SIZE] = hasher.finalize().into();
        self.0.verify(&signature, digest.as_ref())
    }

    pub fn verify_certified_mvba_with_signature(
        &self,
        certified_mvba: &CertifiedMVBA,
        signature: &SignatureBytes,
    ) -> Result<(), ed25519_consensus::Error> {
        let mut hasher = MVBAHasher::default();
        MVBADigest::digest_without_signature(
            &mut hasher,
            certified_mvba.authority,
            certified_mvba.round,
            certified_mvba.proposal.clone(),
        );
        let digest: [u8; BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        self.0
            .verify(&Signature::from(signature.0), digest.as_ref())
    }

    pub fn verify_pisa_aba_bval(
        &self,
        pisa_aba_val: &PisaABABval,
    ) -> Result<(), ed25519_consensus::Error> {
        let signature = Signature::from(pisa_aba_val.signature.0);
        let mut hasher = PisaABAHasher::default();
        PisaABADigest::digest_without_signature(
            &mut hasher,
            pisa_aba_val.view.clone(),
            pisa_aba_val.est,
            pisa_aba_val.maj,
            pisa_aba_val.authority,
        );
        let digest: [u8; PISA_ABA_DIGEST_SIZE] = hasher.finalize().into();
        self.0.verify(&signature, digest.as_ref())
    }

    pub fn verify_pisa_aba_aux(
        &self,
        pisa_aba_aux: &PisaABAAux,
    ) -> Result<(), ed25519_consensus::Error> {
        let signature = Signature::from(pisa_aba_aux.signature.0);
        let mut hasher = PisaABAHasher::default();
        PisaABADigest::digest_without_signature(
            &mut hasher,
            pisa_aba_aux.view.clone(),
            pisa_aba_aux.aux1,
            pisa_aba_aux.aux2,
            pisa_aba_aux.authority,
        );
        let digest: [u8; PISA_ABA_DIGEST_SIZE] = hasher.finalize().into();
        self.0.verify(&signature, digest.as_ref())
    }

    #[cfg(not(test))]
    pub fn verify_block(&self, block: &StatementBlock) -> Result<(), ed25519_consensus::Error> {
        let signature = Signature::from(block.signature().0);
        let mut hasher = BlockHasher::default();
        BlockDigest::digest_without_signature(
            &mut hasher,
            block.author(),
            block.round(),
            block.includes(),
            block.statements(),
            block.meta_creation_time_ns(),
            block.epoch_changed(),
        );
        let digest: [u8; BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        self.0.verify(&signature, digest.as_ref())
    }

    #[cfg(test)]
    pub fn verify_block(&self, _block: &StatementBlock) -> Result<(), ed25519_consensus::Error> {
        Ok(())
    }
}

impl Signer {
    pub fn new_for_test(n: usize) -> Vec<Self> {
        let mut rng = StdRng::seed_from_u64(0);
        (0..n)
            .map(|_| Self(Box::new(ed25519_consensus::SigningKey::new(&mut rng))))
            .collect()
    }

    pub fn sign_post_block(
        &self,
        stuck_round: RoundNumber,
        stuck_block: &Data<StatementBlock>,
        seen_blocks: &BTreeMap<AuthorityIndex, BlockReference>,
    ) -> SignatureBytes {
        let mut hasher = PoSTBlockHasher::default();
        PoSTBlockDigest::digest_without_signature(
            &mut hasher,
            stuck_round,
            stuck_block,
            seen_blocks,
        );
        let digest: [u8; POST_BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        let signature = self.0.sign(digest.as_ref());
        SignatureBytes(signature.to_bytes())
    }

    pub fn sign_mvba_proposal(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
        mvba: MVBA,
    ) -> SignatureBytes {
        let mut hasher = MVBAHasher::default();
        MVBADigest::digest_without_signature(&mut hasher, authority, round, mvba);
        let digest: [u8; RELIABLE_MVBA_DIGEST_SIZE] = hasher.finalize().into();
        let signature = self.0.sign(digest.as_ref());
        SignatureBytes(signature.to_bytes())
    }

    pub fn sign_pisa_aba_bval(
        &self,
        view: FINMVBAView,
        est: BinaryValue,
        maj: BinaryValue,
        authority: AuthorityIndex,
    ) -> SignatureBytes {
        let mut hasher = PisaABAHasher::default();
        PisaABADigest::digest_without_signature(&mut hasher, view, est, maj, authority);
        let digest: [u8; POST_BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        let signature = self.0.sign(digest.as_ref());
        SignatureBytes(signature.to_bytes())
    }

    pub fn sign_pisa_aba_aux(
        &self,
        view: FINMVBAView,
        aux1: BinaryValue,
        aux2: BinaryValue,
        authority: AuthorityIndex,
    ) -> SignatureBytes {
        let mut hasher = PisaABAHasher::default();
        PisaABADigest::digest_without_signature(&mut hasher, view, aux1, aux2, authority);
        let digest: [u8; POST_BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        let signature = self.0.sign(digest.as_ref());
        SignatureBytes(signature.to_bytes())
    }

    #[cfg(not(test))]
    pub fn sign_block(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: &[BlockReference],
        statements: &[BaseStatement],
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
    ) -> SignatureBytes {
        let mut hasher = BlockHasher::default();
        BlockDigest::digest_without_signature(
            &mut hasher,
            authority,
            round,
            includes,
            statements,
            meta_creation_time_ns,
            epoch_marker,
        );
        let digest: [u8; BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        let signature = self.0.sign(digest.as_ref());
        SignatureBytes(signature.to_bytes())
    }

    #[cfg(test)]
    pub fn sign_block(
        &self,
        _authority: AuthorityIndex,
        _round: RoundNumber,
        _includes: &[BlockReference],
        _statements: &[BaseStatement],
        _meta_creation_time_ns: TimestampNs,
        _epoch_marker: EpochStatus,
    ) -> SignatureBytes {
        Default::default()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verification_key())
    }
}

impl AsRef<[u8]> for BlockDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsBytes for BlockDigest {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsBytes for SignatureBytes {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BlockDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", hex::encode(self.0))
    }
}

impl fmt::Display for BlockDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", hex::encode(&self.0[..4]))
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signer(public_key={:?})", self.public_key())
    }
}

impl fmt::Display for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signer(public_key={:?})", self.public_key())
    }
}

impl Default for SignatureBytes {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl ByteRepr for SignatureBytes {
    fn try_copy_from_slice<E: de::Error>(v: &[u8]) -> Result<Self, E> {
        if v.len() != SIGNATURE_SIZE {
            return Err(E::custom(format!("Invalid signature length: {}", v.len())));
        }
        let mut inner = [0u8; SIGNATURE_SIZE];
        inner.copy_from_slice(v);
        Ok(Self(inner))
    }
}

impl Serialize for SignatureBytes {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(BytesVisitor::new())
    }
}

impl ByteRepr for BlockDigest {
    fn try_copy_from_slice<E: de::Error>(v: &[u8]) -> Result<Self, E> {
        if v.len() != BLOCK_DIGEST_SIZE {
            return Err(E::custom(format!(
                "Invalid block digest length: {}",
                v.len()
            )));
        }
        let mut inner = [0u8; BLOCK_DIGEST_SIZE];
        inner.copy_from_slice(v);
        Ok(Self(inner))
    }
}

impl Serialize for BlockDigest {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for BlockDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(BytesVisitor::new())
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

pub fn dummy_signer() -> Signer {
    Signer(Box::new(ed25519_consensus::SigningKey::from([0u8; 32])))
}

pub fn dummy_public_key() -> PublicKey {
    dummy_signer().public_key()
}
