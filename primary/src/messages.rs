// Copyright(C) Facebook, Inc. and its affiliates.
use crate::acs_types::{FINMVBAView, MetaPoSTBlockData};
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use config::{Committee, WorkerId};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryInto;
use std::{fmt, mem};

pub type BinaryValue = u8; // 0, 1, or 2 (None)

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Header {
    pub author: PublicKey,
    pub round: Round,
    pub payload: BTreeMap<Digest, WorkerId>,
    pub parents: BTreeSet<Digest>,
    pub post_blocks: Vec<MetaPoSTBlockData>, // help nodes to find the post blocks
    pub id: Digest,
    pub signature: Signature,
    pub timeout_cert: TimeoutCert,
    pub no_vote_cert: NoVoteCert,
}

impl Header {
    // Creates a new vertex with a signature.
    pub async fn new(
        author: PublicKey,
        round: Round,
        payload: BTreeMap<Digest, WorkerId>,
        parents: BTreeSet<Digest>,
        timeout_cert: TimeoutCert,
        no_vote_cert: NoVoteCert,
        signature_service: &mut SignatureService,
    ) -> Self {
        let header = Self {
            author,
            round,
            payload,
            parents,
            post_blocks: Vec::new(),
            id: Digest::default(),
            signature: Signature::default(),
            timeout_cert,
            no_vote_cert,
        };
        let id = header.digest();
        let signature = signature_service.request_signature(id.clone()).await;
        Self {
            id,
            signature,
            ..header
        }
    }

    pub async fn new_with_post_blocks(
        author: PublicKey,
        round: Round,
        payload: BTreeMap<Digest, WorkerId>,
        parents: BTreeSet<Digest>,
        post_blocks: Vec<MetaPoSTBlockData>,
        timeout_cert: TimeoutCert,
        no_vote_cert: NoVoteCert,
        signature_service: &mut SignatureService,
    ) -> Self {
        let header = Self {
            author,
            round,
            payload,
            parents,
            post_blocks,
            id: Digest::default(),
            signature: Signature::default(),
            timeout_cert,
            no_vote_cert,
        };
        let id = header.digest();
        let signature = signature_service.request_signature(id.clone()).await;
        Self {
            id,
            signature,
            ..header
        }
    }

    pub fn total_size(&self) -> usize {
        let mut size = mem::size_of_val(self);

        size += self
            .payload
            .iter()
            .map(|(k, v)| mem::size_of_val(k) + mem::size_of_val(v))
            .sum::<usize>();
        size += self
            .parents
            .iter()
            .map(|x| mem::size_of_val(x))
            .sum::<usize>();
        size += self
            .post_blocks
            .iter()
            .map(|x| x.total_size())
            .sum::<usize>();

        size += self.timeout_cert.total_size();
        size += self.no_vote_cert.total_size();

        size
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // todo: complete the verification for post blocks
        if self.post_blocks.len() > 0 {
            return Ok(());
        }

        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));

        // Ensure all worker ids are correct.
        for worker_id in self.payload.values() {
            committee
                .worker(&self.author, worker_id)
                .map_err(|_| DagError::MalformedHeader(self.id.clone()))?;
        }

        // Check the signature.
        self.signature
            .verify(&self.id, &self.author)
            .map_err(DagError::from)

        // Check if pointer to prev leader exists
    }
}

impl Hash for Header {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.author);
        hasher.update(self.round.to_le_bytes());
        for (x, y) in &self.payload {
            hasher.update(x);
            hasher.update(y.to_le_bytes());
        }
        for x in &self.parents {
            hasher.update(x);
        }
        for x in &self.post_blocks {
            hasher.update(&x.digest());
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({}, {})",
            self.id,
            self.round,
            self.author,
            self.payload.keys().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub round: Round,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        round: Round,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let timeout = Self {
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(timeout.digest()).await;
        Self {
            signature,
            ..timeout
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Timeout: R{}({})", self.round, self.author,)
    }
}

impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Round {} Timeout by {}", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NoVoteMsg {
    pub round: Round,
    pub author: PublicKey,
    pub signature: Signature,
}

impl NoVoteMsg {
    pub async fn new(
        round: Round,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let msg = Self {
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(msg.digest()).await;
        Self { signature, ..msg }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for NoVoteMsg {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for NoVoteMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "NoVoteMsg: R{}({})", self.round, self.author,)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        header: &Header,
        author: &PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let vote = Self {
            id: header.id.clone(),
            round: header.round,
            origin: header.author,
            author: *author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.origin);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.digest(),
            self.round,
            self.author,
            self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TimeoutCert {
    pub round: Round,
    // Stores a list of public keys and their corresponding signatures.
    pub timeouts: Vec<(PublicKey, Signature)>,
}

impl TimeoutCert {
    pub fn new(round: Round) -> Self {
        Self {
            round,
            timeouts: Vec::new(),
        }
    }

    pub fn total_size(&self) -> usize {
        let mut size = mem::size_of_val(self);

        size += self
            .timeouts
            .iter()
            .map(|(x, _)| mem::size_of_val(x))
            .sum::<usize>();

        size
    }

    // Adds a timeout to the certificate.
    pub fn add_timeout(&mut self, author: PublicKey, signature: Signature) -> DagResult<()> {
        // Ensure this public key hasn't already submitted a timeout for this round
        if self.timeouts.iter().any(|(pk, _)| *pk == author) {
            return Err(DagError::AuthorityReuse(author));
        }

        // Add the timeout to the list
        self.timeouts.push((author, signature));

        Ok(())
    }

    // Verifies the timeout certificate against the committee.
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        let mut weight = 0;

        let mut used = HashSet::new();
        for (name, _) in self.timeouts.iter() {
            ensure!(!used.contains(name), DagError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }

        // Check if the accumulated weight meets the quorum threshold.
        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct NoVoteCert {
    pub round: Round,
    pub no_votes: Vec<(PublicKey, Signature)>,
}

impl NoVoteCert {
    pub fn new(round: Round) -> Self {
        Self {
            round,
            no_votes: Vec::new(),
        }
    }

    pub fn total_size(&self) -> usize {
        let mut size = mem::size_of_val(self);

        size += self
            .no_votes
            .iter()
            .map(|(k, v)| mem::size_of_val(k) + mem::size_of_val(v))
            .sum::<usize>();

        size
    }

    pub fn add_no_vote(&mut self, author: PublicKey, signature: Signature) -> DagResult<()> {
        if self.no_votes.iter().any(|(pk, _)| *pk == author) {
            return Err(DagError::AuthorityReuse(author));
        }

        self.no_votes.push((author, signature));

        Ok(())
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        let mut weight = 0;
        let mut used = HashSet::new();
        for (author, _) in &self.no_votes {
            ensure!(!used.contains(author), DagError::AuthorityReuse(*author));
            let voting_rights = committee.stake(author);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*author));
            used.insert(*author);
            weight += voting_rights;
        }

        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Certificate {
    pub header: Header,
    pub votes: Vec<(PublicKey, Signature)>,
}

impl Certificate {
    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|name| Self {
                header: Header {
                    author: *name,
                    ..Header::default()
                },
                ..Self::default()
            })
            .collect()
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Genesis certificates are always valid.
        if Self::genesis(committee).contains(self) {
            return Ok(());
        }

        // Check the embedded header.
        self.header.verify(committee)?;

        // Ensure the certificate has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), DagError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(DagError::from)
    }

    pub fn round(&self) -> Round {
        self.header.round
    }

    pub fn origin(&self) -> PublicKey {
        self.header.author
    }
}

impl Hash for Certificate {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.header.id);
        hasher.update(self.round().to_le_bytes());
        hasher.update(&self.origin());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: C{}({}, {})",
            self.digest(),
            self.round(),
            self.origin(),
            self.header.id
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.header.id == other.header.id;
        ret &= self.round() == other.round();
        ret &= self.origin() == other.origin();
        ret
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PisaBval {
    pub acs_round: Round,
    pub view: FINMVBAView,
    pub est: BinaryValue,
    pub maj: BinaryValue,
    pub author: PublicKey,
    pub signature: Signature,
}

impl PisaBval {
    pub async fn new(
        acs_round: Round,
        view: FINMVBAView,
        est: BinaryValue,
        maj: BinaryValue,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let bval = Self {
            acs_round,
            view,
            est,
            maj,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(bval.digest()).await;
        Self { signature, ..bval }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for PisaBval {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.acs_round.to_le_bytes());
        hasher.update(&self.view.digest());
        hasher.update(&self.est.to_le_bytes());
        hasher.update(&self.maj.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for PisaBval {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "PisaBval: PB({}, acs_round {}, view: {:?})({}, {})",
            self.author, self.acs_round, self.view, self.est, self.maj
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PisaAux {
    pub acs_round: Round,
    pub view: FINMVBAView,
    pub val1: BinaryValue,
    pub val2: BinaryValue,
    pub author: PublicKey,
    pub signature: Signature,
}

impl PisaAux {
    pub async fn new(
        acs_round: Round,
        view: FINMVBAView,
        val1: BinaryValue,
        val2: BinaryValue,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let aux = Self {
            acs_round,
            view,
            val1,
            val2,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(aux.digest()).await;
        Self { signature, ..aux }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for PisaAux {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.acs_round.to_le_bytes());
        hasher.update(&self.view.digest());
        hasher.update(&self.val1.to_le_bytes());
        hasher.update(&self.val2.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for PisaAux {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "PisaAux: PA({}, acs_round {}, view {:?})({}, {})",
            self.author, self.acs_round, self.view, self.val1, self.val2
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PisaDecision {
    pub acs_round: Round,
    pub view: FINMVBAView,
    pub val: BinaryValue,
    pub author: PublicKey,
    pub signature: Signature,
}

impl PisaDecision {
    pub async fn new(
        acs_round: Round,
        view: FINMVBAView,
        val: BinaryValue,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let decision = Self {
            acs_round,
            view,
            val,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(decision.digest()).await;
        Self {
            signature,
            ..decision
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for PisaDecision {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.acs_round.to_le_bytes());
        hasher.update(&self.view.digest());
        hasher.update(&self.val.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for PisaDecision {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "DecideMessage: PD({}, acs_round {}, view {})({})",
            self.author, self.acs_round, self.view, self.val
        )
    }
}
