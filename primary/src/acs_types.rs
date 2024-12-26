// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::{BinaryValue, Header, PisaAux, PisaBval, PisaDecision};
use crate::primary::{PrimaryMessage, Round};
use crate::error::{DagError, DagResult};
use bytes::Bytes;
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use config::Committee;
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use log::{debug, info};
use network::{CancelHandler, ReliableSender};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, HashMap};
use std::convert::TryInto;
use std::fmt;

pub type MVBARoundNumber = u64;
pub type ABARoundNumber = u64;
// pub type BinaryValue = u64; // b=0, b=1, b=2 (None)
pub type MVBA = u128;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MetaPoSTBlockData {
    pub acs_round: Round,
    pub stuck_block: Header,
    pub dg: Digest,
    pub signature: Signature,
}

impl MetaPoSTBlockData {
    pub async fn new(
        acs_round: Round,   // the last round agreed by the ACS mode
        stuck_block: Header,
        signature_service: &mut SignatureService,
        // seen_blocks: BTreeMap<AuthorityIndex, BlockReference>,
    ) -> Self {
        let meta_post = Self {
            acs_round,
            stuck_block,
            dg: Digest::default(),
            signature: Signature::default(),
        };
        let dg = meta_post.digest();
        let signature = signature_service.request_signature(dg.clone()).await;
        Self {
            dg,
            signature,
            ..meta_post
        }
    }

    pub fn acs_round(&self) -> Round {
        self.acs_round
    }

    pub fn stuck_block(&self) -> &Header {
        &self.stuck_block
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the wrapped stuck block is valid.
        self.stuck_block.verify(committee)?;

        // Ensure the digest is well formed.
        ensure!(self.digest() == self.dg, DagError::InvalidMetaPoSTId);

        // Ensure the authority has voting rights.
        let voting_rights= committee.stake(&self.stuck_block.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.stuck_block.author));

        // Check the signature.
        self.signature
            .verify(&self.dg, &self.stuck_block.author)
            .map_err(DagError::from)
    }

}

impl Hash for MetaPoSTBlockData {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.acs_round.to_le_bytes());
        hasher.update(&self.stuck_block.id);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoSTBlockVote {
    pub dg: Digest,
    // pub origin: PublicKey,
    pub voter: PublicKey,    // the signer of this vote
    pub signature: Signature,
}

impl PoSTBlockVote {
    pub async fn new(
        meta_post: &MetaPoSTBlockData,
        voter: &PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let post_vote = Self {
            dg: meta_post.dg.clone(),
            // round: header.round,
            // origin: meta_post.author,
            voter: *voter,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(post_vote.digest()).await;
        Self { signature, ..post_vote }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.voter) > 0,
            DagError::UnknownAuthority(self.voter)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.voter)
            .map_err(DagError::from)
    }
}

impl Hash for PoSTBlockVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.dg);
        // hasher.update(self.round.to_le_bytes());
        // hasher.update(&self.origin);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CertifiedPoSTBlockData {
    pub meta_post: MetaPoSTBlockData, // the block I proposed at the stuck round
    pub votes: Vec<(PublicKey, Signature)>, // 2f+1 signatures
}

impl CertifiedPoSTBlockData {
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Check the embedded meta post.
        self.meta_post.verify(committee)?;

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
}

impl Hash for CertifiedPoSTBlockData {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.meta_post.dg);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for CertifiedPoSTBlockData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "round: {}, stuck_block: {:?}, signatures: {} }}",
            self.meta_post.acs_round ,
            self.meta_post.stuck_block,
            self.votes.len()
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct MVBAProposal {
    pub author: PublicKey, // the creator of this proposal
    pub acs_round: Round,        // the last round agreed by the ACS mode
    pub proposal: MVBA,
    pub signature: Signature, // signature of the creator
}

impl MVBAProposal {
    pub async  fn new(
        author: PublicKey,
        acs_round: Round,
        proposal: MVBA,
        signature_service: &mut SignatureService,
    ) -> Self {
        let proposal = Self {
            author,
            acs_round,
            proposal,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(proposal.digest()).await;
        Self { signature, ..proposal }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights= committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for MVBAProposal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.author);
        hasher.update(self.acs_round.to_le_bytes());
        hasher.update(&self.proposal.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for MVBAProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MVBAProposal {{ authority: {}, round: {}, proposal: {} }}",
            self.author, self.acs_round, self.proposal
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct MVBAVote {
    pub mvba_proposal: MVBAProposal,
    pub voter: PublicKey,     // the signer of this MVBAProposal
    pub signature: Signature, // my signature on this mvba proposal
}

impl MVBAVote {
    pub async fn new_with_signer(
        mvba_proposal: MVBAProposal,
        voter: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let vote = Self {
            mvba_proposal,
            voter,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.voter) > 0,
            DagError::UnknownAuthority(self.voter)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.voter)
            .map_err(DagError::from)
    }
}

impl Hash for MVBAVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.mvba_proposal.digest());
        hasher.update(&self.voter);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
    
}

impl fmt::Debug for MVBAVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MVBAVote {{ mvba_proposal: {:?}, voter: {} }}",
            self.mvba_proposal, self.voter,
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CertifiedMVBA {
    pub proposal: MVBAProposal,
    pub votes: Vec<(PublicKey, Signature)>, // 2f+1 signatures
}

impl CertifiedMVBA {
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Check the embedded mvba.
        self.proposal.verify(committee)?;

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
}

impl Hash for CertifiedMVBA {
    fn digest(&self) -> Digest {
        self.proposal.digest()
    }
}

impl fmt::Debug for CertifiedMVBA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CertifiedMVBA {{ proposal: {:?}, signatures: {} }}",
            self.proposal,
            self.votes.len()
        )
    }
}

pub struct ACSFin {
    /// The public key of the primary.
    name: PublicKey,
    /// The round number
    round: Round,
    /// est_r value for round r
    pub est_r: BinaryValue,
    /// maj_r value for round r
    pub maj_r: BinaryValue,
    /// The bin values for each round
    bin_values: HashMap<Round, Vec<BinaryValue>>,
    /// The list of maj's values.
    pub majs: HashMap<Round, Vec<BinaryValue>>,
    /// Whether the ACS_FIN aux() message has been sent
    pub aux_sent: bool,
    /// Whether the ACS_FIN aux(1, *) message has been sent
    pub aux_1_sent: bool,
    /// Whether the ACS_FIN aux(0, *) message has been sent
    pub aux_0_sent: bool,
    /// Whether the ACS_FIN bval(1, maj_r) message has been sent
    pub bval_0_sent: bool,
    /// Whether the ACS_FIN bval(0, maj_r) message has been sent
    pub bval_1_sent: bool,
    /// Wheather the this primary has decided or not
    pub decided: bool,
}

impl ACSFin {
    pub fn spawn(name: PublicKey) -> ACSFin {
        Self {
            name,
            round: 0,
            est_r: 0,
            maj_r: 0,
            bin_values: HashMap::new(),
            majs: HashMap::new(),
            aux_sent: false,
            aux_1_sent: false,
            aux_0_sent: false,
            bval_0_sent: false,
            bval_1_sent: false,
            decided: false,
        }
    }

    pub fn propose(&mut self, vi: BinaryValue) {
        self.est_r = vi;
        self.maj_r = 2;
    }

    pub fn create_bval_message(&self, est: BinaryValue, maj: BinaryValue) -> PisaBval {
        let bval_message = PisaBval::new(self.name, self.round, est, maj);
        debug!("Created BVAL message: {:?}", bval_message);

        bval_message
    }

    pub fn create_aux_message(&self, val1: BinaryValue, val2: BinaryValue) -> PisaAux {
        let aux_message = PisaAux::new(self.name, self.round, val1, val2);
        debug!("Created AUX message: {:?}", aux_message);

        aux_message
    }

    pub fn add_bin_value(&mut self, round: Round, bin_value: BinaryValue) {
        self.bin_values
            .entry(round)
            .or_insert_with(Vec::new)
            .push(bin_value);

        debug!("Added bin value {:?} for round {}", bin_value, round);
    }

    pub fn add_maj_value(&mut self, round: Round, maj_value: BinaryValue) {
        self.majs
            .entry(round)
            .or_insert_with(Vec::new)
            .push(maj_value);

        debug!("Added maj value {:?}", maj_value);
    }

    pub async fn broadcast_bval_message(
        &mut self,
        committee: &Committee,
        bval_message: PisaBval,
        network: &mut ReliableSender,
    ) -> Vec<CancelHandler> {
        let addresses = committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();

        let bytes = bincode::serialize(&PrimaryMessage::PisaBval(bval_message))
            .expect("Failed to serialize PisaBval message");

        network.broadcast(addresses, Bytes::from(bytes)).await
    }

    pub async fn broadcast_aux_message(
        &mut self,
        committee: &Committee,
        aux_message: PisaAux,
        network: &mut ReliableSender,
    ) -> Vec<CancelHandler> {
        let addresses = committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();

        let bytes = bincode::serialize(&PrimaryMessage::PisaAux(aux_message))
            .expect("Failed to serialize PisaAux message");

        network.broadcast(addresses, Bytes::from(bytes)).await
    }

    pub async fn decide(
        &mut self,
        committee: &Committee,
        network: &mut ReliableSender,
        decide_value: BinaryValue,
    ) -> Vec<CancelHandler> {
        self.decided = true;

        let decide_message = PisaDecision::new(self.name, self.round, decide_value);
        debug!("Deciding {:?}", decide_message);

        let addresses = committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();

        let bytes = bincode::serialize(&PrimaryMessage::PisaDecision(decide_message))
            .expect("Failed to serialize PisaDecision message");

        network.broadcast(addresses, Bytes::from(bytes)).await
    }

    fn v2_check(&self, vals_r: Vec<BinaryValue>, b: BinaryValue) -> Option<u32> {
        let mut count = 0;
        let opposite = 1 - b;

        for val in vals_r {
            if val == opposite {
                return None;
            } else if val == b {
                count += 1;
            }
        }

        Some(count)
    }

    pub fn v1_check(&self, vals: Vec<BinaryValue>) -> Option<BinaryValue> {
        let bin = vals.get(0).cloned();
        match bin {
            Some(first) => {
                for val in vals {
                    if val != first {
                        return None;
                    }
                }
                Some(first)
            }
            None => {
                return None;
            }
        }
    }

    fn majority(&self, vals: Vec<BinaryValue>) -> BinaryValue {
        let vals_len = vals.len();
        let threshold = ((vals_len as f64 + 1.0) / 2.0).ceil() as usize;

        let count_0 = vals.iter().filter(|&x| *x == 0).count();
        let count_1 = vals.iter().filter(|&x| *x == 1).count();

        if count_0 >= threshold {
            0
        } else if count_1 >= threshold {
            1
        } else {
            2
        }
    }

    pub fn try_decide_round_0(&mut self, vals_r: Vec<BinaryValue>, committee: &Committee) -> bool {
        info!("Trying to decide round 0");
        // Cases b = 1 or b = 0
        if let Some(count) = self.v2_check(vals_r.clone(), 1) {
            if count >= committee.majority_threshold() {
                self.est_r = 1;
                self.maj_r = 1;
                return true;
            }
        } else if let Some(count) = self.v2_check(vals_r.clone(), 0) {
            if count >= committee.majority_threshold() {
                self.est_r = 0;
                self.maj_r = 0;
                return false;
            }
        }
        self.est_r = 1;
        self.maj_r = 1;
        false
    }

    pub fn try_decide(
        &mut self,
        vals_r: Vec<BinaryValue>,
        avals_r: Vec<BinaryValue>,
        committee: &Committee,
    ) -> (bool, BinaryValue) {
        let actual_coin = self.coin(self.round);
        let last_coin = self.coin(self.round - 1);

        // If V2(vals_r, b) >= majority_threshold for b = 0 or b = 1, it means that a quorum of
        // replicas voted for b.
        for b in [0, 1] {
            if let Some(count) = self.v2_check(vals_r.clone(), b) {
                if count >= committee.majority_threshold() {
                    self.est_r = b;
                    self.maj_r = b;
                    return (b == actual_coin, b);
                }
            }
        }

        let v1_vals = self.v1_check(vals_r.clone());
        let mut b_val = None;
        let pass = if v1_vals.unwrap_or(3) == 2 {
            true
        } else {
            [0, 1].iter().any(|&b| {
                if let Some(count) = self.v2_check(vals_r.clone(), b) {
                    b_val = Some(b);
                    count < committee.majority_threshold()
                } else {
                    false
                }
            })
        };

        if pass {
            let avals_has_0_1 = [0, 1].iter().all(|x| avals_r.contains(x));
            // If last condition was satisfied because of V2(vals_r, b) < majority_threshold
            if let Some(b) = b_val {
                if let Some(count) = self.v2_check(avals_r.clone(), b) {
                    if count >= committee.majority_threshold() {
                        self.est_r = b;
                        self.maj_r = b;
                        return (b == actual_coin && b == last_coin, b);
                    }
                } else if avals_has_0_1 && b == last_coin {
                    self.est_r = b;
                    self.maj_r = b;
                    return (false, 3);
                }
            } else {
                // If the condition was satisfied because V1(vals_r) == 2
                for b in [0, 1] {
                    if let Some(count) = self.v2_check(avals_r.clone(), b) {
                        if count >= committee.majority_threshold() {
                            self.est_r = b;
                            self.maj_r = b;
                            return (b == actual_coin && b == last_coin, b);
                        }
                    }
                }
                if avals_has_0_1 {
                    for b in [0, 1] {
                        if b == last_coin {
                            self.est_r = b;
                            self.maj_r = b;
                            return (false, 3);
                        }
                    }
                }
            }
        }

        // If none of the conditions above has returned a value it means est_r+1 has not been set
        // yet.
        self.est_r = actual_coin;
        self.maj_r = self.majority(vals_r.clone());

        (false, 3)
    }

    pub async fn advance_round(
        &mut self,
        committee: &Committee,
        network: &mut ReliableSender,
    ) -> Vec<CancelHandler> {
        self.round += 1;
        self.bval_0_sent = false;
        self.bval_1_sent = false;
        self.aux_sent = false;
        self.aux_0_sent = false;
        self.aux_1_sent = false;

        debug!("Pisa moving to round {}", self.round);

        let bval_message = self.create_bval_message(self.est_r, self.maj_r);

        self.broadcast_bval_message(committee, bval_message, network)
            .await
    }

    pub fn coin(&self, round: Round) -> BinaryValue {
        round as BinaryValue % 2
    }

    pub fn delta_b(&mut self, b: BinaryValue) -> BinaryValue {
        let mut delta_b = 2;

        let not_b = 1 - b;
        let last_coin = self.coin(self.round - 1);
        let current_majs = self.majs.entry(self.round).or_insert_with(Vec::new).clone();
        let v1_majs_is_b = self.v1_check(current_majs.clone()).unwrap_or(3) == b;
        let majs_has_not_b = !current_majs.contains(&not_b);

        if (b == (1 - last_coin) && v1_majs_is_b) || (b == last_coin && majs_has_not_b) {
            delta_b = 1;
        }
        delta_b
    }
}
