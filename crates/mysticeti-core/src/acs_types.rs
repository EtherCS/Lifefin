// We implement FIN protocol here
// refer to: https://dl.acm.org/doi/pdf/10.1145/3576915.3616633

use crate::{
    committee::Committee,
    consensus::universal_committer::UniversalCommitter,
    crypto::{MVBADigest, MetaPoSTBlockDigest, PisaABADigest, PublicKey, SignatureBytes, Signer},
    data::Data,
    types::{AuthorityIndex, BlockReference, RoundNumber, Stake, StatementBlock},
};
use eyre::{bail, Ok};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
};

pub type MVBARoundNumber = u64;
pub type ABARoundNumber = u64;
pub type BinaryValue = u64; // b=0, b=1, b=2 (None)
pub type MVBA = u128;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PisaABAMessage {
    PisaABABval(PisaABABval),
    PisaABAAux(PisaABAAux),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetaPoSTBlockData {
    pub stuck_round: RoundNumber,
    pub stuck_block: Data<StatementBlock>,
    pub seen_blocks: BTreeMap<AuthorityIndex, BlockReference>, // ordered by nodes' public keys
}

impl MetaPoSTBlockData {
    pub fn new(
        stuck_round: RoundNumber,
        stuck_block: Data<StatementBlock>,
        seen_blocks: BTreeMap<AuthorityIndex, BlockReference>,
    ) -> Self {
        Self {
            stuck_round,
            stuck_block,
            seen_blocks,
        }
    }

    pub fn stuck_round(&self) -> RoundNumber {
        self.stuck_round
    }

    pub fn stuck_block(&self) -> &Data<StatementBlock> {
        &self.stuck_block
    }

    pub fn seen_blocks(&self) -> &BTreeMap<AuthorityIndex, BlockReference> {
        &self.seen_blocks
    }

    pub fn digest(&self) -> MetaPoSTBlockDigest {
        let digest =
            MetaPoSTBlockDigest::new(self.stuck_round, &self.stuck_block, &self.seen_blocks);
        digest
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoSTBlockVote {
    pub meta_post_block: MetaPoSTBlockData,
    pub authority: AuthorityIndex,
    pub signature: SignatureBytes,
}

impl PoSTBlockVote {
    pub fn new(
        meta_post_block: MetaPoSTBlockData,
        authority: AuthorityIndex,
        signer: Signer,
    ) -> Self {
        let signature = signer.sign_post_block(
            meta_post_block.stuck_round,
            meta_post_block.stuck_block(),
            meta_post_block.seen_blocks(),
        );
        Self {
            meta_post_block,
            authority,
            signature,
        }
    }

    pub fn meta_post_block(&self) -> &MetaPoSTBlockData {
        &self.meta_post_block
    }

    pub fn signature(&self) -> &SignatureBytes {
        &self.signature
    }

    pub fn author(&self) -> AuthorityIndex {
        self.authority
    }

    pub fn vote_creator(&self) -> AuthorityIndex {
        self.meta_post_block.stuck_block().reference().authority
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let pub_key = committee.get_public_key(self.author());
        let Some(pub_key) = pub_key else {
            bail!("Unknown vote author {}", self.author())
        };
        if let Err(e) = pub_key.verify_post_block_vote(self) {
            bail!("Post block vote signature verification has failed: {:?}", e);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertifiedPoSTBlockData {
    pub stuck_round: RoundNumber,          // the round I am stuck at
    pub stuck_block: Data<StatementBlock>, // the block I proposed at the stuck round
    pub seen_blocks: BTreeMap<AuthorityIndex, BlockReference>, // ordered by nodes' public keys
    pub signatures: Vec<(PublicKey, SignatureBytes)>, // 2f+1 signatures
}

impl CertifiedPoSTBlockData {
    pub fn default(authority: AuthorityIndex) -> Self {
        Self {
            stuck_round: 0,
            stuck_block: StatementBlock::new_genesis(authority),
            seen_blocks: BTreeMap::new(),
            signatures: Vec::new(),
        }
    }

    pub fn new(
        stuck_round: RoundNumber,
        stuck_block: Data<StatementBlock>,
        seen_blocks: BTreeMap<AuthorityIndex, BlockReference>,
        signatures: Vec<(PublicKey, SignatureBytes)>,
    ) -> Self {
        Self {
            stuck_round,
            stuck_block,
            seen_blocks,
            signatures,
        }
    }

    pub fn new_with_my_signagure(
        stuck_round: RoundNumber,
        stuck_block: Data<StatementBlock>,
        seen_blocks: BTreeMap<AuthorityIndex, BlockReference>,
        signer: Signer,
    ) -> Self {
        let mut signatures = Vec::new();
        let signature = signer.sign_post_block(stuck_round, &stuck_block, &seen_blocks);
        signatures.push((signer.public_key(), signature));
        Self {
            stuck_round,
            stuck_block,
            seen_blocks,
            signatures,
        }
    }

    pub fn update_signature(&mut self, author: PublicKey, signature: SignatureBytes) {
        if !self.signatures.iter().any(|(a, _)| a == &author) {
            self.signatures.push((author, signature));
        }
    }

    pub fn get_meta_post_block(&self) -> MetaPoSTBlockData {
        MetaPoSTBlockData::new(
            self.stuck_round,
            self.stuck_block.clone(),
            self.seen_blocks.clone(),
        )
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let meta_post_block = self.get_meta_post_block();
        if self.signatures.len() < committee.quorum_threshold() as usize {
            eyre::bail!(
                "Not enough signatures, only {} but quorum is {}",
                self.signatures.len(),
                committee.quorum_threshold()
            );
        }
        for (author, signature) in &self.signatures {
            if !committee.known_authority_key(author) {
                eyre::bail!("Unknown authority");
            }
            if author
                .verify_meta_post_block_with_signature(&meta_post_block, signature)
                .is_err()
            {
                eyre::bail!("Invalid signature");
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MVBAProposal {
    pub authority: AuthorityIndex, // the creator of this proposal
    pub round: RoundNumber,        // the last round agreed by the ACS mode
    pub proposal: MVBA,
}

impl MVBAProposal {
    pub fn new(authority: AuthorityIndex, round: RoundNumber, proposal: MVBA) -> Self {
        Self {
            authority,
            round,
            proposal,
        }
    }

    pub fn digest(&self) -> MVBADigest {
        MVBADigest::new(self.authority, self.round, self.proposal)
    }

    pub fn author(&self) -> AuthorityIndex {
        self.authority
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MVBAVote {
    pub mvba_proposal: MVBAProposal,
    pub voter: AuthorityIndex,     // the signer of this MVBAProposal
    pub signature: SignatureBytes, // my signature on this mvba proposal
}

impl MVBAVote {
    pub fn new_with_signer(
        mvba_proposal: MVBAProposal,
        voter: AuthorityIndex,
        signer: Signer,
    ) -> Self {
        let signature = signer.sign_mvba_proposal(
            mvba_proposal.authority,
            mvba_proposal.round,
            mvba_proposal.proposal,
        );
        Self {
            mvba_proposal,
            voter,
            signature,
        }
    }

    pub fn mvba_creator(&self) -> AuthorityIndex {
        self.mvba_proposal.authority
    }

    pub fn mvba_voter(&self) -> AuthorityIndex {
        self.voter
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let pub_key = committee.get_public_key(self.mvba_voter());
        let Some(pub_key) = pub_key else {
            bail!("Unknown pisa aba bval author {}", self.mvba_voter())
        };
        if let Err(e) = pub_key.verify_mvba_vote(self) {
            bail!("pisa aba bval signature verification has failed: {:?}", e);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertifiedMVBA {
    pub authority: AuthorityIndex,
    pub round: RoundNumber, // the last round agreed by the ACS mode
    pub proposal: MVBA,     // the proposal value
    pub signatures: Vec<(PublicKey, SignatureBytes)>, // 2f+1 signatures
}

impl CertifiedMVBA {
    pub fn new(authority: AuthorityIndex, round: RoundNumber, proposal: MVBA) -> Self {
        Self {
            authority,
            round,
            proposal,
            signatures: Vec::new(),
        }
    }

    pub fn update_signature(&mut self, author: PublicKey, signature: SignatureBytes) {
        if !self.signatures.iter().any(|(a, _)| a == &author) {
            self.signatures.push((author, signature));
        }
    }

    pub fn is_certified(&self, acs_quorum: Stake) -> bool {
        self.signatures.len() >= acs_quorum as usize
    }

    pub fn get_mvba_proposal(&self) -> MVBAProposal {
        MVBAProposal::new(self.authority, self.round, self.proposal)
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        if self.signatures.len() < committee.quorum_threshold() as usize {
            eyre::bail!("Not enough signatures");
        }
        for (author, signature) in &self.signatures {
            if !committee.known_authority_key(author) {
                eyre::bail!("Unknown authority");
            }
            if author
                .verify_certified_mvba_with_signature(self, signature)
                .is_err()
            {
                eyre::bail!("Invalid signature");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ACSOutput {
    pub round: RoundNumber, // the highest round agreed by the ACS mode
    pub blocks: Vec<Data<StatementBlock>>,
}

impl ACSOutput {
    pub fn new(round: RoundNumber, blocks: Vec<Data<StatementBlock>>) -> Self {
        Self { round, blocks }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn new_leader(&self, committer: UniversalCommitter) -> Data<StatementBlock> {
        // collect the blocks with the highest round
        let highest_blocks: Vec<&Data<StatementBlock>> = self
            .blocks
            .iter()
            .filter(|&b| b.round() == self.round)
            .collect();
        if highest_blocks.len() == 0 {
            tracing::warn!("No blocks with the highest round {}", self.round);
        }
        let mut leader_block = highest_blocks[0].clone();
        let pre_defined_leaders = committer.get_leaders(self.round);
        for block in highest_blocks {
            // if there is a pre-defined leader block, then return it
            if pre_defined_leaders.contains(&block.reference().authority) {
                // we only consider the first pre-defined leader block
                leader_block = block.clone();
                break;
            }
        }
        leader_block
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FINMVBAView {
    pub mvba_round: MVBARoundNumber, // the (FIN) mvba round number
    pub aba_round: ABARoundNumber,   // the (Pisa) aba round number
}

impl FINMVBAView {
    pub fn new() -> Self {
        Self {
            mvba_round: 0,
            aba_round: 0,
        }
    }

    pub fn new_with_rounds(mvba_round: MVBARoundNumber, aba_round: ABARoundNumber) -> Self {
        Self {
            mvba_round,
            aba_round,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PisaABABval {
    pub view: FINMVBAView, // the aba round number
    pub est: BinaryValue,
    pub maj: BinaryValue,
    pub authority: AuthorityIndex,
    pub signature: SignatureBytes,
}

impl PisaABABval {
    pub fn new(
        view: FINMVBAView,
        est: BinaryValue,
        maj: BinaryValue,
        authority: AuthorityIndex,
        signer: &Signer,
    ) -> Self {
        let signature = signer.sign_pisa_aba_bval(view.clone(), est, maj, authority);
        Self {
            view,
            est,
            maj,
            authority,
            signature,
        }
    }

    pub fn author(&self) -> AuthorityIndex {
        self.authority
    }

    pub fn digest(&self) -> PisaABADigest {
        PisaABADigest::new(self.view.clone(), self.est, self.maj, self.authority)
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let pub_key = committee.get_public_key(self.author());
        let Some(pub_key) = pub_key else {
            bail!("Unknown pisa aba bval author {}", self.author())
        };
        if let Err(e) = pub_key.verify_pisa_aba_bval(self) {
            bail!("pisa aba bval signature verification has failed: {:?}", e);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PisaABAAux {
    pub view: FINMVBAView, // the aba round number
    pub aux1: BinaryValue,
    pub aux2: BinaryValue,
    pub authority: AuthorityIndex,
    pub signature: SignatureBytes,
}

impl PisaABAAux {
    pub fn new(
        view: FINMVBAView,
        aux1: BinaryValue,
        aux2: BinaryValue,
        authority: AuthorityIndex,
        signer: &Signer,
    ) -> Self {
        let signature = signer.sign_pisa_aba_aux(view.clone(), aux1, aux2, authority);
        Self {
            view,
            aux1,
            aux2,
            authority,
            signature,
        }
    }

    pub fn author(&self) -> AuthorityIndex {
        self.authority
    }

    pub fn digest(&self) -> PisaABADigest {
        PisaABADigest::new(self.view.clone(), self.aux1, self.aux2, self.authority)
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let pub_key = committee.get_public_key(self.author());
        let Some(pub_key) = pub_key else {
            bail!("Unknown pisa aba aux author {}", self.author())
        };
        if let Err(e) = pub_key.verify_pisa_aba_aux(self) {
            bail!("pisa aba aux signature verification has failed: {:?}", e);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ACSFin {
    pub authority: AuthorityIndex,
    pub committee: Committee,
    pub last_acs_round: RoundNumber, // the last round agreed by the ACS mode
    pub mvbas: BTreeMap<AuthorityIndex, CertifiedMVBA>, // MVBA proposals received from all nodes
    /* the following data is for MVBA */
    pub mvba_view: FINMVBAView, // the current MVBA view
    pub current_bval: BinaryValue,
    pub current_maj: BinaryValue,
    pub raba_bvals: BTreeMap<FINMVBAView, Vec<PisaABABval>>, // record the binary value proposed by each node in each MVBA round/ABA round
    pub raba_aux: BTreeMap<FINMVBAView, Vec<PisaABAAux>>, // record the auxiliary information proposed by each node in each MVBA round/ABA round
}

impl ACSFin {
    pub fn new(
        authority: AuthorityIndex,
        committee: Committee,
        last_acs_round: RoundNumber,
    ) -> Self {
        let mut mvbas = BTreeMap::new();
        let my_reliable_mvba = CertifiedMVBA::new(authority, last_acs_round, 0);
        mvbas.insert(authority, my_reliable_mvba);
        Self {
            authority,
            committee,
            last_acs_round,
            mvbas,
            current_bval: 0,
            current_maj: 2,
            mvba_view: FINMVBAView::new(),
            raba_bvals: BTreeMap::new(),
            raba_aux: BTreeMap::new(),
        }
    }

    pub fn get_own_mvba(&self) -> &CertifiedMVBA {
        self.mvbas.get(&self.authority).unwrap()
    }

    /// first_propose_for_fin returns true iff there are exactly n-f certified mvbas
    pub fn first_propose_for_fin(&self, acs_quorum: Stake) -> bool {
        self.mvbas
            .iter()
            .filter(|(authority, mvba)| {
                if **authority == self.authority {
                    if mvba.signatures.len() as u64 >= acs_quorum {
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    // note that except for our own mvba, mvbas of other peers stored in acs_fin are certified, i.e., with 2f+1 signatures
                    return true;
                }
            })
            .count() as u64
            == acs_quorum
    }

    /// repropose_for_fin returns true if there are more than n-f certified mvbas
    pub fn repropose_for_fin(&self, acs_quorum: Stake) -> bool {
        self.mvbas
            .iter()
            .filter(|(authority, mvba)| {
                if **authority == self.authority {
                    if mvba.signatures.len() as u64 >= acs_quorum {
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    // note that except for our own mvba, mvbas of other peers stored in acs_fin are certified, i.e., with 2f+1 signatures
                    return true;
                }
            })
            .count() as u64
            > acs_quorum
    }

    /// add_certified_mvba returns true if the mvba is added successfully
    pub fn add_certified_mvba(&mut self, mvba: CertifiedMVBA) -> bool {
        match mvba.round.cmp(&self.last_acs_round) {
            // ignore a mvba with a round equal to the last ACS round
            Ordering::Less => false,
            // todo: may need to handle a future certified mvba
            Ordering::Greater => {
                tracing::warn!("Received a mvba with a round larger than the last ACS round");
                false
            }
            // receive a new mvba for this stuck round
            Ordering::Equal => {
                let authority = mvba.authority;
                if let Err(e) = mvba.verify(&self.committee) {
                    tracing::warn!("Invalid mvba from {}: {:?}", authority, e);
                    return false;
                } else {
                    if self.mvbas.contains_key(&authority) {
                        tracing::debug!("Already received a mvba from {}: {:?}", authority, mvba);
                        return false;
                    }
                    self.mvbas.insert(authority, mvba);
                    return true;
                }
            }
        }
    }

    pub fn add_pisa_aba_bvals(
        &mut self,
        bvals: Vec<PisaABABval>,
        signer: &Signer,
    ) -> Vec<PisaABAMessage> {
        let mut return_messages = Vec::new();
        for bval in bvals {
            if let Err(e) = bval.verify(&self.committee) {
                tracing::warn!("Invalid pisa aba bval from {}: {:?}", bval.author(), e);
                continue;
            }
            match bval.view.cmp(&self.mvba_view) {
                Ordering::Less => {
                    tracing::warn!("Received a pisa aba bval with older view: {:?}", bval.view);
                    continue;
                }
                Ordering::Greater => {
                    // we will buffer the future pisa aba bval
                    if self
                        .raba_bvals
                        .get(&bval.view)
                        .unwrap()
                        .iter()
                        .any(|b| b.digest() == bval.digest())
                    {
                        tracing::debug!(
                            "Already received this pisa aba bval from {}: {:?}",
                            bval.author(),
                            bval
                        );
                        continue;
                    }
                    self.raba_bvals
                        .entry(bval.view.clone())
                        .or_insert(Vec::new())
                        .push(bval.clone());
                }
                Ordering::Equal => {
                    if self
                        .raba_bvals
                        .get(&bval.view)
                        .unwrap()
                        .iter()
                        .any(|b| b.digest() == bval.digest())
                    {
                        tracing::debug!(
                            "Already received a pisa aba bval from {}: {:?}",
                            bval.author(),
                            bval
                        );
                        continue;
                    }
                    self.raba_bvals
                        .entry(bval.view.clone())
                        .or_insert(Vec::new())
                        .push(bval.clone());
                    // we handle the pisa aba bval differently if we are in the 0-th aba round
                    if self.mvba_view.aba_round == 0 {
                        if bval.authority == self.authority {
                            let return_aux =
                                PisaABAAux::new(bval.view.clone(), 1, 1, self.authority, signer);
                            return_messages.push(PisaABAMessage::PisaABAAux(return_aux));
                        } else {
                            let est = bval.est;
                            let est_count = self
                                .raba_bvals
                                .get(&bval.view)
                                .unwrap()
                                .iter()
                                .filter(|&b| b.est == est)
                                .count();
                            if est_count >= self.committee.acs_validity_threshold() as usize {
                                // if we haven't send this bval, then do it
                                if let Some(return_bval) = self.create_bval(bval.clone(), signer) {
                                    return_messages.push(PisaABAMessage::PisaABABval(return_bval));
                                }
                                if est == 1 {
                                    if let Some(return_aux) =
                                        self.create_aux_with_inputs(bval.view.clone(), 1, 1, signer)
                                    {
                                        return_messages
                                            .push(PisaABAMessage::PisaABAAux(return_aux));
                                    }
                                }
                            }
                            if est_count >= self.committee.acs_quorum_threshold() as usize {
                                if let Some(return_aux) =
                                    self.create_aux_with_inputs(bval.view.clone(), est, est, signer)
                                {
                                    return_messages.push(PisaABAMessage::PisaABAAux(return_aux));
                                }
                            }
                        }
                    } else {
                        let est = bval.est;
                        let est_count = self
                            .raba_bvals
                            .get(&bval.view)
                            .unwrap()
                            .iter()
                            .filter(|&b| b.est == est)
                            .count();
                        // receive f+1 PisaABABval with the same est value
                        if est_count >= self.committee.acs_validity_threshold() as usize {
                            // if we haven't send this bval, then do it
                            if let Some(return_bval) = self.create_bval(bval.clone(), signer) {
                                return_messages.push(PisaABAMessage::PisaABABval(return_bval));
                            }
                        }
                        // receive n-f PisaABABval with the same est value, enter the agreement phase
                        if est_count >= self.committee.acs_quorum_threshold() as usize {
                            if let Some(return_aux) = self.create_aux(bval.clone(), signer) {
                                return_messages.push(PisaABAMessage::PisaABAAux(return_aux));
                            }
                        }
                    }
                }
            }
        }
        return_messages
    }

    pub fn add_pisa_aba_auxs(&mut self, auxs: Vec<PisaABAAux>) -> Option<MVBA> {
        for aux in auxs {
            if let Err(e) = aux.verify(&self.committee) {
                tracing::warn!("Invalid pisa aba aux from {}: {:?}", aux.author(), e);
                continue;
            }
            match aux.view.cmp(&self.mvba_view) {
                Ordering::Less => {
                    tracing::warn!("Received a pisa aba aux with older view: {:?}", aux.view);
                    continue;
                }
                Ordering::Greater => {
                    // we will buffer the future pisa aba aux
                    if self
                        .raba_aux
                        .get(&aux.view)
                        .unwrap()
                        .iter()
                        .any(|b| b.digest() == aux.digest())
                    {
                        tracing::debug!(
                            "Already received this pisa aba aux from {}: {:?}",
                            aux.author(),
                            aux
                        );
                        continue;
                    }
                    self.raba_aux
                        .entry(aux.view.clone())
                        .or_insert(Vec::new())
                        .push(aux.clone());
                }
                Ordering::Equal => {
                    if self
                        .raba_aux
                        .get(&aux.view)
                        .unwrap()
                        .iter()
                        .any(|b| b.digest() == aux.digest())
                    {
                        tracing::debug!(
                            "Already received a pisa aba aux from {}: {:?}",
                            aux.author(),
                            aux
                        );
                        continue;
                    }
                    // check if we accept this aux
                    let mut bin_values = self.get_binary_values_in_view(aux.view.clone());
                    bin_values.push(2);
                    if !bin_values.contains(&aux.aux1) || !bin_values.contains(&aux.aux2) {
                        tracing::warn!("Invalid pisa aba aux from {}: {:?}", aux.author(), aux);
                        continue;
                    }
                    if aux.aux1 + aux.aux2 == 1 || aux.aux2 == 2 {
                        tracing::warn!("Invalid pisa aba aux from {}: {:?}", aux.author(), aux);
                        continue;
                    }
                    self.raba_aux
                        .entry(aux.view.clone())
                        .or_insert(Vec::new())
                        .push(aux.clone());
                }
            }
        }

        // discard invalid aux if delta_b is 1
        if self.delta_b(0) == 1 {
            // discard all aux with aux1 = 1
            self.raba_aux
                .entry(self.mvba_view.clone())
                .or_insert(Vec::new())
                .retain(|aux| aux.aux1 != 1);
        } else if self.delta_b(1) == 1 {
            // discard all aux with aux1 = 0
            self.raba_aux
                .entry(self.mvba_view.clone())
                .or_insert(Vec::new())
                .retain(|aux| aux.aux1 != 0);
        }
        // if we have n-f PisaABAAux, then we can enter the agreement phase
        if self.raba_aux.get(&self.mvba_view).unwrap().len()
            >= self.committee.acs_quorum_threshold() as usize
        {
            if self.mvba_view.aba_round == 0 {
                if let Some(decided_authority) = self.try_decide_in_round_0() {
                    // if we can decide, then we can commit the ACS
                    if let Some(mvba) = self.mvbas.get(&decided_authority) {
                        return Some(mvba.proposal);
                    } else {
                        tracing::warn!(
                            "We should decide but cannot find the mvba from the decided authority {}",
                            decided_authority
                        );
                        // we use 0 to represent the status: we can decide but haven't received the mvba from the decided authority
                        return Some(0);
                    }
                }
            } else {
                if let Some(decided_authority) = self.try_decide() {
                    // if we can decide, then we can commit the ACS
                    if let Some(mvba) = self.mvbas.get(&decided_authority) {
                        return Some(mvba.proposal);
                    } else {
                        tracing::warn!(
                            "We should decide but cannot find the mvba from the decided authority {}",
                            decided_authority
                        );
                        // we use 0 to represent the status: we can decide but haven't received the mvba from the decided authority
                        return Some(0);
                    }
                }
            }
        }
        return None;
    }

    /// try_decide_in_round_0 will return the AuthorityIndex whose mvba proposal has been decided
    fn try_decide_in_round_0(&mut self) -> Option<AuthorityIndex> {
        let mut decided_value = 2;
        let mut next_est = 2;
        let mut next_maj = 2;
        let current_coin = 1;
        let vals = self.get_agreement_phase_vals(self.mvba_view.clone());
        for new_b in [0, 1] {
            if self.get_number_of_a_value(&vals, new_b)
                >= self.committee.acs_raba_decide_threshold()
            {
                next_est = new_b;
                next_maj = new_b;
                if new_b == current_coin {
                    decided_value = 1;
                }
            } else {
                next_est = 1;
                next_maj = 1;
            }
        }
        if decided_value == 1 {
            tracing::info!("RABA decide {} in view {:?}", 1, self.mvba_view);
            return Some(self.election(self.mvba_view.mvba_round));
        } else {
            // unfortunately, we cannot decide, enter next aba round
            let new_view = FINMVBAView::new_with_rounds(
                self.mvba_view.mvba_round,
                self.mvba_view.aba_round + 1,
            );
            self.new_fin_view(new_view, next_est, next_maj);
            return None;
        }
    }

    /// try_decide will return the AuthorityIndex whose mvba proposal has been decided
    fn try_decide(&mut self) -> Option<AuthorityIndex> {
        let mut decided_value = 2;
        let mut next_est = 2;
        let mut next_maj = 2;
        let last_coin = self.coin(self.mvba_view.aba_round - 1);
        let current_coin = self.coin(self.mvba_view.aba_round);
        // let vals = self.get_binary_values_in_view(self.mvba_view.clone());
        let vals = self.get_agreement_phase_vals(self.mvba_view.clone());
        let avals = self.get_agreement_phase_avals(self.mvba_view.clone());
        for new_b in [0, 1] {
            if self.get_number_of_a_value(&vals, new_b)
                >= self.committee.acs_raba_decide_threshold()
            {
                next_est = new_b;
                next_maj = new_b;
                if current_coin == new_b {
                    tracing::info!("RABA decide {} in view {:?}", new_b, self.mvba_view);
                    decided_value = new_b;
                }
            }
            if self.mvba_view.aba_round > 0
                && (self.get_only_value(&vals) == 2
                    || self.get_number_of_a_value(&vals, new_b)
                        < self.committee.acs_raba_decide_threshold())
            {
                if self.get_number_of_a_value(&avals, new_b)
                    >= self.committee.acs_raba_decide_threshold()
                {
                    next_est = new_b;
                    next_maj = new_b;
                    if current_coin == new_b && last_coin == new_b {
                        tracing::info!("RABA decide {} in view {:?}", new_b, self.mvba_view);
                        decided_value = new_b;
                    }
                } else if avals.contains(&new_b) && new_b == last_coin {
                    next_est = new_b;
                    next_maj = new_b;
                }
            }
        }
        // if next_est hasn't been set
        if next_est == 2 {
            next_est = current_coin;
            if self.mvba_view.aba_round == 0 {
                next_maj = current_coin;
            } else {
                next_maj = self.get_majority(&vals)
            }
        }
        // enter next aba round or decide!
        if decided_value == 0 {
            // we have decided 0
            // however, we cannot decide our mvba, enter a new mvba round and choose another mvba value
            tracing::debug!(
                "Decided 0 in view {:?}, enter a new mvba roudn",
                self.mvba_view
            );
            let new_view = FINMVBAView::new_with_rounds(self.mvba_view.mvba_round + 1, 0);
            let elected_mvba = self.election(new_view.mvba_round);
            // if we receive elected_mvba, est is set to 1
            if let Some(_mvba) = self.mvbas.get(&elected_mvba) {
                self.new_fin_view(new_view, 1, 0);
            } else {
                self.new_fin_view(new_view, 0, 0);
            }
            return None;
        } else if decided_value == 1 {
            // the acs has decided
            tracing::debug!("Decided 1 in view {:?}, the acs is done!", self.mvba_view);
            // todo: commit blocks with post blocks, update
            return Some(self.election(self.mvba_view.mvba_round));
        } else {
            // enter next aba round
            let new_view = FINMVBAView::new_with_rounds(
                self.mvba_view.mvba_round,
                self.mvba_view.aba_round + 1,
            );
            self.new_fin_view(new_view, next_est, next_maj);
            return None;
        }
    }

    fn create_aux(&mut self, bval: PisaABABval, signer: &Signer) -> Option<PisaABAAux> {
        let est = bval.est;
        let est_cap = (est + 1) % 2;
        let delta_b = self.delta_b(est);
        // if we haven't broadcast aux message, then do it
        if !self
            .raba_aux
            .get(&bval.view)
            .unwrap()
            .iter()
            .any(|aux| aux.authority == self.authority && aux.aux1 == est)
            || !self
                .raba_aux
                .get(&bval.view)
                .unwrap()
                .iter()
                .any(|aux| aux.authority == self.authority && aux.aux1 == est_cap)
        {
            if delta_b == 1 {
                let return_aux =
                    PisaABAAux::new(bval.view.clone(), est, est, self.authority, signer);
                // add own aux to the view
                self.raba_aux
                    .entry(bval.view.clone())
                    .or_insert(Vec::new())
                    .push(return_aux.clone());
                return Some(return_aux);
            } else {
                let return_aux = PisaABAAux::new(bval.view.clone(), 2, est, self.authority, signer);
                // add own aux to the view
                self.raba_aux
                    .entry(bval.view.clone())
                    .or_insert(Vec::new())
                    .push(return_aux.clone());
                return Some(return_aux);
            }
        }
        None
    }

    fn create_aux_with_inputs(
        &mut self,
        view: FINMVBAView,
        aux1: BinaryValue,
        aux2: BinaryValue,
        signer: &Signer,
    ) -> Option<PisaABAAux> {
        if !self
            .raba_aux
            .get(&view)
            .unwrap()
            .iter()
            .any(|aux| aux.authority == self.authority && aux.aux1 == aux1 && aux.aux2 == aux2)
        {
            let new_aux = PisaABAAux::new(view.clone(), aux1, aux2, self.authority, signer);
            self.raba_aux
                .entry(view.clone())
                .or_insert(Vec::new())
                .push(new_aux.clone());
            return Some(new_aux);
        }
        None
    }

    fn create_bval(&mut self, bval: PisaABABval, signer: &Signer) -> Option<PisaABABval> {
        let est = bval.est;
        if !self
            .raba_bvals
            .get(&bval.view)
            .unwrap()
            .iter()
            .any(|b| b.authority == self.authority && b.est == est)
        {
            let new_bval = PisaABABval::new(
                bval.view.clone(),
                est,
                self.current_maj,
                self.authority,
                signer,
            );
            self.raba_bvals
                .entry(bval.view.clone())
                .or_insert(Vec::new())
                .push(new_bval.clone());
            return Some(new_bval);
        }
        None
    }

    pub fn update_rbab_round(
        &mut self,
        new_est: BinaryValue,
        new_maj: BinaryValue,
        signer: &Signer,
    ) -> PisaABABval {
        self.mvba_view.aba_round += 1;
        let new_pisa_aba_bval = PisaABABval::new(
            self.mvba_view.clone(),
            new_est,
            new_maj,
            self.authority,
            signer,
        );
        self.raba_bvals
            .entry(self.mvba_view.clone())
            .or_insert(Vec::new())
            .push(new_pisa_aba_bval.clone());
        return new_pisa_aba_bval;
    }

    /// bin_values
    pub fn get_binary_values_in_view(&self, view: FINMVBAView) -> Vec<BinaryValue> {
        let mut bvals = HashSet::new();
        if view > self.mvba_view {
            tracing::warn!("Fail to get binary values: The view is in the future");
            return bvals.into_iter().collect();
        }
        // we can only do this when we have n-f PisaABAAux in the view
        if self.raba_aux.get(&view).unwrap().len() < self.committee.acs_quorum_threshold() as usize
        {
            tracing::warn!("Fail to get binary values: Not enough PisaABAAux in the view");
            return bvals.into_iter().collect();
        }
        let bval_with_zero = self
            .raba_bvals
            .get(&view.clone())
            .unwrap()
            .iter()
            .filter(|&bval| bval.est == 0)
            .count();
        let bval_with_one = self
            .raba_bvals
            .get(&view.clone())
            .unwrap()
            .iter()
            .filter(|&bval| bval.est == 1)
            .count();
        if view.aba_round == 0 {
            if let Some(raba_bvals) = self.raba_bvals.get(&view) {
                // if our own bval.est = 1 or we receive a bval.est = 1, then we add it to the bin_values
                if raba_bvals.iter().any(|bval| bval.est == 1) {
                    bvals.insert(1);
                }
            }
        }
        if bval_with_zero >= (self.committee.acs_quorum_threshold() as usize) {
            bvals.insert(0);
        }
        if bval_with_one >= (self.committee.acs_quorum_threshold() as usize) {
            bvals.insert(1);
        }
        return bvals.into_iter().collect();
    }

    /// majs
    pub fn get_majs_in_view(&self, view: FINMVBAView) -> Vec<BinaryValue> {
        if self.mvba_view.aba_round == 0 {
            // todo
        }
        let mut majs = HashSet::new();
        if view > self.mvba_view {
            tracing::warn!("Fail to get majs: The view is in the future");
            return majs.into_iter().collect();
        }
        // we can only do this when we have n-f PisaABABval with est=0 (or est=1) in the view
        let bval_with_zero = self
            .raba_bvals
            .get(&view.clone())
            .unwrap()
            .iter()
            .filter(|&bval| bval.est == 0)
            .count();
        let bval_with_one = self
            .raba_bvals
            .get(&view.clone())
            .unwrap()
            .iter()
            .filter(|&bval| bval.est == 1)
            .count();
        if bval_with_zero < (self.committee.acs_quorum_threshold() as usize)
            && bval_with_one < (self.committee.acs_quorum_threshold() as usize)
        {
            tracing::warn!("Fail to get majority values: Not enough PisaABABval in the view");
            return majs.into_iter().collect();
        }
        for bval in self.raba_bvals.get(&view).unwrap() {
            majs.insert(bval.maj);
        }
        return majs.into_iter().collect();
    }

    pub fn new_fin_view(
        &mut self,
        new_view: FINMVBAView,
        new_bval: BinaryValue,
        new_maj: BinaryValue,
    ) {
        self.mvba_view = new_view.clone();
        self.current_bval = new_bval;
        self.current_maj = new_maj;
    }

    /// Agreement phase: vals
    pub fn get_agreement_phase_vals(&self, view: FINMVBAView) -> Vec<BinaryValue> {
        let mut return_vals = Vec::new();
        if self.mvba_view.aba_round == 0 {
            // todo
        }
        let aux_count = self.raba_aux.get(&view).unwrap().len();
        if aux_count < self.committee.acs_quorum_threshold() as usize {
            tracing::warn!(
                "Error, we won't trigger this function if we received less than {} aux",
                self.committee.acs_quorum_threshold()
            );
        }
        // we collect all aux1 of self.raba_aux into return_vals
        for aux in self.raba_aux.get(&view).unwrap() {
            return_vals.push(aux.aux1);
        }
        return_vals
    }

    /// Agreement phase: avals
    pub fn get_agreement_phase_avals(&self, view: FINMVBAView) -> Vec<BinaryValue> {
        let mut return_avals = Vec::new();
        if self.mvba_view.aba_round == 0 {
            // todo
        }
        let aux_count = self.raba_aux.get(&view).unwrap().len();
        if aux_count < self.committee.acs_quorum_threshold() as usize {
            tracing::warn!(
                "Error, we won't trigger this function if we received less than {} aux",
                self.committee.acs_quorum_threshold()
            );
        }
        // we collect all aux2 of self.raba_aux into return_avals
        for aux in self.raba_aux.get(&view).unwrap() {
            return_avals.push(aux.aux2);
        }
        return_avals
    }

    pub fn raba_propose(&self) {
        // todo
    }

    pub fn raba_repropose(&self) {
        // todo
    }

    pub fn raba_decide(&mut self) {
        // todo
    }

    /// todo: random
    /// Current election: round robin
    pub fn election(&self, mvba_round: MVBARoundNumber) -> AuthorityIndex {
        mvba_round as AuthorityIndex % self.committee.len() as AuthorityIndex
    }

    pub fn current_election(&self) -> AuthorityIndex {
        self.election(self.mvba_view.mvba_round)
    }

    /// todo: random
    /// Current election: coin flip
    pub fn coin(&self, aba_round: ABARoundNumber) -> BinaryValue {
        // todo
        aba_round as BinaryValue % 2
    }

    /// clean up raba_bvals and raba_aux before the view
    pub fn cleanup(&mut self, view: FINMVBAView) {
        let keys_to_remove: Vec<_> = self
            .raba_bvals
            .keys()
            .filter(|&key| key.clone() < view)
            .cloned()
            .collect();
        for key in keys_to_remove {
            self.raba_bvals.remove(&key);
            self.raba_aux.remove(&key);
        }
    }

    /* These are auxiliary functions */
    /// the V1 function in the Pisa protocol
    pub fn get_only_value(&self, vals: &Vec<BinaryValue>) -> BinaryValue {
        let size = vals.len();
        let zero_val = vals.iter().filter(|&v| *v == 0).count();
        if zero_val == size {
            return 0;
        }
        let one_val = vals.iter().filter(|&v| *v == 1).count();
        if one_val == size {
            return 1;
        }
        let two_val = vals.iter().filter(|&v| *v == 2).count();
        if two_val == size {
            return 2;
        }
        // return others
        return 3;
    }

    /// the V2 function in the Pisa protocol
    pub fn get_number_of_a_value(&self, vals: &Vec<BinaryValue>, val: BinaryValue) -> u64 {
        let zero_val = vals.iter().filter(|&v| *v == 0).count();
        let one_val = vals.iter().filter(|&v| *v == 1).count();
        if zero_val != 0 && one_val != 0 {
            return 0;
        }
        vals.iter().filter(|&v| *v == val).count() as u64
    }

    pub fn get_majority(&self, vals: &Vec<BinaryValue>) -> BinaryValue {
        let size = vals.len();
        let zero_val = vals.iter().filter(|&v| *v == 0).count();
        if zero_val >= (size + 1) / 2 {
            return 0;
        }
        let one_val = vals.iter().filter(|&v| *v == 1).count();
        if one_val >= (size + 1) / 2 {
            return 1;
        }
        // return None otherwise
        return 2;
    }

    /// Get current view's delta_b, return:
    /// 1) 0: we receive n-f PisaABAAux with this est, but it doesn't satisfy the condition
    /// 2) 1: we receive n-f PisaABAAux with this est, and it satisfies the condition
    /// 3) 2: we haven't receive n-f PisaABAAux with this est
    pub fn delta_b(&self, est: BinaryValue) -> BinaryValue {
        let mut delta_b = 2;
        // we are not ready to set delta_b for this view
        if self
            .raba_bvals
            .get(&self.mvba_view)
            .unwrap()
            .iter()
            .filter(|&b| b.est == est)
            .count()
            < self.committee.acs_quorum_threshold() as usize
        {
            return delta_b;
        }
        if self.mvba_view.aba_round == 0 {
            // todo
            delta_b = 1;
        }
        let last_coin = self.coin(self.mvba_view.aba_round - 1);
        let est_cap = (est + 1) % 2;
        let majs = self.get_majs_in_view(self.mvba_view.clone());
        if (est == last_coin && self.get_only_value(&majs) == est)
            || (est == last_coin && !majs.contains(&est_cap))
        {
            delta_b = 1;
        }
        return delta_b;
    }
}
