use crate::{
    committee::Committee,
    crypto::{MetaPoSTBlockDigest, PublicKey, ReliableMVBADigest, SignatureBytes, Signer},
    data::Data,
    types::{AuthorityIndex, BlockReference, RoundNumber, Stake, StatementBlock},
};
use eyre::{bail, Ok};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeMap};
use std::collections::HashMap;

pub type MVBA = u128;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReliableMVBAProposal {
    pub authority: AuthorityIndex,
    pub round: RoundNumber, // the last round agreed by the ACS mode
    pub proposal: MVBA,
    pub signature: SignatureBytes, // my signature on this mvba proposal
}

impl ReliableMVBAProposal {
    pub fn new_with_signer(
        authority: AuthorityIndex,
        round: RoundNumber,
        proposal: MVBA,
        signer: Signer,
    ) -> Self {
        let signature = signer.sign_mvba_proposal(authority, round, proposal);
        Self {
            authority,
            round,
            proposal,
            signature,
        }
    }

    pub fn digest(&self) -> ReliableMVBADigest {
        ReliableMVBADigest::new(self.authority, self.round, self.proposal)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReliableMVBA {
    pub authority: AuthorityIndex,
    pub round: RoundNumber, // the last round agreed by the ACS mode
    pub proposal: MVBA, // the proposal value
    pub signatures: Vec<(PublicKey, SignatureBytes)>, // 2f+1 signatures
}

impl ReliableMVBA {
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

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        if self.signatures.len() < committee.quorum_threshold() as usize {
            eyre::bail!("Not enough signatures");
        }
        for (author, signature) in &self.signatures {
            if !committee.known_authority_key(author) {
                eyre::bail!("Unknown authority");
            }
            if author
                .verify_reliable_mvba_with_signature(self, signature)
                .is_err()
            {
                eyre::bail!("Invalid signature");
            }
        }
        Ok(())
    }
}

pub struct ACSManager {
    authority: AuthorityIndex,
    public_key: PublicKey,
    committee: Committee, // for verification
    round: RoundNumber, // the last round agreed by the ACS mode
    last_seen_meta_post_blocks: HashMap<AuthorityIndex, MetaPoSTBlockData>,
    post_blocks: HashMap<AuthorityIndex, CertifiedPoSTBlockData>,
    mvba: ReliableMVBA, // the MVBA proposal of the node
}

impl ACSManager {
    pub fn new(authority: AuthorityIndex, public_key: PublicKey, committee: Committee, round: RoundNumber) -> Self {
        Self {
            authority,
            public_key,
            committee,
            round,
            last_seen_meta_post_blocks: HashMap::new(),
            post_blocks: HashMap::new(),
            mvba: ReliableMVBA::new(authority, round, 0),
        }
    }

    pub fn create_own_post_block(
        &mut self,
        round: RoundNumber,
        last_block: Data<StatementBlock>,
        last_seen_blocks: BTreeMap<AuthorityIndex, BlockReference>,
    ) -> CertifiedPoSTBlockData {
        if self.round > round {
            tracing::error!(
                "The last ACS round {} is larger than the current round {}",
                self.round,
                round
            );
        }
        // first see if we have already created a PoST block
        if self.post_blocks.contains_key(&self.authority) {
            return self.post_blocks.get(&self.authority).unwrap().clone();
        } else {
            let post_block =
                CertifiedPoSTBlockData::new(round, last_block, last_seen_blocks, Vec::new());
            self.post_blocks.insert(self.authority, post_block.clone());
            return post_block;
        }
    }

    pub fn add_post_block(&mut self, post_block: CertifiedPoSTBlockData, acs_quorum: Stake) {
        match post_block.stuck_round.cmp(&self.round) {
            // ignore a PoST block with a round less than or equal to the last ACS round
            Ordering::Less | Ordering::Equal => {}
            // receive a new PoST block
            Ordering::Greater => {
                let authority = post_block.stuck_block.reference().authority;
                // todo: we currently only support 128 authorities
                if authority > 128 {
                    tracing::error!(
                        "The authority index {} is too large (maximum is 128)",
                        authority
                    );
                    return;
                }
                if self.post_blocks.contains_key(&authority) {
                    tracing::debug!("PoST block from authority {} already received", authority);
                    return;
                }
                self.post_blocks.insert(authority, post_block);
                if (self.mvba.proposal.count_ones() as u64) >= acs_quorum {
                    // note that we don't change the input of the MVBA protocol
                    tracing::info!("MVBA already reached quorum");
                    // return;
                } else {
                    self.mvba.proposal |= 1 << authority;
                    // tracing::info!("Number of 1s in mvba: {}", count);
                }
            }
        }
    }

    fn add_meta_post_block(&mut self, meta_post_block: MetaPoSTBlockData) -> bool {
        match meta_post_block.stuck_round.cmp(&self.round) {
            // ignore a PoST block with a round less than or equal to the last ACS round
            Ordering::Less | Ordering::Equal => {
                return false;
            }
            // receive a new PoST block
            Ordering::Greater => {
                let authority = meta_post_block.stuck_block.reference().authority;
                // todo: we currently only support 128 authorities
                if authority > 128 {
                    tracing::error!(
                        "The authority index {} is too large (maximum is 128)",
                        authority
                    );
                    return false;
                }
                if let Some(meta) =  self.last_seen_meta_post_blocks.get(&authority) {
                    if meta.digest() == meta_post_block.digest() {
                        // this is legal meta post block
                        tracing::debug!("PoST block from authority {} already received", authority);
                        return true;
                    } else {
                        // this is illegal meta post block
                        tracing::debug!("PoST block from authority {} is illegal", authority);
                        return false;
                    }
                } else {
                    self.last_seen_meta_post_blocks.insert(authority, meta_post_block);
                    return true;
                }
            }
        }
    }

    /// this function handle:
    /// 1) vote for our post block
    /// 2) votes servicing as a meta post block from other peers
    pub fn add_votes(&mut self, votes: Vec<PoSTBlockVote>, acs_quorum: Stake) -> Vec<CertifiedPoSTBlockData> {
        let mut return_post_blocks = Vec::new();
        for vote in votes {
            // verify the signature
            if let Err(e) = vote.verify(&self.committee) {
                tracing::warn!("Rejected incorrect PoST block vote {:?}: {:?}", vote, e);
                continue;
            }
            let vote_block_author = vote.vote_author();
            let vote_public_key = vote.author.clone();
            if !self.committee.known_authority_key(&vote_public_key) {
                tracing::warn!("Unknown public key");
            } else {
                if vote_block_author == self.authority {
                    // we handle vote for ourself
                    if let Some(post_block) = self.post_blocks.get_mut(&self.authority) {
                        // check if the vote is for our own PoST block
                        if post_block.get_meta_post_block().digest() == vote.meta_post_block.digest() {
                            // if we already have enough signatures, ignore the vote to avoid different PoST blocks
                            if post_block.signatures.len() >= acs_quorum as usize {
                                continue;
                            }                           
                            // add the signature to the PoST block
                            post_block.update_signature(vote.author, vote.signature);
                            if post_block.signatures.len() >= acs_quorum as usize {
                                return_post_blocks.push(post_block.clone());
                                // own PoST block is certified
                                if (self.mvba.proposal.count_ones() as u64) >= acs_quorum {
                                    // note that we don't change the input of the MVBA protocol
                                    tracing::info!("MVBA already reached quorum");
                                    // return;
                                } else {
                                    self.mvba.proposal |= 1 << self.authority;
                                    // tracing::info!("Number of 1s in mvba: {}", count);
                                }
                            }
                        }
                    }
                } else {
                    // we handle meta post block from other peer
                    if self.add_meta_post_block(vote.meta_post_block.clone()) {
                        // this meta post block is valid
                        let peer_post_block = CertifiedPoSTBlockData::new(vote.meta_post_block.stuck_round, vote.meta_post_block.stuck_block, vote.meta_post_block.seen_blocks, Vec::new());
                        return_post_blocks.push(peer_post_block);
                    }
                }
            }
            
        }
        return_post_blocks
    }

    // pub fn read_my_post_block_after_round(
    //     &self,
    //     round: RoundNumber,
    //     acs_quorum: Stake,
    // ) -> Vec<CertifiedPoSTBlockData> {
    //     let mut my_post_blocks = Vec::new();
    //     if let Some(my_post_block) = self.post_blocks.get(&self.authority) {
    //         if my_post_block.stuck_round > round
    //             && my_post_block.signatures.len() > acs_quorum as usize
    //         {
    //             my_post_blocks.push(my_post_block.clone());
    //         }
    //     }
    //     my_post_blocks
    // }

    // pub fn read_my_meta_post_block_after_round(
    //     &self,
    //     round: RoundNumber,
    // ) -> Vec<MetaPoSTBlockData> {
    //     let mut my_meta_post_blocks = Vec::new();
    //     if let Some(my_post_block) = self.post_blocks.get(&self.authority) {
    //         if my_post_block.stuck_round > round {
    //             my_meta_post_blocks.push(my_post_block.get_meta_post_block());
    //         }
    //     }
    //     my_meta_post_blocks
    // }

    // pub fn read_my_uncertified_mvba_after_round(
    //     &self,
    //     round: RoundNumber,
    // ) -> Vec<ReliableMVBAProposal> {
    //     let mut my_uncertified_mvbas = Vec::new();
    //     // todo
    //     // if let Some(my_post_block) = self.post_blocks.get(&self.authority) {
    //     //     if my_post_block.stuck_round > round {
    //     //         my_meta_post_blocks.push(my_post_block.get_meta_post_block());
    //     //     }
    //     // }
    //     my_uncertified_mvbas
    // }

    // pub fn read_my_certified_mvba_after_round(
    //     &self,
    //     round: RoundNumber,
    // ) -> Vec<ReliableMVBA> {
    //     let mut my_certified_mvbas = Vec::new();
    //     // todo
    //     // if let Some(my_post_block) = self.post_blocks.get(&self.authority) {
    //     //     if my_post_block.stuck_round > round {
    //     //         my_meta_post_blocks.push(my_post_block.get_meta_post_block());
    //     //     }
    //     // }
    //     my_certified_mvbas
    // }

    pub fn ready_for_mvba(&self, committee: &Committee) -> bool {
        (self.mvba.proposal.count_ones() as u64) >= committee.quorum_threshold()
    }

    pub fn authority(&self) -> AuthorityIndex {
        self.authority
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    pub fn last_acs_round(&self) -> RoundNumber {
        self.round
    }

    pub fn reset(&mut self) {
        self.post_blocks.clear();
        // todo 
        // self.mvba = 0;
    }
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
    pub author: PublicKey,
    pub signature: SignatureBytes,
}

impl PoSTBlockVote {
    pub fn new(
        meta_post_block: MetaPoSTBlockData,
        author: PublicKey,
        signer: Signer,
    ) -> Self {
        let signature = signer.sign_post_block(
            meta_post_block.stuck_round,
            meta_post_block.stuck_block(),
            meta_post_block.seen_blocks(),
        );
        Self {
            meta_post_block,
            author,
            signature,
        }
    }

    pub fn meta_post_block(&self) -> &MetaPoSTBlockData {
        &self.meta_post_block
    }

    pub fn signature(&self) -> &SignatureBytes {
        &self.signature
    }

    pub fn vote_author(&self) -> AuthorityIndex{
        self.meta_post_block.stuck_block().reference().authority
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        if !committee.known_authority_key(&self.author) {
            bail!("Unknown block author {:?}", self.author)
        }
        if let Err(e) = self.author.verify_post_block_vote(self) {
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
        // todo: verify
        let meta_post_block = self.get_meta_post_block();
        if self.signatures.len() < committee.quorum_threshold() as usize {
            eyre::bail!("Not enough signatures, only {} but quorum is {}", self.signatures.len(), committee.quorum_threshold());
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
