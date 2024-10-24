use crate::{
    acs_types::{
        ACSFin, CertifiedMVBA, CertifiedPoSTBlockData, MVBAProposal, MVBAVote, MetaPoSTBlockData,
        PoSTBlockVote,
    },
    committee::Committee,
    crypto::{PublicKey, Signer},
    data::Data,
    types::{AuthorityIndex, BlockReference, RoundNumber, Stake, StatementBlock},
};

use std::collections::HashMap;
use std::{cmp::Ordering, collections::BTreeMap};

pub struct ACSManager {
    authority: AuthorityIndex,
    public_key: PublicKey,
    committee: Committee, // for verification
    round: RoundNumber,   // the last round agreed by the ACS mode
    last_seen_meta_post_blocks: HashMap<AuthorityIndex, MetaPoSTBlockData>,
    post_blocks: HashMap<AuthorityIndex, CertifiedPoSTBlockData>,
    pub acs_fin: ACSFin, // manage FIN messages
    last_seen_mvba_proposal: HashMap<AuthorityIndex, MVBAProposal>,
}

impl ACSManager {
    pub fn new(
        authority: AuthorityIndex,
        public_key: PublicKey,
        committee: Committee,
        round: RoundNumber,
    ) -> Self {
        Self {
            authority,
            public_key,
            committee: committee.clone(),
            round,
            last_seen_meta_post_blocks: HashMap::new(),
            post_blocks: HashMap::new(),
            acs_fin: ACSFin::new(authority, committee, round),
            last_seen_mvba_proposal: HashMap::new(),
        }
    }

    pub fn create_own_post_block(
        &mut self,
        round: RoundNumber,
        last_block: Data<StatementBlock>,
        last_seen_blocks: BTreeMap<AuthorityIndex, BlockReference>,
        signer: Signer,
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
            let post_block = CertifiedPoSTBlockData::new_with_my_signagure(
                round,
                last_block,
                last_seen_blocks,
                signer,
            );
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
                if let Err(e) = post_block.verify(&self.committee) {
                    tracing::warn!(
                        "Rejected incorrect PoST block {}: {:?}",
                        post_block.stuck_block.reference(),
                        e
                    );
                    return;
                } else {
                    if self.post_blocks.contains_key(&authority) {
                        tracing::debug!("PoST block from authority {} already received", authority);
                        return;
                    }
                    self.post_blocks.insert(authority, post_block);
                    if (self
                        .acs_fin
                        .mvbas
                        .get(&self.authority)
                        .unwrap()
                        .proposal
                        .count_ones() as u64)
                        >= acs_quorum
                    {
                        // note that we don't change the input of the MVBA protocol
                        tracing::info!(
                            "MVBA already reached quorum, we don't change the mvba proposal"
                        );
                        // return;
                    } else {
                        self.acs_fin
                            .mvbas
                            .get_mut(&self.authority)
                            .unwrap()
                            .proposal |= 1 << authority;
                    }
                }
            }
        }
    }

    // pub fn

    /// we will check the validity of the meta post block here
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
                if let Some(meta) = self.last_seen_meta_post_blocks.get(&authority) {
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
                    self.last_seen_meta_post_blocks
                        .insert(authority, meta_post_block);
                    return true;
                }
            }
        }
    }

    pub fn add_mvba_proposal(&mut self, mvba_proposal: MVBAProposal) -> bool {
        match mvba_proposal.round.cmp(&self.round) {
            // ignore a mvba proposal with a round less than or equal to the last ACS round
            Ordering::Less => {
                return false;
            }
            // todo: may need to handle a future mvba proposal
            Ordering::Greater => {
                tracing::warn!("Received a mvba with a round larger than the last ACS round");
                return false;
            }
            // receive a new mvba proposal
            Ordering::Equal => {
                let authority = mvba_proposal.authority;
                // todo: we currently only support 128 authorities
                if authority > 128 {
                    tracing::error!(
                        "The authority index {} is too large (maximum is 128)",
                        authority
                    );
                    return false;
                }
                if let Some(proposal) = self.last_seen_mvba_proposal.get(&authority) {
                    if proposal.digest() == mvba_proposal.digest() {
                        // this is legal meta post block
                        tracing::debug!(
                            "MVBA proposal from authority {} already received",
                            authority
                        );
                        return true;
                    } else {
                        // this is illegal meta post block
                        tracing::debug!("MVBA proposal from authority {} is illegal", authority);
                        return false;
                    }
                } else {
                    self.last_seen_mvba_proposal
                        .insert(authority, mvba_proposal);
                    return true;
                }
            }
        }
    }

    /// this function handle:
    /// 1) vote for our post block
    /// 2) votes servicing as a meta post block from other peers
    /// It returns: 1) own post block with 2f+1 signatures, 2) a post block used to create a post block vote for other peers
    pub fn add_votes(
        &mut self,
        votes: Vec<PoSTBlockVote>,
        acs_quorum: Stake,
    ) -> Vec<CertifiedPoSTBlockData> {
        let mut return_post_blocks = Vec::new();
        for vote in votes {
            // verify the signature
            if let Err(e) = vote.verify(&self.committee) {
                tracing::warn!("Rejected incorrect PoST block vote {:?}: {:?}", vote, e);
                continue;
            }
            let vote_block_author = vote.vote_creator();
            let vote_public_key = self.committee.get_public_key(vote.author());
            let Some(vote_public_key) = vote_public_key else {
                tracing::warn!("Unknown vote author {}", vote.author());
                continue;
            };
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
                        post_block.update_signature(vote_public_key.clone(), vote.signature);
                        if post_block.signatures.len() >= acs_quorum as usize {
                            return_post_blocks.push(post_block.clone());
                            // own PoST block is certified
                            if (self
                                .acs_fin
                                .mvbas
                                .get(&self.authority)
                                .unwrap()
                                .proposal
                                .count_ones() as u64)
                                >= acs_quorum
                            {
                                // note that we don't change the input of the MVBA protocol
                                tracing::info!("MVBA already reached quorum");
                                // return;
                            } else {
                                self.acs_fin
                                    .mvbas
                                    .get_mut(&self.authority)
                                    .unwrap()
                                    .proposal |= 1 << self.authority;
                            }
                        }
                    } else {
                        tracing::warn!("This vote is not for our PoST block");
                        continue;
                    }
                }
            } else {
                // we handle meta post block from other peer
                if self.add_meta_post_block(vote.meta_post_block.clone()) {
                    // this meta post block is valid
                    let peer_post_block = CertifiedPoSTBlockData::new(
                        vote.meta_post_block.stuck_round,
                        vote.meta_post_block.stuck_block,
                        vote.meta_post_block.seen_blocks,
                        Vec::new(),
                    );
                    return_post_blocks.push(peer_post_block);
                }
            }
        }
        return_post_blocks
    }

    /// this function handle:
    /// 1) uncertified mvba for our block
    /// 2) uncertified mvba from other peers
    /// It returns: 1) own mvba with 2f+1 signatures, 2) a certified mvba used to create a mvba vote for other peers
    pub fn add_mvba_votes(
        &mut self,
        uncertified_mvbas: Vec<MVBAVote>,
        acs_quorum: Stake,
    ) -> Vec<CertifiedMVBA> {
        let mut return_mvbas = Vec::new();
        for mvba in uncertified_mvbas {
            if let Err(e) = mvba.verify(&self.committee) {
                tracing::warn!("Rejected incorrect uncertified MVBA {:?}: {:?}", mvba, e);
                continue;
            }
            let mvba_author = mvba.mvba_creator();
            let voter_public_key = self.committee.get_public_key(mvba.mvba_voter());
            let Some(voter_public_key) = voter_public_key else {
                tracing::warn!("Unknown mvba vote author {}", mvba.mvba_voter());
                continue;
            };
            if mvba_author == self.authority {
                // we handle mvba vote for ourself
                if let Some(certified_mvba) = self.acs_fin.mvbas.get_mut(&self.authority) {
                    // check if the mvba vote is for our own mvba proposal
                    if certified_mvba.get_mvba_proposal().digest() == mvba.mvba_proposal.digest() {
                        // if we already have enough signatures, ignore the vote to avoid different mvba
                        if certified_mvba.signatures.len() >= acs_quorum as usize {
                            continue;
                        }
                        // add the signature to the mvba proposal
                        certified_mvba.update_signature(voter_public_key.clone(), mvba.signature);
                        if certified_mvba.signatures.len() >= acs_quorum as usize {
                            return_mvbas.push(certified_mvba.clone());
                        }
                    } else {
                        tracing::warn!("This mvba vote is not for our mvba proposal");
                        continue;
                    }
                }
            } else {
                // we handle mvba from other peer
                if self.add_mvba_proposal(mvba.mvba_proposal.clone()) {
                    // this mvba proposal is valid
                    let peer_mvba = CertifiedMVBA::new(
                        mvba.mvba_proposal.round,
                        mvba.mvba_proposal.authority,
                        mvba.mvba_proposal.proposal,
                    );
                    return_mvbas.push(peer_mvba);
                }
            }
        }
        return_mvbas
    }

    pub fn add_certified_mvba(&mut self, mvba: CertifiedMVBA) {
        self.acs_fin.add_certified_mvba(mvba);
    }

    pub fn ready_for_mvba(&self, acs_quorum: Stake) -> bool {
        self.acs_fin
            .mvbas
            .get(&self.authority)
            .unwrap()
            .proposal
            .count_ones() as u64
            >= acs_quorum
    }

    pub fn ready_for_fin(&self, acs_quorum: Stake) -> bool {
        self.acs_fin.ready_for_fin(acs_quorum)
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
