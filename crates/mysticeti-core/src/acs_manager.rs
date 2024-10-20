use crate::{
    committee::Committee,
    crypto::{PublicKey, SignatureBytes, Signer},
    data::Data,
    types::{AuthorityIndex, BlockReference, RoundNumber, StatementBlock},
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;

pub type MVBA = u128;

pub struct ACSManager {
    authority: AuthorityIndex,
    committee: Committee,
    round: RoundNumber, // the last round agreed by the ACS mode
    post_blocks: HashMap<AuthorityIndex, UncertifiedPoSTBlockData>,
    mvba: MVBA, // the MVBA proposal of the node
}

impl ACSManager {
    pub fn new(authority: AuthorityIndex, committee: Committee, round: RoundNumber) -> Self {
        Self {
            authority,
            committee,
            round,
            post_blocks: HashMap::new(),
            mvba: 0,
        }
    }

    pub fn create_own_post_block(&mut self, round: RoundNumber, last_block: Data<StatementBlock>, last_seen_blocks: HashMap<AuthorityIndex, BlockReference>) {
        if self.round > round {
            tracing::error!("The stuck round {} is larger than the current round {}", self.round, round);
        }
        // first see if we have already created a PoST block
        if self.post_blocks.contains_key(&self.authority) {
            tracing::debug!("PoST block already created");
        } else {
            let post_block = UncertifiedPoSTBlockData::new(round, last_block, last_seen_blocks, Vec::new());
            self.post_blocks.insert(self.authority, post_block);
        }
    }

    pub fn add_post_blocks(&mut self, post_block: UncertifiedPoSTBlockData) {
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
                if (self.mvba.count_ones() as u64) > self.committee.quorum_threshold() {
                    // note that we don't change the input of the MVBA protocol
                    tracing::info!("MVBA already reached quorum");
                    // return;
                } else {
                    self.mvba |= 1 << authority;
                    // tracing::info!("Number of 1s in mvba: {}", count);
                }
            }
        }
    }

    pub fn add_votes(&mut self, votes: Vec<PoSTBlockVote>) {
        for vote in votes {
            let authority = vote.meta_post_block.stuck_block.reference().authority;
            if self.post_blocks.contains_key(&authority) {
                tracing::error!("PoST block from authority {} already received", authority);
            }
            let mut post_block = UncertifiedPoSTBlockData::default(authority);
            post_block.stuck_round = vote.meta_post_block.stuck_round;
            post_block.stuck_block = vote.meta_post_block.stuck_block;
            post_block.seen_blocks = vote.meta_post_block.seen_blocks;
            post_block.signatures.push((vote.author, vote.signature));
            self.post_blocks.insert(authority, post_block);
            if (self.mvba.count_ones() as u64) > self.committee.quorum_threshold() {
                // note that we don't change the input of the MVBA protocol
                tracing::info!("MVBA already reached quorum");
                // return;
            } else {
                self.mvba |= 1 << authority;
                // tracing::info!("Number of 1s in mvba: {}", count);
            }
        }
    }

    pub fn read_my_post_block_after_round(
        &self,
        round: RoundNumber,
    ) -> Vec<UncertifiedPoSTBlockData> {
        let mut my_post_blocks = Vec::new();
        if let Some(my_post_block) =  self.post_blocks.get(&self.authority) {
            if my_post_block.stuck_round > round && my_post_block.signatures.len() > self.committee.quorum_threshold() as usize {
                my_post_blocks.push(my_post_block.clone());
            }
        }
        my_post_blocks
    }

    pub fn read_my_meta_post_block_after_round(
        &self,
        round: RoundNumber,
    ) -> Vec<MetaPoSTBlockData> {
        let mut my_meta_post_blocks = Vec::new();
        if let Some(my_post_block) =  self.post_blocks.get(&self.authority) {
            if my_post_block.stuck_round > round {
                my_meta_post_blocks.push(my_post_block.get_meta_post_block());
            }
        }
        my_meta_post_blocks
    }

    pub fn ready_for_mvba(&self, committee: &Committee) -> bool {
        (self.mvba.count_ones() as u64) > committee.quorum_threshold()
    }

    // this function just for test
    pub fn set_mvba(&mut self, mvba: MVBA) {
        self.mvba = mvba;
    }

    pub fn mvba(&self) -> MVBA {
        self.mvba
    }

    pub fn reset(&mut self) {
        self.post_blocks.clear();
        self.mvba = 0;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetaPoSTBlockData {
    pub stuck_round: RoundNumber,
    pub stuck_block: Data<StatementBlock>,
    pub seen_blocks: HashMap<AuthorityIndex, BlockReference>, // ordered by nodes' public keys
}

impl MetaPoSTBlockData {
    pub fn new(
        stuck_round: RoundNumber,
        stuck_block: Data<StatementBlock>,
        seen_blocks: HashMap<AuthorityIndex, BlockReference>,
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

    pub fn seen_blocks(&self) -> &HashMap<AuthorityIndex, BlockReference> {
        &self.seen_blocks
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoSTBlockVote {
    pub meta_post_block: MetaPoSTBlockData,
    pub author: PublicKey,
    pub signature: SignatureBytes,
}

impl PoSTBlockVote {
    pub async fn new(
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UncertifiedPoSTBlockData {
    pub stuck_round: RoundNumber,   // the round I am stuck at
    pub stuck_block: Data<StatementBlock>,  // the block I proposed at the stuck round
    pub seen_blocks: HashMap<AuthorityIndex, BlockReference>, // ordered by nodes' public keys
    pub signatures: Vec<(PublicKey, SignatureBytes)>,    // 2f+1 signatures
}

impl UncertifiedPoSTBlockData {
    pub fn default(authority: AuthorityIndex) -> Self {
        Self {
            stuck_round: 0,
            stuck_block: StatementBlock::new_genesis(authority),
            seen_blocks: HashMap::new(),
            signatures: Vec::new(),
        }
    }
    pub fn new(
        stuck_round: RoundNumber,
        stuck_block: Data<StatementBlock>,
        seen_blocks: HashMap<AuthorityIndex, BlockReference>,
        signatures: Vec<(PublicKey, SignatureBytes)>,
    ) -> Self {
        Self {
            stuck_round,
            stuck_block,
            seen_blocks,
            signatures,
        }
    }

    pub fn get_meta_post_block(&self) -> MetaPoSTBlockData {
        MetaPoSTBlockData::new(
            self.stuck_round,
            self.stuck_block.clone(),
            self.seen_blocks.clone(),
        )
    }

    pub fn verify(&self, _committee: &Committee) -> eyre::Result<()> {
        // todo: verify
        Ok(())
    }
}
