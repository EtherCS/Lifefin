use crate::{
    committee::Committee,
    crypto::{PublicKey, SignatureBytes, Signer},
    data::Data,
    types::{AuthorityIndex, BlockReference, RoundNumber, StatementBlock},
};
use ed25519_consensus::Signature;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;

pub type MVBA = u128;

pub struct ACSManager {
    round: RoundNumber,
    post_blocks: HashMap<AuthorityIndex, UncertifiedPoSTBlockData>,
    mvba: MVBA, // the MVBA proposal of the node
}

impl ACSManager {
    pub fn new(round: RoundNumber) -> Self {
        Self {
            round,
            post_blocks: HashMap::new(),
            mvba: 0,
        }
    }

    pub fn add_post_blocks(&mut self, post_block: UncertifiedPoSTBlockData, committee: &Committee) {
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
                if (self.mvba.count_ones() as u64) > committee.quorum_threshold() {
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
    pub async fn new(meta_post_block: MetaPoSTBlockData, author: PublicKey, signer: Signer) -> Self {
        let signature= signer.sign_post_block(meta_post_block.stuck_round, meta_post_block.stuck_block(), meta_post_block.seen_blocks());
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
    pub stuck_round: RoundNumber,
    pub stuck_block: Data<StatementBlock>,
    pub seen_blocks: HashMap<AuthorityIndex, BlockReference>, // ordered by nodes' public keys
    pub signatures: Vec<(PublicKey, Signature)>,
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
        signatures: Vec<(PublicKey, Signature)>,
    ) -> Self {
        Self {
            stuck_round,
            stuck_block,
            seen_blocks,
            signatures,
        }
    }

    pub fn get_meta_post_block(&self) -> MetaPoSTBlockData {
        MetaPoSTBlockData::new(self.stuck_round, self.stuck_block.clone(), self.seen_blocks.clone())
    }

    pub fn get_stuck_round(&self) -> RoundNumber {
        self.stuck_round
    }

    pub fn get_stuck_block(&self) -> &Data<StatementBlock> {
        &self.stuck_block
    }

    pub fn get_seen_blocks(&self) -> &HashMap<AuthorityIndex, BlockReference> {
        &self.seen_blocks
    }

    pub fn get_signatures(&self) -> &Vec<(PublicKey, Signature)> {
        &self.signatures
    }

    pub fn verify(&self, _committee: &Committee) -> eyre::Result<()> {
        // todo: verify
        Ok(())
    }
}
