use crate::aggregators::{MVBAAggregator, MVBAVoteAggregator, PoSTAggregator, PoSTVoteAggregator};
use std::collections::HashMap;

use crate::{
    acs_types::{ACSFin, MetaPoSTBlockData},
    primary::Round,
};
use config::Committee;
use crypto::PublicKey;

pub type AuthorIndex = usize;

// #[derive(Clone)]
pub struct ACSManager {
    name: PublicKey,
    committee: Committee,
    pub last_acs_round: Round, // the last round decided by ACS
    pub acs_fin: ACSFin,
    pub post_vote_aggregators: HashMap<AuthorIndex, PoSTVoteAggregator>, // store the votes from 2nd phase of RBC for PoST blocks
    pub post_block_aggregator: PoSTAggregator, // store the post blocks after RBC
    pub mvba_vote_aggregators: HashMap<PublicKey, MVBAVoteAggregator>, // store the msgs from 2nd phase of RBC for MVBA proposals
    pub mvba_proposal_aggregator: MVBAAggregator, // store the MVBA proposals after RBC
}

impl ACSManager {
    pub fn new(name: PublicKey, committee: Committee) -> Self {
        ACSManager {
            name,
            committee,
            last_acs_round: 0,
            acs_fin: ACSFin::spawn(name),
            post_vote_aggregators: HashMap::new(),
            post_block_aggregator: PoSTAggregator::new(),
            mvba_vote_aggregators: HashMap::new(),
            mvba_proposal_aggregator: MVBAAggregator::new(),
        }
    }
}
