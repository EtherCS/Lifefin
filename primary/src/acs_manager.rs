use crate::{
    acs_types::{ACSOutput, FINMVBAView},
    aggregators::{
        CertifiedMVBAVoteAggregator, CertifiedPoSTVoteAggregator, MVBAAggregator,
        MVBAProposalVoteAggregator, PoSTAggregator, PoSTVoteAggregator,
    },
    Header,
};
use std::collections::HashMap;

use crate::{
    acs_types::{ACSFin, MVBAProposal, MetaPoSTBlockData},
    primary::Round,
};
use config::Committee;
use crypto::{PublicKey, SignatureService};

// #[derive(Clone)]
pub struct ACSManager {
    committee: Committee,
    pub last_acs_round: Round, // the last round decided by ACS
    pub acs_output: ACSOutput, // the last acs output (used for verification and synchronization)
    pub acs_fin: ACSFin,
    /// The last seen PoST blocks from other primaries
    pub last_seen_post_blocks: HashMap<PublicKey, MetaPoSTBlockData>,
    /// The last seen MVBA proposals from other primaries
    pub last_seen_mvba_proposals: HashMap<PublicKey, MVBAProposal>,
    /// The current own post block (for which we are waiting votes).
    pub current_post_block: MetaPoSTBlockData,
    /// Aggregates post block votes into own certified post block.
    pub meta_post_vote_aggregator: PoSTVoteAggregator,
    /// Aggregates mvba proposal votes from other primaries.
    pub mvba_proposal_vote_aggregator: MVBAProposalVoteAggregator,
    /// store the votes from 2nd phase of RBC for PoST blocks
    pub post_vote_aggregators: HashMap<PublicKey, CertifiedPoSTVoteAggregator>,
    /// store the post blocks after RBC
    pub post_block_aggregator: PoSTAggregator,
    /// store the msgs from 2nd phase of RBC for MVBA proposals
    pub mvba_vote_aggregators: HashMap<PublicKey, CertifiedMVBAVoteAggregator>,
    /// store the MVBA proposals after RBC
    pub mvba_proposal_aggregator: MVBAAggregator,
    signature_service: SignatureService,
}

impl ACSManager {
    pub fn new(name: PublicKey, committee: Committee, signature_service: SignatureService) -> Self {
        ACSManager {
            committee: committee.clone(),
            last_acs_round: 0,
            acs_output: ACSOutput::default(),
            acs_fin: ACSFin::spawn(name, committee),
            last_seen_post_blocks: HashMap::new(),
            last_seen_mvba_proposals: HashMap::new(),
            current_post_block: MetaPoSTBlockData::default(),
            meta_post_vote_aggregator: PoSTVoteAggregator::new(),
            mvba_proposal_vote_aggregator: MVBAProposalVoteAggregator::new(),
            post_vote_aggregators: HashMap::new(),
            post_block_aggregator: PoSTAggregator::new(),
            mvba_vote_aggregators: HashMap::new(),
            mvba_proposal_aggregator: MVBAAggregator::new(),
            signature_service,
        }
    }

    pub async fn create_own_post_block(&mut self, header: Header) -> MetaPoSTBlockData {
        let new_post =
            MetaPoSTBlockData::new(self.last_acs_round, header, &mut self.signature_service).await;
        new_post
    }

    pub fn reset(&mut self, acs_round: Round) {
        self.last_acs_round = acs_round;
        self.acs_fin.reset();
        self.last_seen_post_blocks.clear();
        self.last_seen_mvba_proposals.clear();
        // self.current_post_block = MetaPoSTBlockData::default();
        self.meta_post_vote_aggregator.reset();
        self.mvba_proposal_vote_aggregator.reset();
        // self.post_vote_aggregators.clear();
        for (_, aggregator) in self.post_vote_aggregators.iter_mut() {
            aggregator.reset();
        }
        self.post_block_aggregator.reset();
        // self.mvba_vote_aggregators.clear();
        for (_, aggregator) in self.mvba_vote_aggregators.iter_mut() {
            aggregator.reset();
        }
        self.mvba_proposal_aggregator.reset();
    }

    pub fn decided_acs_output(&self, view: FINMVBAView) -> Option<ACSOutput> {
        let mut acs_vertices: Vec<MetaPoSTBlockData> = Vec::new();
        let k = self.acs_fin.election(view.clone()); // the authority index proposing the mvba
        if let Some(author) = self.committee.authority(k) {
            if let Some(decided_mvba) = self.mvba_proposal_aggregator.mvba_proposals(&author) {
                // get a vec containing all 1's indices in decided_mvba.proposal
                let decided_author_indices: Vec<usize> = (0..32)
                    .filter(|&i| (decided_mvba.proposal & (1 << i)) != 0)
                    .collect();
                for i in decided_author_indices {
                    if let Some(author) = self.committee.authority(i) {
                        if let Some(post_block) = self.post_block_aggregator.post_block(&author) {
                            acs_vertices.push(post_block.clone());
                        }
                    }
                }
                // get the highest round from the acs_vertices
                let highest_round = acs_vertices.iter().map(|v| v.round()).max().unwrap_or(0);
                let acs_output = ACSOutput::new(highest_round, acs_vertices);
                return Some(acs_output);
            }
        } else {
            // error
            panic!("Pisa protocol: Authority not found");
        }
        None
    }
}
