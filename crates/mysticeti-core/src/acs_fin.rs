// We implement FIN protocol here
// refer to: https://dl.acm.org/doi/pdf/10.1145/3576915.3616633

use crate::{
    acs_manager::ReliableMVBA,
    committee::Committee,
    types::{AuthorityIndex, RoundNumber},
};

use std::collections::HashMap;

pub type View = u32;

pub struct ACSFin {
    authority: AuthorityIndex,
    committee: Committee,
    view: View,                                   // equal to round number in the paper
    round: RoundNumber,                           // the last round agreed by the ACS mode
    mvbas: HashMap<AuthorityIndex, ReliableMVBA>, // MVBA proposals received from all nodes
}

impl ACSFin {
    pub fn new(authority: AuthorityIndex, committee: Committee) -> Self {
        Self {
            authority,
            committee,
            view: 0,
            round: 0,
            mvbas: HashMap::new(),
        }
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

    /// Current election: round robin
    pub fn election(&self) -> AuthorityIndex {
        self.view as AuthorityIndex % self.committee.len() as AuthorityIndex
    }
}
