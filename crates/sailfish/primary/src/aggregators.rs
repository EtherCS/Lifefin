// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Timeout, TimeoutCert, Vote, NoVoteMsg, NoVoteCert, PisaBval, PisaAux, PisaDecision, BinaryValue};
use config::{Committee, Stake};
use crypto::{PublicKey, Signature};
use std::collections::HashSet;

/// Aggregates votes for a particular header into a certificate.
pub struct VotesAggregator {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl VotesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        vote: Vote,
        committee: &Committee,
        header: &Header,
    ) -> DagResult<Option<Certificate>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.votes.push((author, vote.signature));
        self.weight += committee.stake(&author);

        //to check if we have received vote from the current round leader
        // let leader = committee.leader(vote.round as usize);
        // if !self.used.contains(&leader){
        //     return Ok(None);
        // }

        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(Certificate {
                header: header.clone(),
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}

/// Aggregate certificates and check if we reach a quorum.
pub struct CertificatesAggregator {
    weight: Stake,
    certificates: Vec<Certificate>,
    used: HashSet<PublicKey>,
}

impl CertificatesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            certificates: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        certificate: Certificate,
        committee: &Committee,
    ) -> DagResult<Option<Vec<Certificate>>> {
        let origin = certificate.origin();

        // Ensure it is the first time this authority votes.
        if !self.used.insert(origin) {
            return Ok(None);
        }

        self.certificates.push(certificate);
        self.weight += committee.stake(&origin);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(self.certificates.drain(..).collect()));
        }
        Ok(None)
    }
}

/// Aggregates timeouts for a particular round into an action or trigger.
pub struct TimeoutAggregator {
    weight: Stake,
    timeouts: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl TimeoutAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            timeouts: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        timeout: Timeout,
        committee: &Committee,
    ) -> DagResult<Option<TimeoutCert>> {
        let author = timeout.author;

        // Ensure it is the first time this authority sends a timeout.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.timeouts.push((author, timeout.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            // Once quorum is reached, you might want to reset for the next round or trigger an action.
            return Ok(Some(TimeoutCert {
                round: timeout.round.clone(),
                timeouts: self.timeouts.clone(),
            })); // Return the authorities that contributed to this quorum.
        }
        Ok(None)
    }
}

/// Aggregates no-vote messages for a particular round into a certification.
pub struct NoVoteAggregator {
    weight: Stake,
    no_votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl NoVoteAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            no_votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        no_vote_msg: NoVoteMsg,
        committee: &Committee,
    ) -> DagResult<Option<NoVoteCert>> {
        let author = no_vote_msg.author;

        // Ensure it is the first time this authority sends a no-vote message.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.no_votes.push((author, no_vote_msg.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            // Once quorum is reached, you might reset for the next round or use the certification as needed.
            return Ok(Some(NoVoteCert {
                round: no_vote_msg.round.clone(),
                no_votes: self.no_votes.clone(),
            })); // Return the certification that aggregates the no-votes reaching quorum.
        }
        Ok(None)
    }
}

/// Aggregates PisaBval messages for a particular round into a certification.
pub struct PisaBvalAggregator {
    weight0: Stake,
    weight1: Stake,
    pisa_bvals: Vec<PisaBval>,
    used0: HashSet<PublicKey>,
    used1: HashSet<PublicKey>,
}

impl PisaBvalAggregator {
    pub fn new() -> Self {
        Self {
            weight0: 0,
            weight1: 0,
            pisa_bvals: Vec::new(),
            used0: HashSet::new(),
            used1: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        committee: &Committee,
        pisa_bval: PisaBval
    ) -> bool {
        let author = pisa_bval.author;

        match pisa_bval.est {
            0 => {
                // Ensure it is the first time this authority sends a PisaBval message.
                if !self.used0.insert(author) {
                    return false;
                }

                self.pisa_bvals.push(pisa_bval);
                self.weight0 += committee.stake(&author);

                self.weight0 >= committee.validity_threshold()
            }
            1 => {
                // Ensure it is the first time this authority sends a PisaBval message.
                if !self.used1.insert(author) {
                    return false;
                }

                self.pisa_bvals.push(pisa_bval);
                self.weight1 += committee.stake(&author);

                self.weight1 >= committee.validity_threshold()
            }
            _ => return false,
        }
    }

    pub fn enough_bvals_for_quorum(&self, committee: &Committee, b: BinaryValue) -> bool {
        match b {
            0 => self.weight0 >= committee.quorum_threshold(),
            1 => self.weight1 >= committee.quorum_threshold(),
            _ => false,
        }
    }
}


/// Aggregates PisaAux messages for a particular round into a certification.
pub struct PisaAuxAggregator {
    weight: Stake,
    pisa_auxs: Vec<PisaAux>,
    used: HashSet<PublicKey>,
}

impl PisaAuxAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            pisa_auxs: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        committee: &Committee,
        pisa_aux: PisaAux
    ) -> bool {
        let author = pisa_aux.author;

        // Ensure it is the first time this authority sends a PisaAux message.
        if !self.used.insert(author) {
            return false;
        }

        self.pisa_auxs.push(pisa_aux);
        self.weight += committee.stake(&author);

        self.weight >= committee.quorum_threshold()
    }

    pub fn get_vals_round(&self) -> Vec<BinaryValue> {
        let mut vals_round = Vec::new();
        for pisa_aux in &self.pisa_auxs {
            vals_round.push(pisa_aux.val1);
        }
        vals_round
    }

    pub fn get_avals_round(&self) -> Vec<BinaryValue> {
        let mut avals_round = Vec::new();
        for pisa_aux in &self.pisa_auxs {
            avals_round.push(pisa_aux.val2);
        }
        avals_round
    }
}

/// Aggregates PisaDesicion message for a particular round into a certification.
pub struct PisaDesicionAggregator {
    weight0: Stake,
    weight1: Stake,
    pisa_decision0: Vec<PisaDecision>,
    pisa_decision1: Vec<PisaDecision>,
    used0: HashSet<PublicKey>,
    used1: HashSet<PublicKey>,
}

impl PisaDesicionAggregator {
    pub fn new() -> Self {
        Self {
            weight0: 0,
            weight1: 0,
            pisa_decision0: Vec::new(),
            pisa_decision1: Vec::new(),
            used0: HashSet::new(),
            used1: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        committee: &Committee,
        pisa_decision: PisaDecision
    ) -> bool {
        let author = pisa_decision.author;

        match pisa_decision.val {
            0 => {
                // Ensure it is the first time this authority sends a PisaDecision message.
                if !self.used0.insert(author) {
                    return false;
                }

                self.pisa_decision0.push(pisa_decision);
                self.weight0 += committee.stake(&author);

                self.weight0 >= committee.quorum_threshold()
            },
            1 => {
                // Ensure it is the first time this authority sends a PisaDecision message.
                if !self.used1.insert(author) {
                    return false;
                }

                self.pisa_decision1.push(pisa_decision);
                self.weight1 += committee.stake(&author);

                self.weight1 >= committee.quorum_threshold()
            },
            _ => return false,
        }
    }
}
