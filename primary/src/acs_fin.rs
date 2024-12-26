// Copyright(C) Facebook, Inc. and its affiliates.
use crate::primary::{Round, PrimaryMessage};
use crate::messages::{BinaryValue, PisaAux, PisaBval, PisaDecision};
use config::Committee;
use std::collections::{HashMap};
use crypto::PublicKey;
use bytes::Bytes;
use network::{ReliableSender, CancelHandler};
use log::{debug, info};

pub struct AcsFin {
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

impl AcsFin {
    pub fn spawn (
        name: PublicKey,
    ) -> AcsFin {
        Self {
            name: name,
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

    pub fn create_bval_message (&self, est: BinaryValue, maj: BinaryValue) -> PisaBval {
        let bval_message = PisaBval::new(self.name, self.round, est, maj);
        debug!("Created BVAL message: {:?}", bval_message);

        bval_message
    }

    pub fn create_aux_message (&self, val1: BinaryValue, val2: BinaryValue) -> PisaAux {
        let aux_message = PisaAux::new(self.name, self.round, val1, val2);
        debug!("Created AUX message: {:?}", aux_message);

        aux_message
    }

    pub fn add_bin_value (&mut self, round: Round, bin_value: BinaryValue) {
        self.bin_values
            .entry(round)
            .or_insert_with(Vec::new)
            .push(bin_value);

        debug!("Added bin value {:?} for round {}", bin_value, round);
    }

    pub fn add_maj_value (&mut self, round: Round, maj_value: BinaryValue) {
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
        network: &mut ReliableSender
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
        network: &mut ReliableSender
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
        decide_value: BinaryValue
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
            }
            else if val == b {
                count += 1;
            }
        };

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
            },
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
        }
        else if let Some(count) = self.v2_check(vals_r.clone(), 0) {
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
            }
            else {
            // If the condition was satisfied because V1(vals_r) == 2
                for b in [0, 1] {
                    if let Some(count) = self.v2_check(avals_r.clone(), b) {
                        if count >= committee.majority_threshold() {
                            self.est_r = b;
                            self.maj_r = b;
                            return (b == actual_coin && b == last_coin, b);
                        }
                    }
                };
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
        network: &mut ReliableSender
    ) -> Vec<CancelHandler> {
        self.round += 1;
        self.bval_0_sent = false;
        self.bval_1_sent = false;
        self.aux_sent = false;
        self.aux_0_sent = false;
        self.aux_1_sent = false;

        debug!("Pisa moving to round {}", self.round);

        let bval_message = self.create_bval_message(self.est_r, self.maj_r);

        self.broadcast_bval_message(committee, bval_message, network).await
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

        if (b == (1 - last_coin) && v1_majs_is_b) ||
            (b == last_coin && majs_has_not_b) {
            delta_b = 1;
        }
        delta_b
    }
}
