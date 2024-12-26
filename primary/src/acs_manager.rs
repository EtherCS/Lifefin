use crate::primary::Round;
use crypto::PublicKey;
use config::Committee;

pub struct ACSManager{
    name: PublicKey,
    committee: Committee,
    pub last_acs_round: Round,
    

}