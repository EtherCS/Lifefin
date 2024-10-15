// under Optimistic mode, node performs as usual
// under Fallback mode, node performs ACS mechanism

use eyre;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConsensusMode {
    Optimistic = 0,
    Fallback = 1,
}

// C: committee type
// P: public key of a node
// R: round number
// B: block
// S: signature
pub trait PoSTBlock<C, P, R, B, S> {
    fn get_stuck_round(&self) -> &R;
    fn get_stuck_block(&self) -> &B;
    fn get_seen_blocks(&self) -> &Vec<B>;
    fn get_signatures(&self) -> &Vec<(P, S)>;
    fn verify(&self, c: &C) -> eyre::Result<()>;
}


