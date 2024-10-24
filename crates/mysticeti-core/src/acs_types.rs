// We implement FIN protocol here
// refer to: https://dl.acm.org/doi/pdf/10.1145/3576915.3616633

use crate::{
    committee::Committee,
    crypto::{MetaPoSTBlockDigest, MVBADigest, PublicKey, SignatureBytes, Signer},
    data::Data,
    types::{AuthorityIndex, BlockReference, RoundNumber, Stake, StatementBlock},
};
use eyre::{bail, Ok};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type MVBARoundNumber = u32;
pub type ABARoundNumber = u64;
pub type BinaryValue = u64; // b=0, b=1, b=2 (None)
pub type MVBA = u128;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetaPoSTBlockData {
    pub stuck_round: RoundNumber,
    pub stuck_block: Data<StatementBlock>,
    pub seen_blocks: BTreeMap<AuthorityIndex, BlockReference>, // ordered by nodes' public keys
}

impl MetaPoSTBlockData {
    pub fn new(
        stuck_round: RoundNumber,
        stuck_block: Data<StatementBlock>,
        seen_blocks: BTreeMap<AuthorityIndex, BlockReference>,
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

    pub fn seen_blocks(&self) -> &BTreeMap<AuthorityIndex, BlockReference> {
        &self.seen_blocks
    }

    pub fn digest(&self) -> MetaPoSTBlockDigest {
        let digest =
            MetaPoSTBlockDigest::new(self.stuck_round, &self.stuck_block, &self.seen_blocks);
        digest
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoSTBlockVote {
    pub meta_post_block: MetaPoSTBlockData,
    pub authority: AuthorityIndex,
    pub signature: SignatureBytes,
}

impl PoSTBlockVote {
    pub fn new(meta_post_block: MetaPoSTBlockData, authority: AuthorityIndex, signer: Signer) -> Self {
        let signature = signer.sign_post_block(
            meta_post_block.stuck_round,
            meta_post_block.stuck_block(),
            meta_post_block.seen_blocks(),
        );
        Self {
            meta_post_block,
            authority,
            signature,
        }
    }

    pub fn meta_post_block(&self) -> &MetaPoSTBlockData {
        &self.meta_post_block
    }

    pub fn signature(&self) -> &SignatureBytes {
        &self.signature
    }

    pub fn author(&self) -> AuthorityIndex {
        self.authority
    }

    pub fn vote_creator(&self) -> AuthorityIndex {
        self.meta_post_block.stuck_block().reference().authority
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let pub_key = committee.get_public_key(self.author());
        let Some(pub_key) = pub_key else {
            bail!("Unknown vote author {}", self.author())
        };
        if let Err(e) = pub_key.verify_post_block_vote(self) {
            bail!("Post block vote signature verification has failed: {:?}", e);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertifiedPoSTBlockData {
    pub stuck_round: RoundNumber,          // the round I am stuck at
    pub stuck_block: Data<StatementBlock>, // the block I proposed at the stuck round
    pub seen_blocks: BTreeMap<AuthorityIndex, BlockReference>, // ordered by nodes' public keys
    pub signatures: Vec<(PublicKey, SignatureBytes)>, // 2f+1 signatures
}

impl CertifiedPoSTBlockData {
    pub fn default(authority: AuthorityIndex) -> Self {
        Self {
            stuck_round: 0,
            stuck_block: StatementBlock::new_genesis(authority),
            seen_blocks: BTreeMap::new(),
            signatures: Vec::new(),
        }
    }

    pub fn new(
        stuck_round: RoundNumber,
        stuck_block: Data<StatementBlock>,
        seen_blocks: BTreeMap<AuthorityIndex, BlockReference>,
        signatures: Vec<(PublicKey, SignatureBytes)>,
    ) -> Self {
        Self {
            stuck_round,
            stuck_block,
            seen_blocks,
            signatures,
        }
    }

    pub fn new_with_my_signagure(
        stuck_round: RoundNumber,
        stuck_block: Data<StatementBlock>,
        seen_blocks: BTreeMap<AuthorityIndex, BlockReference>,
        signer: Signer,
    ) -> Self {
        let mut signatures = Vec::new();
        let signature = signer.sign_post_block(
            stuck_round,
            &stuck_block,
            &seen_blocks,
        );
        signatures.push((signer.public_key(), signature));
        Self {
            stuck_round,
            stuck_block,
            seen_blocks,
            signatures,
        }
    }

    pub fn update_signature(&mut self, author: PublicKey, signature: SignatureBytes) {
        if !self.signatures.iter().any(|(a, _)| a == &author) {
            self.signatures.push((author, signature));
        }
    }

    pub fn get_meta_post_block(&self) -> MetaPoSTBlockData {
        MetaPoSTBlockData::new(
            self.stuck_round,
            self.stuck_block.clone(),
            self.seen_blocks.clone(),
        )
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let meta_post_block = self.get_meta_post_block();
        if self.signatures.len() < committee.quorum_threshold() as usize {
            eyre::bail!(
                "Not enough signatures, only {} but quorum is {}",
                self.signatures.len(),
                committee.quorum_threshold()
            );
        }
        for (author, signature) in &self.signatures {
            if !committee.known_authority_key(author) {
                eyre::bail!("Unknown authority");
            }
            if author
                .verify_meta_post_block_with_signature(&meta_post_block, signature)
                .is_err()
            {
                eyre::bail!("Invalid signature");
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MVBAProposal {
    pub authority: AuthorityIndex,  // the creator of this proposal
    pub round: RoundNumber, // the last round agreed by the ACS mode
    pub proposal: MVBA,
}

impl MVBAProposal {
    pub fn new(authority: AuthorityIndex, round: RoundNumber, proposal: MVBA) -> Self {
        Self {
            authority,
            round,
            proposal,
        }
    }

    pub fn digest(&self) -> MVBADigest {
        MVBADigest::new(self.authority, self.round, self.proposal)
    }

    pub fn author(&self) -> AuthorityIndex {
        self.authority
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MVBAVote {
    pub mvba_proposal: MVBAProposal,
    pub voter: AuthorityIndex,  // the signer of this MVBAProposal
    pub signature: SignatureBytes, // my signature on this mvba proposal
}

impl MVBAVote {
    pub fn new_with_signer(
        mvba_proposal: MVBAProposal,
        voter: AuthorityIndex,
        signer: Signer,
    ) -> Self {
        let signature = signer.sign_mvba_proposal(mvba_proposal.authority, mvba_proposal.round, mvba_proposal.proposal);
        Self {
            mvba_proposal,
            voter,
            signature,
        }
    }

    pub fn mvba_creator(&self) -> AuthorityIndex {
        self.mvba_proposal.authority
    }

    pub fn mvba_voter(&self) -> AuthorityIndex {
        self.voter
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let pub_key = committee.get_public_key(self.mvba_voter());
        let Some(pub_key) = pub_key else {
            bail!("Unknown pisa aba bval author {}", self.mvba_voter())
        };
        if let Err(e) = pub_key.verify_mvba_vote(self) {
            bail!("pisa aba bval signature verification has failed: {:?}", e);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertifiedMVBA {
    pub authority: AuthorityIndex,
    pub round: RoundNumber, // the last round agreed by the ACS mode
    pub proposal: MVBA,     // the proposal value
    pub signatures: Vec<(PublicKey, SignatureBytes)>, // 2f+1 signatures
}

impl CertifiedMVBA {
    pub fn new(authority: AuthorityIndex, round: RoundNumber, proposal: MVBA) -> Self {
        Self {
            authority,
            round,
            proposal,
            signatures: Vec::new(),
        }
    }

    pub fn update_signature(&mut self, author: PublicKey, signature: SignatureBytes) {
        if !self.signatures.iter().any(|(a, _)| a == &author) {
            self.signatures.push((author, signature));
        }
    }

    pub fn is_certified(&self, acs_quorum: Stake) -> bool {
        self.signatures.len() >= acs_quorum as usize
    }

    pub fn get_mvba_proposal(&self) -> MVBAProposal {
        MVBAProposal::new(self.authority, self.round, self.proposal)
    }
    
    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        if self.signatures.len() < committee.quorum_threshold() as usize {
            eyre::bail!("Not enough signatures");
        }
        for (author, signature) in &self.signatures {
            if !committee.known_authority_key(author) {
                eyre::bail!("Unknown authority");
            }
            if author
                .verify_certified_mvba_with_signature(self, signature)
                .is_err()
            {
                eyre::bail!("Invalid signature");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FINMVBAView {
    mvba_round: MVBARoundNumber, // the (FIN) mvba round number
    aba_round: ABARoundNumber,   // the (Pisa) aba round number
}

impl FINMVBAView {
    pub fn new() -> Self {
        Self {
            mvba_round: 0,
            aba_round: 0,
        }
    }
}
pub struct PisaABABval {
    pub aba_round: ABARoundNumber, // the aba round number
    pub est: BinaryValue,
    pub maj: BinaryValue,
    pub authority: AuthorityIndex,
    pub signature: SignatureBytes,
}

impl PisaABABval {
    pub fn new(
        aba_round: ABARoundNumber,
        est: BinaryValue,
        maj: BinaryValue,
        authority: AuthorityIndex,
        signer: Signer,
    ) -> Self {
        let signature = signer.sign_pisa_aba_bval(aba_round, est, maj, authority);
        Self {
            aba_round,
            est,
            maj,
            authority,
            signature,
        }
    }

    pub fn author(&self) -> AuthorityIndex {
        self.authority
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let pub_key = committee.get_public_key(self.author());
        let Some(pub_key) = pub_key else {
            bail!("Unknown pisa aba bval author {}", self.author())
        };
        if let Err(e) = pub_key.verify_pisa_aba_bval(self) {
            bail!("pisa aba bval signature verification has failed: {:?}", e);
        }
        Ok(())
    }
}

pub struct PisaABAAux {
    pub aba_round: ABARoundNumber, // the aba round number
    pub aux1: BinaryValue,
    pub aux2: BinaryValue,
    pub authority: AuthorityIndex,
    pub signature: SignatureBytes,
}

impl PisaABAAux {
    pub fn new(
        aba_round: ABARoundNumber,
        aux1: BinaryValue,
        aux2: BinaryValue,
        authority: AuthorityIndex,
        signer: Signer,
    ) -> Self {
        let signature = signer.sign_pisa_aba_aux(aba_round, aux1, aux2, authority);
        Self {
            aba_round,
            aux1,
            aux2,
            authority,
            signature,
        }
    }

    pub fn author(&self) -> AuthorityIndex {
        self.authority
    }

    pub fn verify(&self, committee: &Committee) -> eyre::Result<()> {
        let pub_key = committee.get_public_key(self.author());
        let Some(pub_key) = pub_key else {
            bail!("Unknown pisa aba aux author {}", self.author())
        };
        if let Err(e) = pub_key.verify_pisa_aba_aux(self) {
            bail!("pisa aba aux signature verification has failed: {:?}", e);
        }
        Ok(())
    }
}
pub struct ACSFin {
    pub authority: AuthorityIndex,
    pub committee: Committee,
    pub last_acs_round: RoundNumber, // the last round agreed by the ACS mode
    pub mvbas: BTreeMap<AuthorityIndex, CertifiedMVBA>, // MVBA proposals received from all nodes
    /* the following data is for MVBA */
    pub mvba_view: FINMVBAView, // the current MVBA view
    pub raba_bvals: BTreeMap<FINMVBAView, BTreeMap<AuthorityIndex, PisaABABval>>, // record the binary value proposed by each node in each MVBA round/ABA round
    pub raba_aux: BTreeMap<FINMVBAView, BTreeMap<AuthorityIndex, PisaABAAux>>, // record the auxiliary information proposed by each node in each MVBA round/ABA round
}

impl ACSFin {
    pub fn new(
        authority: AuthorityIndex,
        committee: Committee,
        last_acs_round: RoundNumber,
    ) -> Self {
        let mut mvbas = BTreeMap::new();
        let my_reliable_mvba = CertifiedMVBA::new(authority, last_acs_round, 0);
        mvbas.insert(authority, my_reliable_mvba);
        Self {
            authority,
            committee,
            last_acs_round,
            mvbas,
            mvba_view: FINMVBAView::new(),
            raba_bvals: BTreeMap::new(),
            raba_aux: BTreeMap::new(),
        }
    }

    pub fn get_own_mvba(&self) -> &CertifiedMVBA {
        self.mvbas.get(&self.authority).unwrap()
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

    /// todo: random
    /// Current election: round robin
    pub fn election(&self) -> AuthorityIndex {
        self.mvba_view.mvba_round as AuthorityIndex % self.committee.len() as AuthorityIndex
    }

    /// todo: random
    /// Current election: coin flip
    pub fn coin(&self) -> BinaryValue {
        // todo
        self.mvba_view.aba_round as BinaryValue % 2
    }
}
