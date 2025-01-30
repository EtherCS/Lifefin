use crate::acs_manager::ACSManager;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::acs_types::{
    ACSOutput, CertifiedMVBA, CertifiedMVBAVote, CertifiedPoSTBlockData, CertifiedPoSTBlockVote,
    FINMVBAView, MVBAProposal, MVBAVote, MetaPoSTBlockData, PoSTBlockVote,
};
use crate::aggregators::{
    CertificatesAggregator, CertifiedMVBAVoteAggregator, CertifiedPoSTVoteAggregator,
    NoVoteAggregator, PisaAuxAggregator, PisaBvalAggregator, PisaDesicionAggregator,
    TimeoutAggregator, VotesAggregator,
};
use crate::error::{DagError, DagResult};
use crate::messages::{
    BinaryValue, Certificate, Header, NoVoteCert, NoVoteMsg, PisaAux, PisaBval, PisaDecision,
    Timeout, TimeoutCert, Vote,
};
use crate::primary::{PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::{Committee, ConsensusMode};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

// #[cfg(test)]
// #[path = "tests/core_tests.rs"]
// pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,
    /// Receiver for dag messages (headers, timeouts, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<Header>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Receives our newly created timeouts from the `Proposer`.
    rx_timeout: Receiver<Timeout>,
    /// Receives our newly created no vote msgs from the `Proposer`.
    rx_no_vote_msg: Receiver<NoVoteMsg>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send valid a quorum of certificates' ids to the `Proposer` (along with their round).
    tx_proposer: Sender<(Vec<Certificate>, Round)>,
    /// Send a valid TimeoutCertificate along with the round to the `Proposer`.
    tx_timeout_cert: Sender<(TimeoutCert, Round)>,
    /// Send a valid NoVoteCert along with the round to the `Proposer`.
    tx_no_vote_cert: Sender<(NoVoteCert, Round)>,
    /// Send a the header that has voted for the prev leader to the `Consensus` logic.
    tx_consensus_header: Sender<Header>,
    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// The set of headers we are currently processing.
    processing: HashMap<Round, HashSet<Digest>>,
    /// The last header we proposed (for which we are waiting votes).
    current_header: Header,
    /// Aggregates votes into a certificate.
    votes_aggregator: VotesAggregator,
    /// Aggregates certificates to use as parents for new headers.
    certificates_aggregators: HashMap<Round, Box<CertificatesAggregator>>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    /// Aggregates timeouts to use for sending timeout certificate.
    timeouts_aggregators: HashMap<Round, Box<TimeoutAggregator>>,
    /// Aggregates no vote messages to use for sending no vote certificates.
    no_vote_aggregators: HashMap<Round, Box<NoVoteAggregator>>,

    // ACS data
    /// The consensus mode the node is running in.
    consensus_mode: ConsensusMode,
    /// The ACSFin protocol manager.
    acs_manager: ACSManager,
    /// Buffer for optimistic messages received in fallback mode.
    optimistic_buffer: Vec<PrimaryMessage>,
    /// Aggregator of Bval messages
    pisa_bval_aggregators: HashMap<FINMVBAView, Box<PisaBvalAggregator>>,
    /// Aggregator of Aux messages
    pisa_aux_aggregators: HashMap<FINMVBAView, Box<PisaAuxAggregator>>,
    /// Aggregator of the desicion messages of other primaries
    pisa_descion_aggregators: HashMap<FINMVBAView, Box<PisaDesicionAggregator>>,
    /// The last seen headers from other primaries, used to verify the PoST blocks
    last_seen_headers: HashMap<PublicKey, Header>,
    /// (test only) The round for changing to fallback mode.
    fallback_round: Round,
    /// Send valid a quorum of post blocks to the `Proposer` (along with the decided acs round).
    tx_post_proposer: Sender<(Vec<MetaPoSTBlockData>, Vec<Certificate>, Round)>,
    /// Send ACS output to the consensus module for direct commit
    tx_acs_consensus: Sender<(ACSOutput, Certificate)>,
    /// Receive fallback messages from consensus module, long time not committed
    rx_fallback: Receiver<u64>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        synchronizer: Synchronizer,
        signature_service: SignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<Header>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        rx_timeout: Receiver<Timeout>,
        rx_no_vote_msg: Receiver<NoVoteMsg>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<(Vec<Certificate>, Round)>,
        tx_timeout_cert: Sender<(TimeoutCert, Round)>,
        tx_no_vote_cert: Sender<(NoVoteCert, Round)>,
        tx_consensus_header: Sender<Header>,
        fallback_round: Round,
        tx_post_proposer: Sender<(Vec<MetaPoSTBlockData>, Vec<Certificate>, Round)>,
        tx_acs_consensus: Sender<(ACSOutput, Certificate)>,
        rx_fallback: Receiver<u64>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee: committee.clone(),
                store,
                synchronizer,
                signature_service: signature_service.clone(),
                gc_depth,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                rx_timeout,
                rx_no_vote_msg,
                tx_consensus,
                tx_proposer,
                tx_timeout_cert,
                tx_no_vote_cert,
                tx_consensus_header,
                gc_round: 0,
                fallback_round,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                processing: HashMap::with_capacity(2 * gc_depth as usize),
                current_header: Header::default(),
                votes_aggregator: VotesAggregator::new(),
                certificates_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                no_vote_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                consensus_mode: ConsensusMode::Optimistic,
                acs_manager: ACSManager::new(name, committee.clone(), signature_service.clone()),
                optimistic_buffer: Vec::new(),
                pisa_bval_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                pisa_aux_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                pisa_descion_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                last_seen_headers: HashMap::new(),
                consensus_round,
                tx_post_proposer,
                tx_acs_consensus,
                rx_fallback,
            }
            .run()
            .await;
        });
    }

    async fn process_own_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        // Serialize the Timeout instance into bytes using bincode or a similar serialization tool.
        let bytes = bincode::serialize(&PrimaryMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize own timeout");

        // Broadcast the serialized Timeout to all other primaries.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();

        // Send the Timeout to each address.
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

        self.cancel_handlers
            .entry(timeout.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Log the broadcast for debugging purposes.
        debug!("Broadcasted own timeout for round {}", timeout.round);

        self.process_timeout(timeout).await
    }

    async fn process_own_no_vote_msg(&mut self, no_vote_msg: NoVoteMsg) -> DagResult<()> {
        // Serialize the No Vote Msg instance into bytes using bincode or a similar serialization tool.
        let bytes = bincode::serialize(&PrimaryMessage::NoVoteMsg(no_vote_msg.clone()))
            .expect("Failed to serialize own no vote message");

        // Send No Vote Msg to the leader of the round
        let leader_pub_key = self.committee.leader((no_vote_msg.round + 1) as usize);

        let address = self
            .committee
            .primary(&leader_pub_key)
            .expect("public key not found")
            .primary_to_primary;
        // Send the No Vote Msg to each address.
        let handler = self.network.send(address, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(no_vote_msg.round)
            .or_insert_with(Vec::new)
            .push(handler);

        // Log the broadcast for debugging purposes.
        debug!(
            "Broadcasted own no vote message for round {}",
            no_vote_msg.round
        );

        Ok(())
    }

    async fn process_own_header(&mut self, header: Header) -> DagResult<()> {
        // Reset the votes aggregator.
        self.current_header = header.clone();
        self.votes_aggregator = VotesAggregator::new();

        // Broadcast the new header in a reliable manner.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessage::Header(header.clone()))
            .expect("Failed to serialize our own header");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(header.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Process the header.
        self.process_header(&header).await
    }

    #[async_recursion]
    async fn process_header(&mut self, header: &Header) -> DagResult<()> {
        //debug!("Processing {:?}", header);
        info!(
            "Processing header {} fo round {}",
            header.author, header.round
        );

        // Send header to consensus
        self.tx_consensus_header
            .send(header.clone())
            .await
            .expect("Failed to send header to consensus");
        // Indicate that we are processing this header.
        self.processing
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.id.clone());

        // todo: add more verification for headers with post blocks
        if header.post_blocks.len() == 0 {
            // Ensure we have the parents. If at least one parent is missing, the synchronizer returns an empty
            // vector; it will gather the missing parents (as well as all ancestors) from other nodes and then
            // reschedule processing of this header.
            let parents = self.synchronizer.get_parents(header).await?;
            if parents.is_empty() {
                debug!("Processing of {} suspended: missing parent(s)", header.id);
                return Ok(());
            }
            // Check the parent certificates. Ensure the parents form a quorum and are all from the previous round.
            let mut stake = 0;
            let mut has_leader = false;
            for x in parents {
                ensure!(
                    x.round() + 1 == header.round,
                    DagError::MalformedHeader(header.id.clone())
                );
                stake += self.committee.stake(&x.origin());

                has_leader = has_leader
                    || self
                        .committee
                        .leader((header.round - 1) as usize)
                        .eq(&x.header.author);
            }
            ensure!(
                stake >= self.committee.quorum_threshold(),
                DagError::HeaderRequiresQuorum(header.id.clone())
            );

            if !has_leader {
                header.timeout_cert.verify(&self.committee)?;
                if self
                    .committee
                    .leader(header.round as usize)
                    .eq(&header.author)
                {
                    header.no_vote_cert.verify(&self.committee)?;
                }
            }
        }

        // Ensure we have the payload. If we don't, the synchronizer will ask our workers to get it, and then
        // reschedule processing of this header once we have it.
        if self.synchronizer.missing_payload(header).await? {
            debug!("Processing of {} suspended: missing payload", header);
            return Ok(());
        }

        // Store the header.
        let bytes = bincode::serialize(header).expect("Failed to serialize header");
        self.store.write(header.id.to_vec(), bytes).await;

        // todo: add more verification for headers with post blocks
        // Check if we can vote for this header.
        if self
            .last_voted
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.author)
        {
            // Make a vote and send it to the header's creator.
            let vote = Vote::new(header, &self.name, &mut self.signature_service).await;
            debug!("Created {:?}", vote);
            if vote.origin == self.name {
                self.process_vote(vote)
                    .await
                    .expect("Failed to process our own vote");
            } else {
                let address = self
                    .committee
                    .primary(&header.author)
                    .expect("Author of valid header is not in the committee")
                    .primary_to_primary;
                let bytes = bincode::serialize(&PrimaryMessage::Vote(vote))
                    .expect("Failed to serialize our own vote");
                let handler = self.network.send(address, Bytes::from(bytes)).await;
                self.cancel_handlers
                    .entry(header.round)
                    .or_insert_with(Vec::new)
                    .push(handler);
                self.last_seen_headers.insert(header.author, header.clone());
            }
        }

        if header.round == self.fallback_round
            && self.consensus_mode == ConsensusMode::Optimistic
            && self.acs_manager.last_acs_round < header.round
        {
            // self.consensus_mode = ConsensusMode::Fallback;
            debug!(
                "Switched to fallback mode in view {}",
                self.acs_manager.last_acs_round
            );
            let _ = self.switch_to_fallback_mode().await;
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        debug!("Processing {:?}", timeout);

        // Check if we have enough timeout messages to create a timeout cert to propose next header.
        if let Some(timeout_cert) = self
            .timeouts_aggregators
            .entry(timeout.round)
            .or_insert_with(|| Box::new(TimeoutAggregator::new()))
            .append(timeout.clone(), &self.committee)?
        {
            debug!("Aggregated timeout cert {:?}", timeout);
            // Send it to the `Proposer`.
            self.tx_timeout_cert
                .send((timeout_cert, timeout.round))
                .await
                .expect("Failed to send timeout");
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_no_vote_msg(&mut self, no_vote_msg: NoVoteMsg) -> DagResult<()> {
        debug!("Processing {:?}", no_vote_msg);

        // Check if there's already an aggregator for this round, prepare to add if not
        if !self.no_vote_aggregators.contains_key(&no_vote_msg.round) {
            let initial_no_vote_msg = NoVoteMsg::new(
                no_vote_msg.round,
                self.name.clone(),
                &mut self.signature_service,
            )
            .await;

            let mut aggregator = NoVoteAggregator::new();
            // Add the initial message to the new aggregator
            aggregator.append(initial_no_vote_msg, &self.committee)?;

            // Insert the new aggregator into the map
            self.no_vote_aggregators
                .insert(no_vote_msg.round, Box::new(aggregator));
        }

        // Check if we have no vote messages to create a no vote cert to propose next header(as a leader).
        if let Some(no_vote_cert) = self
            .no_vote_aggregators
            .entry(no_vote_msg.round)
            .or_insert_with(|| Box::new(NoVoteAggregator::new()))
            .append(no_vote_msg.clone(), &self.committee)?
        {
            // Send it to the `Proposer`.
            debug!("Aggregated no vote cert {:?}", no_vote_msg);
            self.tx_no_vote_cert
                .send((no_vote_cert, no_vote_msg.round))
                .await
                .expect("Failed to send no vote message");
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_vote(&mut self, vote: Vote) -> DagResult<()> {
        debug!("Processing {:?}", vote);

        // Add it to the votes' aggregator and try to make a new certificate.
        if let Some(certificate) =
            self.votes_aggregator
                .append(vote, &self.committee, &self.current_header)?
        {
            debug!("Assembled {:?}", certificate);

            // Broadcast the certificate.
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate.clone()))
                .expect("Failed to serialize our own certificate");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(certificate.round())
                .or_insert_with(Vec::new)
                .extend(handlers);

            // Process the new certificate.
            self.process_certificate(certificate)
                .await
                .expect("Failed to process valid certificate");
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        // debug!("Processing {:?}", certificate);
        info!(
            "Processing certificate {} for round {}",
            certificate.origin(),
            certificate.round()
        );

        // Process the header embedded in the certificate if we haven't already voted for it (if we already
        // voted, it means we already processed it). Since this header got certified, we are sure that all
        // the data it refers to (ie. its payload and its parents) are available. We can thus continue the
        // processing of the certificate even if we don't have them in store right now.
        if !self
            .processing
            .get(&certificate.header.round)
            .map_or_else(|| false, |x| x.contains(&certificate.header.id))
        {
            // This function may still throw an error if the storage fails.
            self.process_header(&certificate.header).await?;
        }

        // Ensure we have all the ancestors of this certificate yet. If we don't, the synchronizer will gather
        // them and trigger re-processing of this certificate.
        if !self.synchronizer.deliver_certificate(&certificate).await? {
            debug!(
                "Processing of {:?} suspended: missing ancestors",
                certificate
            );
            return Ok(());
        }

        // Store the certificate.
        let bytes = bincode::serialize(&certificate).expect("Failed to serialize certificate");
        self.store.write(certificate.digest().to_vec(), bytes).await;

        // Check if we have enough certificates to enter a new dag round and propose a header.
        if let Some(parents) = self
            .certificates_aggregators
            .entry(certificate.round())
            .or_insert_with(|| Box::new(CertificatesAggregator::new()))
            .append(certificate.clone(), &self.committee)?
        {
            // Send it to the `Proposer`.
            self.tx_proposer
                .send((parents, certificate.round()))
                .await
                .expect("Failed to send certificate");
        }

        // Send it to the consensus layer.
        let id = certificate.header.id.clone();
        if let Err(e) = self.tx_consensus.send(certificate).await {
            warn!(
                "Failed to deliver certificate {} to the consensus: {}",
                id, e
            );
        }
        Ok(())
    }

    async fn switch_to_fallback_mode(&mut self) -> DagResult<()> {
        self.consensus_mode = ConsensusMode::Fallback;
        let my_own_post_block = self
            .acs_manager
            .create_own_post_block(self.current_header.clone())
            .await;
        self.acs_manager.current_post_block = my_own_post_block.clone();

        // PoST propose stage:
        // Serialize the meta post instance into bytes using bincode or a similar serialization tool.
        let bytes = bincode::serialize(&PrimaryMessage::MetaPoSTBlockData(
            my_own_post_block.clone(),
        ))
        .expect("Failed to serialize own meta post block");

        // Broadcast the serialized meta post to all other primaries.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();

        // Send the meta post to each address.
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

        self.cancel_handlers
            .entry(my_own_post_block.stuck_block.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Log the broadcast for debugging purposes.
        debug!(
            "Broadcasted own post block stuck in round {}",
            my_own_post_block.stuck_block.round
        );

        self.process_meta_post_block(my_own_post_block.clone())
            .await?;

        Ok(())
    }

    async fn process_meta_post_block(
        &mut self,
        meta_post_block: MetaPoSTBlockData,
    ) -> DagResult<()> {
        debug!("Processing meta post block {:?}", meta_post_block);
        let author = meta_post_block.stuck_block.author.clone();
        self.acs_manager
            .last_seen_post_blocks
            .insert(author, meta_post_block.clone());
        let post_block_vote =
            PoSTBlockVote::new(&meta_post_block, &self.name, &mut self.signature_service).await;
        if author == self.name {
            self.process_meta_post_block_vote(post_block_vote.clone())
                .await?;
        } else {
            let address = self
                .committee
                .primary(&author)
                .expect("Author of valid header is not in the committee")
                .primary_to_primary;
            let bytes = bincode::serialize(&PrimaryMessage::PoSTBlockVote(post_block_vote.clone()))
                .expect("Failed to serialize PoST block vote");
            let handler = self.network.send(address, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(meta_post_block.stuck_block.round)
                .or_insert_with(Vec::new)
                .push(handler);
        }
        Ok(())
    }

    async fn process_meta_post_block_vote(
        &mut self,
        post_block_vote: PoSTBlockVote,
    ) -> DagResult<()> {
        debug!("Processing PoST block vote {:?}", post_block_vote);
        if let Some(post_block) = self.acs_manager.meta_post_vote_aggregator.append(
            post_block_vote.clone(),
            &self.committee,
            &self.acs_manager.current_post_block,
        )? {
            // our post block is certified by 2f+1 nodes
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, info)| info.primary_to_primary)
                .collect();
            let bytes =
                bincode::serialize(&PrimaryMessage::CertifiedPoSTBlockData(post_block.clone()))
                    .expect("Failed to serialize PoST block");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(post_block.meta_post.stuck_block.round)
                .or_insert_with(Vec::new)
                .extend(handlers);
            // This is our post block, it must deliver via RBC
            self.process_post_block_after_rbc(post_block).await?;
        }
        Ok(())
    }

    async fn process_post_block_after_rbc(
        &mut self,
        post_block: CertifiedPoSTBlockData,
    ) -> DagResult<()> {
        debug!("Processing PoST block {:?}", post_block);
        if self
            .acs_manager
            .post_block_aggregator
            .contains(&post_block.meta_post.stuck_block.author)
        {
            // we have handle this post block before
            debug!("Post block already handled");
            return Ok(());
        } else {
            // notify other primaries about the new post block
            self.vote_certified_post_block(post_block.clone()).await;

            // now see if we have 2f+1 post blocks for mvba
            if let Some(meta_post_blocks) = self
                .acs_manager
                .post_block_aggregator
                .append(post_block.clone().meta_post, &self.committee)?
            {
                let handler_round = post_block.clone().meta_post.stuck_block.round;
                // create our mvba proposal
                let mvba_proposal = MVBAProposal::new(
                    self.name,
                    self.acs_manager.last_acs_round,
                    meta_post_blocks,
                    &self.committee,
                    &mut self.signature_service,
                )
                .await;
                // handle own proposal
                self.process_mvba_proposal(mvba_proposal.clone()).await?;
                let addresses = self
                    .committee
                    .others_primaries(&self.name)
                    .iter()
                    .map(|(_, info)| info.primary_to_primary)
                    .collect();
                let bytes =
                    bincode::serialize(&PrimaryMessage::MVBAProposal(mvba_proposal.clone()))
                        .expect("Failed to serialize PoST block");
                let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

                self.cancel_handlers
                    .entry(handler_round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);
            }
        }
        Ok(())
    }

    async fn vote_certified_post_block(&mut self, post_block: CertifiedPoSTBlockData) {
        let handler_round = post_block.clone().meta_post.stuck_block.round;
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();
        // notify other primaries about the new post block
        let certified_post_block_vote =
            CertifiedPoSTBlockVote::new(post_block.clone(), self.name, &mut self.signature_service)
                .await;
        let bytes = bincode::serialize(&PrimaryMessage::CertifiedPoSTBlockVote(
            certified_post_block_vote.clone(),
        ))
        .expect("Failed to serialize certified PoST block vote");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(handler_round)
            .or_insert_with(Vec::new)
            .extend(handlers);
    }

    async fn process_vote_phase_post_block(
        &mut self,
        certified_post_block_vote: CertifiedPoSTBlockVote,
    ) -> DagResult<()> {
        debug!(
            "Processing certified post block vote {:?}",
            certified_post_block_vote
        );
        let post_vote_aggregator = self
            .acs_manager
            .post_vote_aggregators
            .entry(
                certified_post_block_vote
                    .certified_post_block
                    .meta_post
                    .stuck_block
                    .author,
            )
            .or_insert_with(|| CertifiedPoSTVoteAggregator::new());
        if let Some(post_block) =
            post_vote_aggregator.append(certified_post_block_vote.clone(), &self.committee)?
        {
            self.process_post_block_after_rbc(post_block).await?;
        }
        Ok(())
    }

    async fn process_mvba_proposal(&mut self, mvba_proposal: MVBAProposal) -> DagResult<()> {
        debug!("Processing mvba proposal {:?}", mvba_proposal);
        let author = mvba_proposal.author.clone();
        self.acs_manager
            .last_seen_mvba_proposals
            .insert(author, mvba_proposal.clone());
        let mvba_proposal_vote = MVBAVote::new(
            mvba_proposal.clone(),
            self.name,
            &mut self.signature_service,
        )
        .await;
        if author == self.name {
            self.process_mvba_proposal_vote(mvba_proposal_vote.clone())
                .await?;
        } else {
            let address = self
                .committee
                .primary(&author)
                .expect("Author of valid header is not in the committee")
                .primary_to_primary;
            let bytes = bincode::serialize(&PrimaryMessage::MVBAVote(mvba_proposal_vote.clone()))
                .expect("Failed to serialize PoST block vote");
            let handler = self.network.send(address, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(mvba_proposal.acs_round)
                .or_insert_with(Vec::new)
                .push(handler);
        }
        Ok(())
    }

    async fn process_mvba_proposal_vote(&mut self, mvba_vote: MVBAVote) -> DagResult<()> {
        debug!("Processing mvba vote {:?}", mvba_vote.clone());
        if let Some(mvba) = self.acs_manager.mvba_proposal_vote_aggregator.append(
            mvba_vote.clone(),
            &self.committee,
            &mvba_vote.mvba_proposal,
        )? {
            // our mvba is certified by 2f+1 nodes
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, info)| info.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::CertifiedMVBA(mvba.clone()))
                .expect("Failed to serialize PoST block");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(mvba.proposal.acs_round)
                .or_insert_with(Vec::new)
                .extend(handlers);
            // This is our mvba, it must deliver via RBC
            self.process_mvba_after_rbc(mvba).await?;
        }
        Ok(())
    }

    async fn process_mvba_after_rbc(&mut self, mvba: CertifiedMVBA) -> DagResult<()> {
        debug!("Processing mvba {:?}", mvba);
        if self
            .acs_manager
            .mvba_proposal_aggregator
            .contains(&mvba.proposal.author)
        {
            // we have handle this mvba before
            debug!("MVBA already handled");
            return Ok(());
        } else {
            // notify other primaries about the new mvba
            self.vote_certified_mvba(mvba.clone()).await;

            // now see if we have 2f+1 mvba for acs
            if let Some(mvbas) = self
                .acs_manager
                .mvba_proposal_aggregator
                .append(mvba.clone().proposal, &self.committee)?
            {
                // todo: enter the pisa protocol
                debug!("Received MVBAs {:?}", mvbas);
                debug!(
                    "Received post blocks {:?}",
                    self.acs_manager.post_block_aggregator
                );
                debug!("Enter Pisa protocol");
                let k = self.acs_manager.acs_fin.current_election(); // get the authority index
                if let Some(authority) = self.committee.authority(k) {
                    if self
                        .acs_manager
                        .mvba_proposal_aggregator
                        .contains(&authority)
                    {
                        // raba-propose or raba-repropose 1
                        self.initialize_pisa_protocol(1).await;
                    } else {
                        // raba-propose 0
                        self.initialize_pisa_protocol(0).await;
                    }
                } else {
                    // error
                    panic!("Pisa protocol: Authority not found");
                }
            }
        }
        Ok(())
    }

    async fn vote_certified_mvba(&mut self, mvba: CertifiedMVBA) {
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();
        // notify other primaries about the new post block
        let certified_mvba_vote =
            CertifiedMVBAVote::new(mvba.clone(), self.name, &mut self.signature_service).await;
        let bytes = bincode::serialize(&PrimaryMessage::CertifiedMVBAVote(
            certified_mvba_vote.clone(),
        ))
        .expect("Failed to serialize certified mvba vote");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(mvba.proposal.acs_round)
            .or_insert_with(Vec::new)
            .extend(handlers);
    }

    async fn process_vote_phase_mvba(
        &mut self,
        certified_mvba_vote: CertifiedMVBAVote,
    ) -> DagResult<()> {
        debug!("Processing certified mvba vote {:?}", certified_mvba_vote);
        let mvba_vote_aggregator = self
            .acs_manager
            .mvba_vote_aggregators
            .entry(certified_mvba_vote.certified_mvba.proposal.author)
            .or_insert_with(|| CertifiedMVBAVoteAggregator::new());
        if let Some(mvba) =
            mvba_vote_aggregator.append(certified_mvba_vote.clone(), &self.committee)?
        {
            self.process_mvba_after_rbc(mvba).await?;
        }
        Ok(())
    }

    async fn initialize_pisa_protocol(&mut self, raba_proposed_value: BinaryValue) {
        let est_r = raba_proposed_value;
        self.acs_manager.acs_fin.propose(est_r);

        // To test if the protocol starts at round 1
        // let handlers = self
        //     .acs_manager.acs_fin
        //     .advance_round(&self.committee, &mut self.network)
        //     .await;
        //
        // self.cancel_handlers
        //     .entry(1)
        //     .or_insert_with(Vec::new)
        //     .extend(handlers);

        // Executes behaviour of Pisa protocol in round 0.
        let bval_message = self
            .acs_manager
            .acs_fin
            .create_bval_message(
                self.acs_manager.last_acs_round,
                self.acs_manager.acs_fin.est_r,
                2,
                &mut self.signature_service,
            )
            .await;
        // add own bval
        self.pisa_bval_aggregators
            .entry(bval_message.view.clone())
            .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
            .append(&self.committee, bval_message.clone());
        self.acs_manager.acs_fin.bval_1_sent = true;

        let handlers = self
            .acs_manager
            .acs_fin
            .broadcast_bval_message(&self.committee, bval_message.clone(), &mut self.network)
            .await;

        self.cancel_handlers
            .entry(bval_message.view.aba_round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        self.acs_manager
            .acs_fin
            .add_bin_value(bval_message.view, bval_message.est);

        // Broadcasting aux(1,1) if it hasn't been sent yet
        if !self.acs_manager.acs_fin.aux_sent {
            let aux_message = self
                .acs_manager
                .acs_fin
                .create_aux_message(
                    self.acs_manager.last_acs_round,
                    1,
                    1,
                    &mut self.signature_service,
                )
                .await;
            // add own aux
            self.pisa_aux_aggregators
                .entry(aux_message.view.clone())
                .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
                .append(&self.committee, aux_message.clone());
            let handlers = self
                .acs_manager
                .acs_fin
                .broadcast_aux_message(&self.committee, aux_message.clone(), &mut self.network)
                .await;

            self.cancel_handlers
                .entry(aux_message.view.mvba_round)
                .or_insert_with(Vec::new)
                .extend(handlers);

            self.acs_manager.acs_fin.aux_sent = true;
        }
    }

    async fn finalize_fallback(&mut self, acs_output: ACSOutput) {
        debug!(
            "Switched to optimistic mode in view {}",
            self.acs_manager.last_acs_round
        );
        // update the last acs round
        self.acs_manager.last_acs_round = acs_output.acs_round();

        // get the new leader SB_L
        let new_acs_leader = acs_output.new_leader_block(self.committee.clone());
        let mut new_acs_leader_certificate = Certificate::default();
        // using post blocks to create certificates
        let mut parents = Vec::new();

        // Store the post_blocks and certificates.
        for post_block in acs_output.vertices.iter() {
            let bytes = bincode::serialize(post_block).expect("Failed to serialize post block");
            self.store.write(post_block.digest().to_vec(), bytes).await;
            // need construct certificate for DAG verification
            let certificate = Certificate {
                header: post_block.stuck_block.clone(),
                votes: Vec::new(),
            };
            // record the new leader's certificate for directly commit
            if post_block.digest() == new_acs_leader.digest() {
                new_acs_leader_certificate = certificate.clone();
            }
            parents.push(certificate.clone());
            let c_bytes =
                bincode::serialize(&certificate).expect("Failed to serialize certificate");
            self.store
                .write(certificate.digest().to_vec(), c_bytes)
                .await;
            // Send it to the consensus layer.
            let id = certificate.header.id.clone();
            if let Err(e) = self.tx_consensus.send(certificate).await {
                warn!(
                    "Failed to deliver certificate {} to the consensus: {}",
                    id, e
                );
            }
        }

        // send output to consensus module for direct commit
        self.tx_acs_consensus
            .send((acs_output.clone(), new_acs_leader_certificate))
            .await
            .expect("Failed to send new acs leader");

        // todo: grace transition: acs_output.acs_round()+2
        // need to rewrite the verification of DAG
        self.tx_post_proposer
            .send((
                acs_output.vertices.clone(),
                parents,
                acs_output.acs_round() + 1,
            ))
            .await
            .expect("Failed to send post proposer");

        debug!(
            "Committing ACS output in new round {}",
            acs_output.acs_round
        );
        self.consensus_mode = ConsensusMode::Optimistic;

        self.acs_manager.reset(acs_output.acs_round());

        // help others to terminate the ACS
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessage::ACSOutput(acs_output.clone()))
            .expect("Failed to serialize ACS output");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(acs_output.acs_round())
            .or_insert_with(Vec::new)
            .extend(handlers);
    }

    async fn process_pisa_bval(&mut self, pisa_bval: PisaBval) -> DagResult<()> {
        info!("Processing pisa_bval_message{:?}", pisa_bval);

        // If acs is starting (round 0) we execute pisa protocol, else we execute pillar protocol.
        match pisa_bval.view.aba_round {
            0 => self.process_pisa_bval_start(pisa_bval).await?,
            _ => self.process_pillar_bval(pisa_bval).await?,
        }
        Ok(())
    }

    async fn process_pisa_bval_start(&mut self, pisa_bval: PisaBval) -> DagResult<()> {
        debug!("Executing pisa protocol with {:?}", pisa_bval);

        // If we have received f + 1 bval(b, *) messages we can proceed.
        if self
            .pisa_bval_aggregators
            .entry(pisa_bval.view.clone())
            .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
            .append(&self.committee, pisa_bval.clone())
        {
            info!("Received f + 1 bval({}, *) messages", pisa_bval.est);
            match pisa_bval.est {
                0 => {
                    // If bval(0, maj_r message has not been broadcast yet, we broadcast it.
                    if !self.acs_manager.acs_fin.bval_0_sent {
                        let bval_majr_message = self
                            .acs_manager
                            .acs_fin
                            .create_bval_message(
                                self.acs_manager.last_acs_round,
                                pisa_bval.est.clone(),
                                self.acs_manager.acs_fin.maj_r,
                                &mut self.signature_service,
                            )
                            .await;
                        // add own bval
                        self.pisa_bval_aggregators
                            .entry(bval_majr_message.view.clone())
                            .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                            .append(&self.committee, bval_majr_message.clone());
                        let handlers = self
                            .acs_manager
                            .acs_fin
                            .broadcast_bval_message(
                                &self.committee,
                                bval_majr_message.clone(),
                                &mut self.network,
                            )
                            .await;

                        self.cancel_handlers
                            .entry(bval_majr_message.view.mvba_round)
                            .or_insert_with(Vec::new)
                            .extend(handlers);

                        self.acs_manager.acs_fin.bval_0_sent = true;
                    }
                }
                1 => {
                    // If bval(1, maj_r message has not been broadcast yet, we broadcast it.
                    if !self.acs_manager.acs_fin.bval_1_sent {
                        let bval_majr_message = self
                            .acs_manager
                            .acs_fin
                            .create_bval_message(
                                self.acs_manager.last_acs_round,
                                pisa_bval.est.clone(),
                                self.acs_manager.acs_fin.maj_r,
                                &mut self.signature_service,
                            )
                            .await;
                        // add own bval
                        self.pisa_bval_aggregators
                            .entry(bval_majr_message.view.clone())
                            .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                            .append(&self.committee, bval_majr_message.clone());
                        let handlers = self
                            .acs_manager
                            .acs_fin
                            .broadcast_bval_message(
                                &self.committee,
                                bval_majr_message.clone(),
                                &mut self.network,
                            )
                            .await;

                        self.cancel_handlers
                            .entry(bval_majr_message.view.mvba_round)
                            .or_insert_with(Vec::new)
                            .extend(handlers);

                        self.acs_manager.acs_fin.bval_1_sent = true;
                    }

                    // We add b to bin values if it is 1 and broadcast aux(1, 1) if we haven't.
                    self.acs_manager
                        .acs_fin
                        .add_bin_value(pisa_bval.view.clone(), pisa_bval.est);
                    if !self.acs_manager.acs_fin.aux_sent {
                        let aux_message = self
                            .acs_manager
                            .acs_fin
                            .create_aux_message(
                                self.acs_manager.last_acs_round,
                                1,
                                1,
                                &mut self.signature_service,
                            )
                            .await;
                        // add own aux
                        self.pisa_aux_aggregators
                            .entry(aux_message.view.clone())
                            .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
                            .append(&self.committee, aux_message.clone());
                        let handlers = self
                            .acs_manager
                            .acs_fin
                            .broadcast_aux_message(
                                &self.committee,
                                aux_message.clone(),
                                &mut self.network,
                            )
                            .await;

                        self.cancel_handlers
                            .entry(aux_message.view.mvba_round)
                            .or_insert_with(Vec::new)
                            .extend(handlers);

                        self.acs_manager.acs_fin.aux_sent = true;
                    }
                }
                _ => (),
            }

            // If we have received 2f + 1 bval(b, *) messages we can proceed.
            if self
                .pisa_bval_aggregators
                .entry(pisa_bval.view.clone())
                .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                .enough_bvals_for_quorum(&self.committee, pisa_bval.est)
            {
                info!("Received 2f + 1 bval({}, *) messages", pisa_bval.est);
                self.acs_manager
                    .acs_fin
                    .add_bin_value(pisa_bval.view, pisa_bval.est);
                if self.acs_manager.acs_fin.aux_sent {
                    let aux_message = self
                        .acs_manager
                        .acs_fin
                        .create_aux_message(
                            self.acs_manager.last_acs_round,
                            pisa_bval.est,
                            pisa_bval.est,
                            &mut self.signature_service,
                        )
                        .await;
                    // add own aux
                    self.pisa_aux_aggregators
                        .entry(aux_message.view.clone())
                        .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
                        .append(&self.committee, aux_message.clone());
                    let handlers = self
                        .acs_manager
                        .acs_fin
                        .broadcast_aux_message(
                            &self.committee,
                            aux_message.clone(),
                            &mut self.network,
                        )
                        .await;

                    self.cancel_handlers
                        .entry(aux_message.view.mvba_round)
                        .or_insert_with(Vec::new)
                        .extend(handlers);
                    self.acs_manager.acs_fin.aux_sent = true;
                }
            }
        }
        Ok(())
    }

    async fn process_pillar_bval(&mut self, pillar_bval: PisaBval) -> DagResult<()> {
        debug!("Executing pillar protocol with {:?}", pillar_bval);
        self.acs_manager
            .acs_fin
            .add_maj_value(pillar_bval.view.clone(), pillar_bval.maj);
        let maj_r = self.acs_manager.acs_fin.maj_r;

        // If we have received f + 1 bval(b, *) messages we can proceed.
        if self
            .pisa_bval_aggregators
            .entry(pillar_bval.view.clone())
            .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
            .append(&self.committee, pillar_bval.clone())
        {
            info!("Received f + 1 bval({}, *) messages", pillar_bval.est);
            if let Some(message) = match pillar_bval.est {
                0 => {
                    if !self.acs_manager.acs_fin.bval_0_sent {
                        let bval_majr_message = self
                            .acs_manager
                            .acs_fin
                            .create_bval_message(
                                self.acs_manager.last_acs_round,
                                0,
                                maj_r,
                                &mut self.signature_service,
                            )
                            .await;
                        // add own bval
                        self.pisa_bval_aggregators
                            .entry(bval_majr_message.view.clone())
                            .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                            .append(&self.committee, bval_majr_message.clone());
                        self.acs_manager.acs_fin.bval_0_sent = true;
                        Some(bval_majr_message)
                    } else {
                        None
                    }
                }
                1 => {
                    if !self.acs_manager.acs_fin.bval_1_sent {
                        let bval_majr_message = self
                            .acs_manager
                            .acs_fin
                            .create_bval_message(
                                self.acs_manager.last_acs_round,
                                1,
                                maj_r,
                                &mut self.signature_service,
                            )
                            .await;
                        // add own bval
                        self.pisa_bval_aggregators
                            .entry(bval_majr_message.view.clone())
                            .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                            .append(&self.committee, bval_majr_message.clone());
                        self.acs_manager.acs_fin.bval_1_sent = true;
                        Some(bval_majr_message)
                    } else {
                        None
                    }
                }
                _ => None,
            } {
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .broadcast_bval_message(&self.committee, message.clone(), &mut self.network)
                    .await;

                self.cancel_handlers
                    .entry(message.view.mvba_round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);
            }

            // If we have received 2f + 1 bval(b, *) messages we can proceed.
            if self
                .pisa_bval_aggregators
                .entry(pillar_bval.view.clone())
                .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                .enough_bvals_for_quorum(&self.committee, pillar_bval.est)
            {
                info!("Received 2f + 1 bval({}, *) messages", pillar_bval.est);
                self.acs_manager
                    .acs_fin
                    .add_bin_value(pillar_bval.view.clone(), pillar_bval.est);

                let delta_b = self.acs_manager.acs_fin.delta_b(pillar_bval.est);

                // if aux(b, *) or aux(not b, *) has not been sent, we can proceed.
                if !self.acs_manager.acs_fin.aux_0_sent || self.acs_manager.acs_fin.aux_1_sent {
                    let message = match delta_b {
                        1 => {
                            self.acs_manager
                                .acs_fin
                                .create_aux_message(
                                    self.acs_manager.last_acs_round,
                                    pillar_bval.est,
                                    pillar_bval.est,
                                    &mut self.signature_service,
                                )
                                .await
                        }
                        _ => {
                            self.acs_manager
                                .acs_fin
                                .create_aux_message(
                                    self.acs_manager.last_acs_round,
                                    2,
                                    pillar_bval.est,
                                    &mut self.signature_service,
                                )
                                .await
                        }
                    };
                    // add own aux
                    self.pisa_aux_aggregators
                        .entry(message.view.clone())
                        .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
                        .append(&self.committee, message.clone());
                    let handlers = self
                        .acs_manager
                        .acs_fin
                        .broadcast_aux_message(&self.committee, message.clone(), &mut self.network)
                        .await;

                    self.cancel_handlers
                        .entry(pillar_bval.view.mvba_round)
                        .or_insert_with(Vec::new)
                        .extend(handlers);
                }
            }
        }

        Ok(())
    }

    async fn process_pisa_aux(&mut self, pisa_aux: PisaAux) -> DagResult<()> {
        debug!("Received pisa_aux_message{:?}", pisa_aux);

        match pisa_aux.view.aba_round {
            0 => self.process_pisa_aux_start(pisa_aux).await?,
            _ => self.process_pillar_aux(pisa_aux).await?,
        }
        Ok(())
    }

    async fn process_pisa_aux_start(&mut self, pisa_aux: PisaAux) -> DagResult<()> {
        info!("Processing pisa aux message {:?}", pisa_aux);

        // We are expecting n - f or 2f + 1 aux(*, *) messages.
        if self
            .pisa_aux_aggregators
            .entry(pisa_aux.view.clone())
            .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
            .append(&self.committee, pisa_aux.clone())
        {
            info!("Received n - f or 2f + 1 aux(*, *) messages");
            let vals_r = self
                .pisa_aux_aggregators
                .entry(pisa_aux.view.clone())
                .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
                .get_vals_round();

            let decide = self
                .acs_manager
                .acs_fin
                .try_decide_round_0(vals_r, &self.committee);

            // If we are able to decide (V2(vals_r, b) >= (n + f + 1)/2 and b = 1) we broadcast a decide message.
            if decide && !self.acs_manager.acs_fin.decided {
                // We broadcast the decide message if we haven't already and change to optimistic
                // mode.
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .decide(
                        self.acs_manager.last_acs_round,
                        &self.committee,
                        &mut self.network,
                        1,
                        &mut self.signature_service,
                    )
                    .await;
                self.cancel_handlers
                    .entry(pisa_aux.view.clone().mvba_round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);
                // In aba_round = 0, we only decide on 1, everything is done
                if let Some(acs_output) = self
                    .acs_manager
                    .decided_acs_output(self.acs_manager.acs_fin.mvba_view.clone())
                {
                    // todo: detect if we have missing post blocks
                    self.acs_manager.acs_output = acs_output.clone();
                    self.finalize_fallback(acs_output.clone()).await;
                } else {
                    debug!("ACS output not ready yet");
                    // enter next aba round and propose new bval message
                    let new_view = FINMVBAView::new_with_rounds(
                        self.acs_manager.acs_fin.mvba_view.mvba_round,
                        self.acs_manager.acs_fin.mvba_view.aba_round + 1,
                    );
                    self.acs_manager.acs_fin.advance_view(new_view);
                    let bval_message = self
                        .acs_manager
                        .acs_fin
                        .create_bval_message(
                            self.acs_manager.last_acs_round,
                            self.acs_manager.acs_fin.est_r,
                            self.acs_manager.acs_fin.maj_r,
                            &mut self.signature_service,
                        )
                        .await;
                    // add own bval
                    self.pisa_bval_aggregators
                        .entry(bval_message.view.clone())
                        .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                        .append(&self.committee, bval_message.clone());
                    let handlers = self
                        .acs_manager
                        .acs_fin
                        .broadcast_bval_message(&self.committee, bval_message, &mut self.network)
                        .await;
                    self.cancel_handlers
                        .entry(pisa_aux.view.mvba_round)
                        .or_insert_with(Vec::new)
                        .extend(handlers);
                }
                // self.switch_to_optimistic_mode().await;
            } else {
                // enter next aba round and propose new bval message
                let new_view = FINMVBAView::new_with_rounds(
                    self.acs_manager.acs_fin.mvba_view.mvba_round,
                    self.acs_manager.acs_fin.mvba_view.aba_round + 1,
                );
                self.acs_manager.acs_fin.advance_view(new_view);
                let bval_message = self
                    .acs_manager
                    .acs_fin
                    .create_bval_message(
                        self.acs_manager.last_acs_round,
                        self.acs_manager.acs_fin.est_r,
                        self.acs_manager.acs_fin.maj_r,
                        &mut self.signature_service,
                    )
                    .await;
                // add own bval
                self.pisa_bval_aggregators
                    .entry(bval_message.view.clone())
                    .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                    .append(&self.committee, bval_message.clone());
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .broadcast_bval_message(&self.committee, bval_message, &mut self.network)
                    .await;
                self.cancel_handlers
                    .entry(pisa_aux.view.mvba_round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);
            }
        }

        Ok(())
    }

    async fn process_pillar_aux(&mut self, pillar_aux: PisaAux) -> DagResult<()> {
        debug!("Processing pillar aux message {:?}", pillar_aux);

        // We are expecting n - f or 2f + 1 aux(*, *) messages.
        if self
            .pisa_aux_aggregators
            .entry(pillar_aux.view.clone())
            .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
            .append(&self.committee, pillar_aux.clone())
        {
            let vals_r = self
                .pisa_aux_aggregators
                .entry(pillar_aux.view.clone())
                .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
                .get_vals_round();

            let avals_r = self
                .pisa_aux_aggregators
                .entry(pillar_aux.view.clone())
                .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
                .get_avals_round();

            let (decide, b) = self
                .acs_manager
                .acs_fin
                .try_decide(vals_r, avals_r, &self.committee);

            if decide && !self.acs_manager.acs_fin.decided {
                // We broadcast the decide message if we haven't already and chancge to optimistic
                // todo: do different things based on the decided value b.
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .decide(
                        self.acs_manager.last_acs_round,
                        &self.committee,
                        &mut self.network,
                        b,
                        &mut self.signature_service,
                    )
                    .await;
                self.cancel_handlers
                    .entry(pillar_aux.view.clone().mvba_round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);
                if b == 1 {
                    // we decide on 1, everything is done
                    if let Some(acs_output) = self
                        .acs_manager
                        .decided_acs_output(self.acs_manager.acs_fin.mvba_view.clone())
                    {
                        // todo: detect if we have missing post blocks
                        self.acs_manager.acs_output = acs_output.clone();
                        self.finalize_fallback(acs_output.clone()).await;
                    } else {
                        debug!("ACS output not ready yet");
                    }
                    // self.switch_to_optimistic_mode().await;
                } else if b == 0 {
                    // we decide on 0, enter the next view
                    let new_view = FINMVBAView::new_with_rounds(
                        self.acs_manager.acs_fin.mvba_view.mvba_round + 1,
                        0,
                    );
                    self.acs_manager.acs_fin.advance_view(new_view);
                    let k = self.acs_manager.acs_fin.current_election(); // get the authority index
                    if let Some(authority) = self.committee.authority(k) {
                        if self
                            .acs_manager
                            .mvba_proposal_aggregator
                            .contains(&authority)
                        {
                            // raba-propose 1
                            self.initialize_pisa_protocol(1).await;
                        } else {
                            // raba-propose 0
                            self.initialize_pisa_protocol(0).await;
                        }
                    } else {
                        // error
                        panic!("Pisa protocol: Authority not found");
                    }
                }
            } else {
                // If we are not able to decide yet we continue to the next aba round and propose new bval message.
                let new_view = FINMVBAView::new_with_rounds(
                    self.acs_manager.acs_fin.mvba_view.mvba_round,
                    self.acs_manager.acs_fin.mvba_view.aba_round + 1,
                );
                self.acs_manager.acs_fin.advance_view(new_view);
                let bval_message = self
                    .acs_manager
                    .acs_fin
                    .create_bval_message(
                        self.acs_manager.last_acs_round,
                        self.acs_manager.acs_fin.est_r,
                        self.acs_manager.acs_fin.maj_r,
                        &mut self.signature_service,
                    )
                    .await;
                // add own bval
                self.pisa_bval_aggregators
                    .entry(bval_message.view.clone())
                    .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                    .append(&self.committee, bval_message.clone());
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .broadcast_bval_message(&self.committee, bval_message, &mut self.network)
                    .await;
                self.cancel_handlers
                    .entry(pillar_aux.view.clone().mvba_round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);
            }
        }
        Ok(())
    }

    async fn process_pisa_desicion(&mut self, desicion: PisaDecision) -> DagResult<()> {
        debug!("Processing pisa_decision_message {:?}", desicion);

        // If we have received 2f + 1 desicion messages we decide on that value.
        if self
            .pisa_descion_aggregators
            .entry(desicion.view.clone())
            .or_insert_with(|| Box::new(PisaDesicionAggregator::new()))
            .append(&self.committee, desicion.clone())
        {
            if !self.acs_manager.acs_fin.decided {
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .decide(
                        self.acs_manager.last_acs_round,
                        &self.committee,
                        &mut self.network,
                        desicion.val,
                        &mut self.signature_service,
                    )
                    .await;
                self.cancel_handlers
                    .entry(desicion.view.clone().mvba_round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);

                if let Some(acs_output) = self
                    .acs_manager
                    .decided_acs_output(self.acs_manager.acs_fin.mvba_view.clone())
                {
                    // todo: detect if we have missing post blocks
                    self.acs_manager.acs_output = acs_output.clone();
                    self.finalize_fallback(acs_output.clone()).await;
                } else {
                    debug!("ACS output not ready yet");
                }

                // self.switch_to_optimistic_mode().await;
            }
        }
        Ok(())
    }

    async fn process_acs_output(&mut self, acs_output: ACSOutput) -> DagResult<()> {
        debug!(
            "Terminate acs instance from others in view {}",
            acs_output.view
        );
        self.finalize_fallback(acs_output.clone()).await;
        Ok(())
    }

    fn sanitize_header(&mut self, header: &Header) -> DagResult<()> {
        ensure!(
            self.gc_round <= header.round,
            DagError::TooOld(header.id.clone(), header.round)
        );

        // Verify the header's signature.
        header.verify(&self.committee)?;

        ensure!(
            self.consensus_mode == ConsensusMode::Optimistic,
            DagError::InvalidFallbackMessage
        );

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    fn sanitize_timeout(&mut self, timeout: &Timeout) -> DagResult<()> {
        ensure!(
            self.gc_round <= timeout.round,
            DagError::TooOld(timeout.digest(), timeout.round)
        );

        // Verify the timeout's signature.
        timeout.verify(&self.committee)?;

        ensure!(
            self.consensus_mode == ConsensusMode::Optimistic,
            DagError::InvalidFallbackMessage
        );

        Ok(())
    }

    fn sanitize_no_vote_msg(&mut self, no_vote_msg: &NoVoteMsg) -> DagResult<()> {
        ensure!(
            self.gc_round <= no_vote_msg.round,
            DagError::TooOld(no_vote_msg.digest(), no_vote_msg.round)
        );

        // Verify the no vote message's signature.
        no_vote_msg.verify(&self.committee)?;

        ensure!(
            self.consensus_mode == ConsensusMode::Optimistic,
            DagError::InvalidFallbackMessage
        );

        Ok(())
    }

    fn sanitize_vote(&mut self, vote: &Vote) -> DagResult<()> {
        ensure!(
            self.current_header.round <= vote.round,
            DagError::TooOld(vote.digest(), vote.round)
        );

        // Ensure we receive a vote on the expected header.
        ensure!(
            vote.id == self.current_header.id
                && vote.origin == self.current_header.author
                && vote.round == self.current_header.round,
            DagError::UnexpectedVote(vote.id.clone())
        );

        ensure!(
            self.consensus_mode == ConsensusMode::Optimistic,
            DagError::InvalidFallbackMessage
        );

        // Verify the vote.
        vote.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_certificate(&mut self, certificate: &Certificate) -> DagResult<()> {
        ensure!(
            self.gc_round <= certificate.round(),
            DagError::TooOld(certificate.digest(), certificate.round())
        );

        ensure!(
            self.consensus_mode == ConsensusMode::Optimistic,
            DagError::InvalidFallbackMessage
        );

        // Verify the certificate (and the embedded header).
        certificate.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_meta_post_block(&mut self, meta_post_block: &MetaPoSTBlockData) -> DagResult<()> {
        // verify if it has the same fallback view
        // todo: buffer future PoST blocks
        ensure!(
            self.acs_manager.last_acs_round <= meta_post_block.acs_round,
            DagError::PoSTTooOld(
                meta_post_block.digest(),
                meta_post_block.acs_round,
                self.acs_manager.last_acs_round
            )
        );

        // verify if it is the first PoST block from the node
        let author = meta_post_block.stuck_block.author.clone();
        ensure!(
            self.acs_manager
                .last_seen_post_blocks
                .get(&author)
                .is_none(),
            DagError::AuthorityReuse(author)
        );
        // self.last_seen_post_blocks.insert(author, meta_post_block.clone());

        // verify if it contains the latest vertex
        if let Some(last_seen_header) = self.last_seen_headers.get(&author) {
            // refuse an old vertex
            ensure!(
                last_seen_header.round <= meta_post_block.stuck_block.round,
                DagError::HeaderTooOld(meta_post_block.stuck_block.round, last_seen_header.round)
            );
            if last_seen_header.round == meta_post_block.stuck_block.round {
                // refuse equivocated PoST blocks
                ensure!(
                    last_seen_header.id == meta_post_block.stuck_block.id,
                    DagError::EquivocationPoST
                );
            }
        }

        // Verify the meta post block.
        meta_post_block
            .verify(&self.committee)
            .map_err(DagError::from)
    }

    fn sanitize_post_block_vote(&mut self, post_block_vote: &PoSTBlockVote) -> DagResult<()> {
        ensure!(
            self.acs_manager.last_acs_round <= post_block_vote.acs_round,
            DagError::TooOld(post_block_vote.digest(), post_block_vote.acs_round)
        );

        // Ensure we receive a vote on the expected post block.
        ensure!(
            post_block_vote.dg == self.acs_manager.current_post_block.dg
                && post_block_vote.acs_round == self.acs_manager.current_post_block.acs_round,
            DagError::UnexpectedPoSTVote(post_block_vote.dg.clone())
        );

        // Verify the post block vote.
        post_block_vote
            .verify(&self.committee)
            .map_err(DagError::from)
    }

    fn sanitize_post_block(&mut self, post_block: &CertifiedPoSTBlockData) -> DagResult<()> {
        ensure!(
            self.acs_manager.last_acs_round <= post_block.meta_post.acs_round,
            DagError::TooOld(post_block.digest(), post_block.meta_post.acs_round)
        );

        // Verify the post block.
        post_block.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_certified_post_block_vote(
        &mut self,
        certified_post_block_vote: &CertifiedPoSTBlockVote,
    ) -> DagResult<()> {
        ensure!(
            self.acs_manager.last_acs_round
                <= certified_post_block_vote
                    .certified_post_block
                    .meta_post
                    .acs_round,
            DagError::TooOld(
                certified_post_block_vote.digest(),
                certified_post_block_vote
                    .certified_post_block
                    .meta_post
                    .acs_round
            )
        );

        // Verify the post block vote.
        certified_post_block_vote
            .verify(&self.committee)
            .map_err(DagError::from)
    }

    fn sanitize_mvba_proposal(&mut self, mvba_proposal: &MVBAProposal) -> DagResult<()> {
        ensure!(
            self.acs_manager.last_acs_round <= mvba_proposal.acs_round,
            DagError::TooOld(mvba_proposal.digest(), mvba_proposal.acs_round)
        );

        // verify if it is the first mvba proposal from the node
        let author = mvba_proposal.author.clone();
        if let Some(last_mvba_proposal) = self.acs_manager.last_seen_mvba_proposals.get(&author) {
            // refuse equivocated mvba proposals
            ensure!(
                last_mvba_proposal.digest() == mvba_proposal.digest(),
                DagError::EquivocationMVBAProposal
            );
        }
        // Verify the mvba proposal.
        mvba_proposal
            .verify(&self.committee)
            .map_err(DagError::from)
    }

    fn sanitize_mvba_proposal_vote(&mut self, mvba_vote: &MVBAVote) -> DagResult<()> {
        ensure!(
            self.acs_manager.last_acs_round <= mvba_vote.mvba_proposal.acs_round,
            DagError::TooOld(mvba_vote.digest(), mvba_vote.mvba_proposal.acs_round)
        );

        // Ensure we receive a vote on the expected mvba proposal.
        if let Some(my_mvba_proposal) = self.acs_manager.last_seen_mvba_proposals.get(&self.name) {
            ensure!(
                mvba_vote.mvba_proposal.digest() == my_mvba_proposal.digest()
                    && mvba_vote.mvba_proposal.acs_round == my_mvba_proposal.acs_round,
                DagError::UnexpectedMVBAVote(mvba_vote.mvba_proposal.digest())
            );
        } else {
            return Err(DagError::NotMyMVBAProposal);
        }

        // Verify the mvba vote.
        mvba_vote.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_mvba(&mut self, mvba: &CertifiedMVBA) -> DagResult<()> {
        ensure!(
            self.acs_manager.last_acs_round <= mvba.proposal.acs_round,
            DagError::TooOld(mvba.digest(), mvba.proposal.acs_round)
        );

        // Verify the mvba.
        mvba.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_certified_mvba_vote(
        &mut self,
        certified_mvba_vote: &CertifiedMVBAVote,
    ) -> DagResult<()> {
        ensure!(
            self.acs_manager.last_acs_round
                <= certified_mvba_vote.certified_mvba.proposal.acs_round,
            DagError::TooOld(
                certified_mvba_vote.digest(),
                certified_mvba_vote.certified_mvba.proposal.acs_round
            )
        );

        // Verify the mvba vote.
        certified_mvba_vote
            .verify(&self.committee)
            .map_err(DagError::from)
    }

    fn sanitize_pisa_bval(&mut self, pisa_bval: &PisaBval) -> DagResult<()> {
        ensure!(
            self.acs_manager.acs_fin.mvba_view <= pisa_bval.clone().view,
            DagError::PisaViewTooOld(pisa_bval.digest(), pisa_bval.clone().view)
        );

        ensure!(
            self.acs_manager.last_acs_round <= pisa_bval.acs_round,
            DagError::MVBAMsgTooOld(pisa_bval.acs_round, self.acs_manager.last_acs_round)
        );

        // Verify the pisa bval signature.
        pisa_bval.verify(&self.committee).map_err(DagError::from)
        // Ok(())
    }

    fn sanitize_pisa_aux(&mut self, pisa_aux: &PisaAux) -> DagResult<()> {
        ensure!(
            self.acs_manager.acs_fin.mvba_view <= pisa_aux.clone().view,
            DagError::PisaViewTooOld(pisa_aux.digest(), pisa_aux.clone().view)
        );

        ensure!(
            self.acs_manager.last_acs_round <= pisa_aux.acs_round,
            DagError::MVBAMsgTooOld(pisa_aux.acs_round, self.acs_manager.last_acs_round)
        );

        // Verify the pisa aux signature.
        pisa_aux.verify(&self.committee).map_err(DagError::from)
        // Ok(())
    }

    fn sanitize_pisa_desicion(&mut self, pisa_decision: &PisaDecision) -> DagResult<()> {
        ensure!(
            self.acs_manager.acs_fin.mvba_view <= pisa_decision.clone().view,
            DagError::PisaViewTooOld(pisa_decision.digest(), pisa_decision.clone().view)
        );

        ensure!(
            self.acs_manager.last_acs_round <= pisa_decision.acs_round,
            DagError::MVBAMsgTooOld(pisa_decision.acs_round, self.acs_manager.last_acs_round)
        );

        // Verify the pisa decision signature.
        pisa_decision
            .verify(&self.committee)
            .map_err(DagError::from)
        // Ok(())
    }

    fn sanitize_acs_output(&mut self, acs_output: &ACSOutput) -> DagResult<()> {
        ensure!(
            self.acs_manager.last_acs_round == acs_output.view,
            DagError::NotSameACSView(acs_output.view, self.acs_manager.last_acs_round)
        );

        // todo: Verify the acs output signature.
        // acs_output.verify(&self.committee).map_err(DagError::from)
        Ok(())
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Header(header) => {
                            if self.consensus_mode == ConsensusMode::Optimistic {
                                match self.sanitize_header(&header) {
                                    Ok(()) => self.process_header(&header).await,
                                    error => error
                                }
                            } else {
                                // If we are in fallback mode we buffer the messages.
                                self.optimistic_buffer.push(PrimaryMessage::Header(header));
                                Ok(())
                            }

                        },
                        PrimaryMessage::Timeout(timeout) => {
                            if self.consensus_mode == ConsensusMode::Optimistic {
                                match self.sanitize_timeout(&timeout) {
                                    Ok(()) => self.process_timeout(timeout).await,
                                    error => error
                                }
                            } else {
                                // If we are in fallback mode we buffer the messages.
                                self.optimistic_buffer.push(PrimaryMessage::Timeout(timeout));
                                Ok(())
                            }
                        },
                        PrimaryMessage::NoVoteMsg(no_vote_msg) => {
                            if self.consensus_mode == ConsensusMode::Optimistic {
                                match self.sanitize_no_vote_msg(&no_vote_msg) {
                                    Ok(()) => self.process_no_vote_msg(no_vote_msg).await,
                                    error => error
                                }
                            } else {
                                // If we are in fallback mode we buffer the messages.
                                self.optimistic_buffer.push(PrimaryMessage::NoVoteMsg(no_vote_msg));
                                Ok(())
                            }
                        },
                        PrimaryMessage::Vote(vote) => {
                            if self.consensus_mode == ConsensusMode::Optimistic {
                                match self.sanitize_vote(&vote) {
                                    Ok(()) => self.process_vote(vote).await,
                                    error => error
                                }
                            } else {
                                // If we are in fallback mode we buffer the messages.
                                self.optimistic_buffer.push(PrimaryMessage::Vote(vote));
                                Ok(())
                            }
                        },
                        PrimaryMessage::Certificate(certificate) => {
                            if self.consensus_mode == ConsensusMode::Optimistic {
                                match self.sanitize_certificate(&certificate) {
                                    Ok(()) => self.process_certificate(certificate).await,
                                    error => error
                                }
                            } else {
                                // If we are in fallback mode we buffer the messages.
                                self.optimistic_buffer.push(PrimaryMessage::Certificate(certificate));
                                Ok(())
                            }
                        },
                        PrimaryMessage::MetaPoSTBlockData(meta_post_block) => {
                            match self.sanitize_meta_post_block(&meta_post_block) {
                                Ok(()) => self.process_meta_post_block(meta_post_block.clone()).await,
                                error => error
                            }
                        },
                        PrimaryMessage::PoSTBlockVote(post_block_vote) => {
                            match self.sanitize_post_block_vote(&post_block_vote) {
                                Ok(()) => self.process_meta_post_block_vote(post_block_vote).await,
                                error => error
                            }
                        },
                        PrimaryMessage::CertifiedPoSTBlockData(post_block) => {
                            match self.sanitize_post_block(&post_block) {
                                Ok(()) => self.process_post_block_after_rbc(post_block).await,
                                error => error
                            }
                        },
                        PrimaryMessage::CertifiedPoSTBlockVote(certified_post_block_vote) => {
                            match self.sanitize_certified_post_block_vote(&certified_post_block_vote) {
                                Ok(()) => self.process_vote_phase_post_block(certified_post_block_vote).await,
                                error => error
                            }
                        },
                        PrimaryMessage::MVBAProposal(mvba_proposal) => {
                            match self.sanitize_mvba_proposal(&mvba_proposal) {
                                Ok(()) => self.process_mvba_proposal(mvba_proposal).await,
                                error => error
                            }
                        },
                        PrimaryMessage::MVBAVote(mvba_vote) => {
                            match self.sanitize_mvba_proposal_vote(&mvba_vote) {
                                Ok(()) => self.process_mvba_proposal_vote(mvba_vote).await,
                                error => error
                            }
                        },
                        PrimaryMessage::CertifiedMVBA(mvba) => {
                            match self.sanitize_mvba(&mvba) {
                                Ok(()) => self.process_mvba_after_rbc(mvba).await,
                                error => error
                            }
                        },
                        PrimaryMessage::CertifiedMVBAVote(certified_mvba_vote) => {
                            match self.sanitize_certified_mvba_vote(&certified_mvba_vote) {
                                Ok(()) => self.process_vote_phase_mvba(certified_mvba_vote).await,
                                error => error
                            }
                        },
                        PrimaryMessage::PisaBval(pisa_bval) => {
                            match self.sanitize_pisa_bval(&pisa_bval) {
                                Ok(()) => self.process_pisa_bval(pisa_bval).await,
                                error => error
                            }
                            // self.process_pisa_bval(pisa_bval).await
                        },
                        PrimaryMessage::PisaAux(pisa_aux) => {
                            match self.sanitize_pisa_aux(&pisa_aux) {
                                Ok(()) => self.process_pisa_aux(pisa_aux).await,
                                error => error
                            }
                            // self.process_pisa_aux(pisa_aux).await
                        },
                        PrimaryMessage::PisaDecision(pisa_decision) => {
                            match self.sanitize_pisa_desicion(&pisa_decision) {
                                Ok(()) => self.process_pisa_desicion(pisa_decision).await,
                                error => error
                            }
                            // self.process_pisa_desicion(pisa_decision).await
                        },
                        PrimaryMessage::ACSOutput(acs_output) => {
                            match self.sanitize_acs_output(&acs_output) {
                                Ok(()) => self.process_acs_output(acs_output).await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => self.process_header(&header).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,
                // We also receive here our timeout created by the `Proposer`.
                Some(timeout) = self.rx_timeout.recv() => self.process_own_timeout(timeout).await,
                // We also receive here our no vote messages created by the `Proposer`.
                Some(no_vote_msg) = self.rx_no_vote_msg.recv() => self.process_own_no_vote_msg(no_vote_msg).await,

                // We receive fallback message from consensus module, indicating we fail to commit blocks for a timeout
                Some(_signal) = self.rx_fallback.recv() => {
                    if self.consensus_mode == ConsensusMode::Optimistic {
                        debug!("Switched to fallback mode in view {}", self.acs_manager.last_acs_round);
                        self.switch_to_fallback_mode().await
                    } else {
                        Ok(())
                    }
                },
            };
            match result {
                Ok(()) => (),
                Err(DagError::StoreError(e)) => {
                    error!("{}", e);
                    panic!("Storage failure: killing node.");
                }
                Err(e @ DagError::TooOld(..)) => debug!("{}", e),
                Err(e) => warn!("{}", e),
            }

            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.last_voted.retain(|k, _| k >= &gc_round);
                self.processing.retain(|k, _| k >= &gc_round);
                self.certificates_aggregators.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
            }
        }
    }
}
