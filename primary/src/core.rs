use crate::acs_manager::ACSManager;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::acs_types::ACSFin;
use crate::aggregators::{
    CertificatesAggregator, NoVoteAggregator, PisaAuxAggregator, PisaBvalAggregator,
    PisaDesicionAggregator, TimeoutAggregator, VotesAggregator,
};
use crate::error::{DagError, DagResult};
use crate::messages::{
    Certificate, Header, NoVoteCert, NoVoteMsg, PisaAux, PisaBval, PisaDecision, Timeout,
    TimeoutCert, Vote,
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

    /// The consensus mode the node is running in.
    consensus_mode: ConsensusMode,
    /// The ACSFin protocol manager.
    acs_manager: ACSManager,
    /// Buffer for optimistic messages received in fallback mode.
    optimistic_buffer: Vec<PrimaryMessage>,

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
    /// The round for changing to fallback mode.
    fallback_round: Round,
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
    /// Aggregator of Bval messages
    pisa_bval_aggregators: HashMap<Round, Box<PisaBvalAggregator>>,
    /// Aggregator of Aux messages
    pisa_aux_aggregators: HashMap<Round, Box<PisaAuxAggregator>>,
    /// Aggregator of the desicion messages of other primaries
    pisa_descion_aggregators: HashMap<Round, Box<PisaDesicionAggregator>>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    /// Aggregates timeouts to use for sending timeout certificate.
    timeouts_aggregators: HashMap<Round, Box<TimeoutAggregator>>,
    /// Aggregates no vote messages to use for sending no vote certificates.
    no_vote_aggregators: HashMap<Round, Box<NoVoteAggregator>>,
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
        fallback_round: Round,
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
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee: committee.clone(),
                store,
                synchronizer,
                signature_service,
                consensus_round,
                gc_depth,
                consensus_mode: ConsensusMode::Optimistic,
                acs_manager: ACSManager::new(name, committee.clone()),
                optimistic_buffer: Vec::new(),
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
                pisa_bval_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                pisa_aux_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                pisa_descion_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                no_vote_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
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

        // Ensure we have the payload. If we don't, the synchronizer will ask our workers to get it, and then
        // reschedule processing of this header once we have it.
        if self.synchronizer.missing_payload(header).await? {
            debug!("Processing of {} suspended: missing payload", header);
            return Ok(());
        }

        // Store the header.
        let bytes = bincode::serialize(header).expect("Failed to serialize header");
        self.store.write(header.id.to_vec(), bytes).await;

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
            }
        }

        if header.round == self.fallback_round && self.consensus_mode == ConsensusMode::Optimistic {
            self.consensus_mode = ConsensusMode::Fallback;
            debug!("Switched to fallback mode");
            self.switch_to_fallback_mode().await;
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

    async fn switch_to_fallback_mode(&mut self) {}

    async fn initialize_pisa_protocol(&mut self) {
        let est_r = 1;
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
            .create_bval_message(self.acs_manager.acs_fin.est_r, 2);
        self.acs_manager.acs_fin.bval_1_sent = true;

        let handlers = self
            .acs_manager
            .acs_fin
            .broadcast_bval_message(&self.committee, bval_message.clone(), &mut self.network)
            .await;

        self.cancel_handlers
            .entry(bval_message.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        self.acs_manager
            .acs_fin
            .add_bin_value(bval_message.round, bval_message.est);

        // Broadcasting aux(1,1) if it hasn't been sent yet
        if !self.acs_manager.acs_fin.aux_sent {
            let aux_message = self.acs_manager.acs_fin.create_aux_message(1, 1);

            let handlers = self
                .acs_manager
                .acs_fin
                .broadcast_aux_message(&self.committee, aux_message.clone(), &mut self.network)
                .await;

            self.cancel_handlers
                .entry(aux_message.round)
                .or_insert_with(Vec::new)
                .extend(handlers);

            self.acs_manager.acs_fin.aux_sent = true;
        }
    }

    async fn switch_to_optimistic_mode(&mut self) {
        self.consensus_mode = ConsensusMode::Optimistic;
        debug!("Switched to optimistic mode");

        let messages: Vec<PrimaryMessage> = self.optimistic_buffer.drain(..).collect();

        for message in messages {
            let result = match message {
                PrimaryMessage::Header(header) => match self.sanitize_header(&header) {
                    Ok(()) => self.process_header(&header).await,
                    error => error,
                },
                PrimaryMessage::Timeout(timeout) => match self.sanitize_timeout(&timeout) {
                    Ok(()) => self.process_timeout(timeout).await,
                    error => error,
                },
                PrimaryMessage::NoVoteMsg(no_vote_msg) => {
                    match self.sanitize_no_vote_msg(&no_vote_msg) {
                        Ok(()) => self.process_no_vote_msg(no_vote_msg).await,
                        error => error,
                    }
                }
                PrimaryMessage::Vote(vote) => match self.sanitize_vote(&vote) {
                    Ok(()) => self.process_vote(vote).await,
                    error => error,
                },
                PrimaryMessage::Certificate(certificate) => {
                    match self.sanitize_certificate(&certificate) {
                        Ok(()) => self.process_certificate(certificate).await,
                        error => error,
                    }
                }
                _ => panic!("Unexpected core message"),
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
        }
    }

    async fn process_pisa_bval(&mut self, pisa_bval: PisaBval) -> DagResult<()> {
        info!("Processing pisa_bval_message{:?}", pisa_bval);

        // If acs is starting (round 0) we execute pisa protocol, else we execute pillar protocol.
        match pisa_bval.round {
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
            .entry(pisa_bval.round)
            .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
            .append(&self.committee, pisa_bval.clone())
        {
            info!("Received f + 1 bval({}, *) messages", pisa_bval.est);
            match pisa_bval.est {
                0 => {
                    // If bval(0, maj_r message has not been broadcast yet, we broadcast it.
                    if !self.acs_manager.acs_fin.bval_0_sent {
                        let bval_majr_message = self.acs_manager.acs_fin.create_bval_message(
                            pisa_bval.est.clone(),
                            self.acs_manager.acs_fin.maj_r,
                        );

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
                            .entry(bval_majr_message.round)
                            .or_insert_with(Vec::new)
                            .extend(handlers);

                        self.acs_manager.acs_fin.bval_0_sent = true;
                    }
                }
                1 => {
                    // If bval(1, maj_r message has not been broadcast yet, we broadcast it.
                    if !self.acs_manager.acs_fin.bval_1_sent {
                        let bval_majr_message = self.acs_manager.acs_fin.create_bval_message(
                            pisa_bval.est.clone(),
                            self.acs_manager.acs_fin.maj_r,
                        );

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
                            .entry(bval_majr_message.round)
                            .or_insert_with(Vec::new)
                            .extend(handlers);

                        self.acs_manager.acs_fin.bval_1_sent = true;
                    }

                    // We add b to bin values if it is 1 and broadcast aux(1, 1) if we haven't.
                    self.acs_manager
                        .acs_fin
                        .add_bin_value(pisa_bval.round, pisa_bval.est);
                    if !self.acs_manager.acs_fin.aux_sent {
                        let aux_message = self.acs_manager.acs_fin.create_aux_message(1, 1);
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
                            .entry(aux_message.round)
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
                .entry(pisa_bval.round)
                .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                .enough_bvals_for_quorum(&self.committee, pisa_bval.est)
            {
                info!("Received 2f + 1 bval({}, *) messages", pisa_bval.est);
                self.acs_manager
                    .acs_fin
                    .add_bin_value(pisa_bval.round, pisa_bval.est);
                if self.acs_manager.acs_fin.aux_sent {
                    let aux_message = self
                        .acs_manager
                        .acs_fin
                        .create_aux_message(pisa_bval.est, pisa_bval.est);

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
                        .entry(aux_message.round)
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
            .add_maj_value(pillar_bval.round, pillar_bval.maj);
        let maj_r = self.acs_manager.acs_fin.maj_r;

        // If we have received f + 1 bval(b, *) messages we can proceed.
        if self
            .pisa_bval_aggregators
            .entry(pillar_bval.round)
            .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
            .append(&self.committee, pillar_bval.clone())
        {
            info!("Received f + 1 bval({}, *) messages", pillar_bval.est);
            if let Some(message) = match pillar_bval.est {
                0 => {
                    if !self.acs_manager.acs_fin.bval_0_sent {
                        let bval_majr_message =
                            self.acs_manager.acs_fin.create_bval_message(0, maj_r);

                        self.acs_manager.acs_fin.bval_0_sent = true;
                        Some(bval_majr_message)
                    } else {
                        None
                    }
                }
                1 => {
                    if !self.acs_manager.acs_fin.bval_1_sent {
                        let bval_majr_message =
                            self.acs_manager.acs_fin.create_bval_message(1, maj_r);

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
                    .entry(message.round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);
            }

            // If we have received 2f + 1 bval(b, *) messages we can proceed.
            if self
                .pisa_bval_aggregators
                .entry(pillar_bval.round)
                .or_insert_with(|| Box::new(PisaBvalAggregator::new()))
                .enough_bvals_for_quorum(&self.committee, pillar_bval.est)
            {
                info!("Received 2f + 1 bval({}, *) messages", pillar_bval.est);
                self.acs_manager
                    .acs_fin
                    .add_bin_value(pillar_bval.round, pillar_bval.est);

                let delta_b = self.acs_manager.acs_fin.delta_b(pillar_bval.est);

                // if aux(b, *) or aux(not b, *) has not been sent, we can proceed.
                if !self.acs_manager.acs_fin.aux_0_sent || self.acs_manager.acs_fin.aux_1_sent {
                    let message = match delta_b {
                        1 => self
                            .acs_manager
                            .acs_fin
                            .create_aux_message(pillar_bval.est, pillar_bval.est),
                        _ => self
                            .acs_manager
                            .acs_fin
                            .create_aux_message(2, pillar_bval.est),
                    };
                    let handlers = self
                        .acs_manager
                        .acs_fin
                        .broadcast_aux_message(&self.committee, message.clone(), &mut self.network)
                        .await;

                    self.cancel_handlers
                        .entry(pillar_bval.round)
                        .or_insert_with(Vec::new)
                        .extend(handlers);
                }
            }
        }

        Ok(())
    }

    async fn process_pisa_aux(&mut self, pisa_aux: PisaAux) -> DagResult<()> {
        debug!("Received pisa_aux_message{:?}", pisa_aux);

        match pisa_aux.round {
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
            .entry(pisa_aux.round)
            .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
            .append(&self.committee, pisa_aux.clone())
        {
            info!("Received n - f or 2f + 1 aux(*, *) messages");
            let vals_r = self
                .pisa_aux_aggregators
                .entry(pisa_aux.round)
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
                    .decide(&self.committee, &mut self.network, 1)
                    .await;
                self.cancel_handlers
                    .entry(pisa_aux.round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);
                self.switch_to_optimistic_mode().await;
            } else {
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .advance_round(&self.committee, &mut self.network)
                    .await;

                self.cancel_handlers
                    .entry(pisa_aux.round)
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
            .entry(pillar_aux.round)
            .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
            .append(&self.committee, pillar_aux.clone())
        {
            let vals_r = self
                .pisa_aux_aggregators
                .entry(pillar_aux.round)
                .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
                .get_vals_round();

            let avals_r = self
                .pisa_aux_aggregators
                .entry(pillar_aux.round)
                .or_insert_with(|| Box::new(PisaAuxAggregator::new()))
                .get_avals_round();

            let (decide, b) = self
                .acs_manager
                .acs_fin
                .try_decide(vals_r, avals_r, &self.committee);

            if decide && !self.acs_manager.acs_fin.decided {
                // We broadcast the decide message if we haven't already and chancge to optimistic
                // mode.
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .decide(&self.committee, &mut self.network, b)
                    .await;
                self.cancel_handlers
                    .entry(pillar_aux.round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);

                self.switch_to_optimistic_mode().await;
            } else {
                // If we are not able to decide yet we continue to the next round.
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .advance_round(&self.committee, &mut self.network)
                    .await;

                self.cancel_handlers
                    .entry(pillar_aux.round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);
            }
        }
        Ok(())
    }

    async fn process_pisa_desicion(&mut self, desicion: PisaDecision) -> DagResult<()> {
        debug!("Processing pisa_decision_message{:?}", desicion);

        // If we have received 2f + 1 desicion messages we decide on that value.
        if self
            .pisa_descion_aggregators
            .entry(desicion.round)
            .or_insert_with(|| Box::new(PisaDesicionAggregator::new()))
            .append(&self.committee, desicion.clone())
        {
            if !self.acs_manager.acs_fin.decided {
                let handlers = self
                    .acs_manager
                    .acs_fin
                    .decide(&self.committee, &mut self.network, desicion.val)
                    .await;

                self.cancel_handlers
                    .entry(desicion.round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);

                self.switch_to_optimistic_mode().await;
            }
        }
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
                        PrimaryMessage::PisaBval(pisa_bval) => {
                            self.process_pisa_bval(pisa_bval).await
                        },
                        PrimaryMessage::PisaAux(pisa_aux) => {
                            self.process_pisa_aux(pisa_aux).await
                        },
                        PrimaryMessage::PisaDecision(pisa_decision) => {
                            self.process_pisa_desicion(pisa_decision).await
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
