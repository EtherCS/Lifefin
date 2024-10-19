// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use futures::future::join_all;
use tokio::sync::mpsc;

use crate::{
    acs_manager::{ACSManager, MetaPoSTBlockData, PoSTBlockVote},
    committee::Committee,
    crypto::{PublicKey, Signer},
    network::NetworkMessage,
    runtime::{Handle, JoinHandle},
    types::{RoundNumber, StatementBlock},
};

pub struct PoSTBlockDisseminator {
    /// The ACS manager, shared with the core
    acs_manager: Arc<RwLock<ACSManager>>,
    /// The sender to the network.
    sender: mpsc::Sender<NetworkMessage>,
    /// The handle of the task disseminating our acs block
    own_acs_blocks: Option<JoinHandle<Option<()>>>,
    /// The handle of the task disseminating our meta acs block
    own_meta_acs_blocks: Option<JoinHandle<Option<()>>>,
    /// Signer
    signer: Signer,
}

impl PoSTBlockDisseminator {
    pub fn new(
        acs_manager: Arc<RwLock<ACSManager>>,
        sender: mpsc::Sender<NetworkMessage>,
        signer: Signer,
    ) -> Self {
        Self {
            acs_manager,
            sender,
            own_acs_blocks: None,
            own_meta_acs_blocks: None,
            signer,
        }
    }

    pub async fn shutdown(mut self) {
        let mut waiters = Vec::with_capacity(1);
        if let Some(handle) = self.own_acs_blocks.take() {
            handle.abort();
            waiters.push(handle);
        }
        if let Some(handle) = self.own_meta_acs_blocks.take() {
            handle.abort();
            waiters.push(handle);
        }
        join_all(waiters).await;
    }

    // todo:
    pub async fn send_vote(
        &mut self,
        author: PublicKey,
        meta_post_block: MetaPoSTBlockData,
    ) -> Option<()> {
        let vote = PoSTBlockVote::new(meta_post_block, author, self.signer.clone()).await;
        self.sender
            .send(NetworkMessage::ProofOfStuckBlockVote(vote))
            .await
            .ok()
    }

    pub async fn disseminate_own_post_block(&mut self, round: RoundNumber) {
        if let Some(existing) = self.own_acs_blocks.take() {
            existing.abort();
            existing.await.ok();
        }

        let acs_handle = Handle::current().spawn(Self::stream_own_post_blocks(
            Arc::clone(&self.acs_manager),
            self.sender.clone(),
            round,
        ));
        self.own_acs_blocks = Some(acs_handle);
    }

    pub async fn disseminate_own_meta_post_block(&mut self, round: RoundNumber) {
        if let Some(existing) = self.own_meta_acs_blocks.take() {
            existing.abort();
            existing.await.ok();
        }

        let meta_acs_handle = Handle::current().spawn(Self::stream_own_meta_post_blocks(
            Arc::clone(&self.acs_manager),
            self.sender.clone(),
            round,
        ));
        self.own_meta_acs_blocks = Some(meta_acs_handle);
    }

    /// stream_own_acs_blocks is used to send UncertifiedPoSTBlockData after collecting enough votes
    /// todo: reliable send
    async fn stream_own_post_blocks(
        acs_manager: Arc<RwLock<ACSManager>>,
        to: mpsc::Sender<NetworkMessage>,
        mut round: RoundNumber,
    ) -> Option<()> {
        loop {
            let blocks = acs_manager
                .read()
                .expect("fails to read my own acs block")
                .read_my_post_block_after_round(round);
            for block in blocks {
                // let post_block = post_block.clone();
                let last_stuck_round = block.stuck_round;
                to.send(NetworkMessage::ProofOfStuckBlock(block))
                    .await
                    .ok()?;
                println!("send post block");
                round = last_stuck_round;
            }
        }
    }

    /// stream_own_meta_acs_blocks is used to send MetaPoSTBlockData
    /// todo: reliable send
    async fn stream_own_meta_post_blocks(
        acs_manager: Arc<RwLock<ACSManager>>,
        to: mpsc::Sender<NetworkMessage>,
        mut round: RoundNumber,
    ) -> Option<()> {
        loop {
            let meta_blocks = acs_manager
                .read()
                .expect("fails to read my own acs block")
                .read_my_meta_post_block_after_round(round);
            for meta_block in meta_blocks {
                // let post_block = post_block.clone();
                let last_stuck_round = meta_block.stuck_round;
                to.send(NetworkMessage::MetaProofOfStuckBlock(meta_block))
                    .await
                    .ok()?;
                println!("send meta post block");
                round = last_stuck_round;
            }
        }
    }
}
