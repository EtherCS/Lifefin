// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::{Arc, RwLock}};

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
    /// Signer
    signer: Signer,
}

impl PoSTBlockDisseminator
{
    pub fn new(
        acs_manager: Arc<RwLock<ACSManager>>,
        sender: mpsc::Sender<NetworkMessage>,
        signer: Signer,
    ) -> Self {
        Self {
            acs_manager,
            sender,
            own_acs_blocks: None,
            signer,
        }
    }

    pub async fn shutdown(mut self) {
        let mut waiters = Vec::with_capacity(1);
        if let Some(handle) = self.own_acs_blocks.take() {
            handle.abort();
            waiters.push(handle);
        }
        join_all(waiters).await;
    }

    // todo: 
    pub async fn send_vote(
        &mut self,
        author: PublicKey,
        meta_post_block: MetaPoSTBlockData
    ) -> Option<()> {
        let vote = PoSTBlockVote::new(meta_post_block, author, self.signer.clone()).await;
        self.sender.send(NetworkMessage::ProofOfStuckBlockVote(vote)).await.ok()
    }

    pub async fn disseminate_own_acs_block(&mut self, round: RoundNumber, committee: Committee,) {
        if let Some(existing) = self.own_acs_blocks.take() {
            existing.abort();
            existing.await.ok();
        }

        let acs_handle = Handle::current().spawn(Self::stream_own_acs_blocks(
            Arc::clone(&self.acs_manager),
            self.sender.clone(),
            round,
            // quorum_threshold,
            committee,
        ));
        self.own_acs_blocks = Some(acs_handle);
    }

    async fn stream_own_acs_blocks(
        acs_manager: Arc<RwLock<ACSManager>>,
        to: mpsc::Sender<NetworkMessage>,
        mut round: RoundNumber,
        committee: Committee,
        // quorum_threshold: Stake,
    ) -> Option<()> {
        loop {
            let mut mvba = 0;
            // just for test
            if acs_manager.read().expect("Fail to read acs manager").ready_for_mvba(&committee) {
                mvba = acs_manager.read().expect("Fail to read acs manager").mvba();
                let meta_post_block = MetaPoSTBlockData::new(round, StatementBlock::new_genesis(0), HashMap::new());
                to.send(NetworkMessage::MetaProofOfStuckBlock(meta_post_block))
                    .await
                    .ok()?;
                println!("send meta post block with MVBA {}", mvba);
            }
            // let notified = inner.notify.notified();
            // if let Some(post_block) = inner.block_store.get_own_acs_block(round) {
            //     // check if we get enough (n-f) signatures
            //     // if not, just send the metadata of the PoST block
            //     // otherwise, send the (certified) PoST block
            //     if post_block.signatures.len() as u64 <= quorum_threshold {
            //         let meta_post_block = MetaPoSTBlockData::new(
            //             post_block.stuck_round,
            //             post_block.stuck_block.clone(),
            //             post_block.seen_blocks.clone(),
            //         );
            //         to.send(NetworkMessage::MetaProofOfStuckBlock(meta_post_block))
            //             .await
            //             .ok()?;
            //     } else {
            //         round = post_block.get_stuck_round();
            //         to.send(NetworkMessage::ProofOfStuckBlock(post_block))
            //             .await
            //             .ok()?;
            //     }
            // }
            // notified.await
        }
    }
}

