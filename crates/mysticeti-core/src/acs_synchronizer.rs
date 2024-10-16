// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::future::join_all;
use rand::{seq::SliceRandom, thread_rng};
use tokio::sync::mpsc;

use crate::{
    acs_manager::{MetaPoSTBlockData, PoSTBlockVote},
    block_handler::BlockHandler,
    crypto::{PublicKey, Signer},
    metrics::Metrics,
    net_sync::{self, NetworkSyncerInner},
    network::NetworkMessage,
    runtime::{sleep, timestamp_utc, Handle, JoinHandle},
    syncer::CommitObserver,
    types::{AuthorityIndex, BlockReference, RoundNumber, Stake, StatementBlock},
};


pub struct PoSTBlockDisseminator {
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
        sender: mpsc::Sender<NetworkMessage>,
        signer: Signer,
    ) -> Self {
        Self {
            sender,
            own_acs_blocks: None,
            signer,
        }
    }

    pub async fn shutdown(mut self) {
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
    
    pub async fn disseminate_own_acs_block(&mut self, round: RoundNumber, quorum_threshold: Stake) {
        if let Some(existing) = self.own_acs_blocks.take() {
            existing.abort();
            existing.await.ok();
        }

        let acs_handle = Handle::current().spawn(Self::stream_own_acs_blocks(
            self.sender.clone(),
            round,
            quorum_threshold,
        ));
        self.own_acs_blocks = Some(acs_handle);
    }

    async fn stream_own_acs_blocks(
        to: mpsc::Sender<NetworkMessage>,
        mut round: RoundNumber,
        quorum_threshold: Stake,
    ) -> Option<()> {
        loop {
            // just for test
            let meta_post_block = MetaPoSTBlockData::new(round, StatementBlock::new_genesis(0), HashMap::new());
            to.send(NetworkMessage::MetaProofOfStuckBlock(meta_post_block))
                .await
                .ok()?;
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

