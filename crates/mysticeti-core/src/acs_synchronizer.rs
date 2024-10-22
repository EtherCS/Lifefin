// // Copyright (c) Mysten Labs, Inc.
// // SPDX-License-Identifier: Apache-2.0

// use std::sync::{Arc, RwLock};

// use futures::future::join_all;
// use tokio::sync::mpsc;

// use crate::{
//     acs_manager::{ACSManager, MetaPoSTBlockData, PoSTBlockVote, ReliableMVBAProposal},
//     crypto::{PublicKey, Signer},
//     network::NetworkMessage,
//     runtime::{Handle, JoinHandle},
//     types::RoundNumber,
// };

// pub struct PoSTBlockDisseminator {
//     /// The ACS manager, shared with the core
//     acs_manager: Arc<RwLock<ACSManager>>,
//     /// The sender to the network.
//     sender: mpsc::Sender<NetworkMessage>,
//     /// The handle of the task disseminating our acs block
//     own_acs_blocks: Option<JoinHandle<Option<()>>>,
//     /// The handle of the task disseminating our meta acs block
//     own_meta_acs_blocks: Option<JoinHandle<Option<()>>>,
//     /// The current meta post block from this peer
//     last_meta_post_block: Option<MetaPoSTBlockData>,
//     /// The handle of the task disseminating our uncertified mvba
//     own_uncertified_mvbas: Option<JoinHandle<Option<()>>>,
//     /// The handle of the task disseminating our certified mvba
//     own_certified_mvbas: Option<JoinHandle<Option<()>>>,
//     /// The current mvba proposal from this peer
//     last_uncertified_mvba: Option<ReliableMVBAProposal>,
//     /// Signer
//     signer: Signer,
// }

// impl PoSTBlockDisseminator {
//     pub fn new(
//         acs_manager: Arc<RwLock<ACSManager>>,
//         sender: mpsc::Sender<NetworkMessage>,
//         signer: Signer,
//     ) -> Self {
//         Self {
//             acs_manager,
//             sender,
//             own_acs_blocks: None,
//             own_meta_acs_blocks: None,
//             last_meta_post_block: None,
//             own_uncertified_mvbas: None,
//             own_certified_mvbas: None,
//             last_uncertified_mvba: None,
//             signer,
//         }
//     }

//     pub async fn shutdown(mut self) {
//         let mut waiters = Vec::with_capacity(1);
//         if let Some(handle) = self.own_acs_blocks.take() {
//             handle.abort();
//             waiters.push(handle);
//         }
//         if let Some(handle) = self.own_meta_acs_blocks.take() {
//             handle.abort();
//             waiters.push(handle);
//         }
//         if let Some(handle) = self.own_uncertified_mvbas.take() {
//             handle.abort();
//             waiters.push(handle);
//         }
//         if let Some(handle) = self.own_certified_mvbas.take() {
//             handle.abort();
//             waiters.push(handle);
//         }
//         join_all(waiters).await;
//     }

//     // send vote for a valid meta post block
//     pub async fn send_vote_to_post_block(&mut self, author_key: PublicKey, meta_post_block: MetaPoSTBlockData) {
//         // check the validity of the meta post block
//         // verify the stuck round
//         if meta_post_block.stuck_round() < self.acs_manager.read().unwrap().last_acs_round() {
//             tracing::warn!("Received a meta post block with a lower stuck round");
//             return;
//         }
//         // verify if we received an equivocated block
//         if let Some(last_meta_post_block) = &self.last_meta_post_block {
//             if last_meta_post_block.digest() != meta_post_block.digest() {
//                 tracing::warn!("Received an equivocated block");
//                 return;
//             }
//         }
//         // todo: more verification
//         // 1) for a post block with a round smaller than us, we need to synchronize all missing references to guarantee the data availability
//         // 2) verify last seen blocks
//         self.last_meta_post_block = meta_post_block.clone().into();
//         let vote = PoSTBlockVote::new(meta_post_block, author_key, self.signer.clone());
//         self.sender
//             .send(NetworkMessage::ProofOfStuckBlockVote(vote))
//             .await
//             .ok();
//     }

//     pub async fn disseminate_own_post_block(&mut self, round: RoundNumber) {
//         if let Some(existing) = self.own_acs_blocks.take() {
//             existing.abort();
//             existing.await.ok();
//         }

//         // let acs_handle = Handle::current().spawn(Self::stream_own_post_blocks(
//         //     Arc::clone(&self.acs_manager),
//         //     self.sender.clone(),
//         //     round,
//         // ));
//         // self.own_acs_blocks = Some(acs_handle);
//     }

//     pub async fn disseminate_own_meta_post_block(&mut self, round: RoundNumber) {
//         if let Some(existing) = self.own_meta_acs_blocks.take() {
//             existing.abort();
//             existing.await.ok();
//         }

//         // let meta_acs_handle = Handle::current().spawn(Self::stream_own_meta_post_blocks(
//         //     Arc::clone(&self.acs_manager),
//         //     self.sender.clone(),
//         //     round,
//         // ));
//         // self.own_meta_acs_blocks = Some(meta_acs_handle);
//     }

//     pub async fn disseminate_own_uncertified_mvbas(&mut self, round: RoundNumber) {
//         if let Some(existing) = self.own_uncertified_mvbas.take() {
//             existing.abort();
//             existing.await.ok();
//         }

//         let acs_handle = Handle::current().spawn(Self::stream_own_uncertified_mvbas(
//             Arc::clone(&self.acs_manager),
//             self.sender.clone(),
//             round,
//         ));
//         self.own_uncertified_mvbas = Some(acs_handle);
//     }

//     pub async fn disseminate_own_certified_mvbas(&mut self, round: RoundNumber) {
//         if let Some(existing) = self.own_certified_mvbas.take() {
//             existing.abort();
//             existing.await.ok();
//         }

//         let acs_handle = Handle::current().spawn(Self::stream_own_certified_mvbas(
//             Arc::clone(&self.acs_manager),
//             self.sender.clone(),
//             round,
//         ));
//         self.own_certified_mvbas = Some(acs_handle);
//     }

//     /// stream_own_acs_blocks is used to send CertifiedPoSTBlockData after collecting enough votes
//     /// todo: reliable send (currently, it only sends once)
//     // async fn stream_own_post_blocks(
//     //     acs_manager: Arc<RwLock<ACSManager>>,
//     //     to: mpsc::Sender<NetworkMessage>,
//     //     mut round: RoundNumber,
//     //     acs_quorum: Stake,
//     // ) -> Option<()> {
//     //     loop {
//     //         let blocks = acs_manager
//     //             .read()
//     //             .expect("fails to read my own post block")
//     //             .read_my_post_block_after_round(round, acs_quorum);
//     //         for block in blocks {
//     //             let last_stuck_round = block.stuck_round;
//     //             to.send(NetworkMessage::ProofOfStuckBlock(block))
//     //                 .await
//     //                 .ok()?;
//     //             println!("send post block");
//     //             round = last_stuck_round;
//     //         }
//     //     }
//     // }

//     /// stream_own_meta_acs_blocks is used to send MetaPoSTBlockData
//     /// todo: reliable send (currently, it only sends once)
//     // async fn stream_own_meta_post_blocks(
//     //     acs_manager: Arc<RwLock<ACSManager>>,
//     //     to: mpsc::Sender<NetworkMessage>,
//     //     mut round: RoundNumber,
//     // ) -> Option<()> {
//     //     loop {
//     //         let meta_blocks = acs_manager
//     //             .read()
//     //             .expect("fails to read my own meta post block")
//     //             .read_my_meta_post_block_after_round(round);
//     //         for meta_block in meta_blocks {
//     //             let last_stuck_round = meta_block.stuck_round;
//     //             to.send(NetworkMessage::MetaProofOfStuckBlock(meta_block))
//     //                 .await
//     //                 .ok()?;
//     //             println!("send meta post block");
//     //             round = last_stuck_round;
//     //         }
//     //     }
//     // }

//     /// stream_own_uncertified_mvbas is used to send ReliableMVBAProposal
//     /// todo: reliable send (currently, it only sends once)
//     async fn stream_own_uncertified_mvbas(
//         acs_manager: Arc<RwLock<ACSManager>>,
//         to: mpsc::Sender<NetworkMessage>,
//         mut round: RoundNumber,
//     ) -> Option<()> {
//         loop {
//             // todo
//             // let blocks = acs_manager
//             //     .read()
//             //     .expect("fails to read my own post block")
//             //     .read_my_post_block_after_round(round);
//             // for block in blocks {
//             //     let last_stuck_round = block.stuck_round;
//             //     to.send(NetworkMessage::ProofOfStuckBlock(block))
//             //         .await
//             //         .ok()?;
//             //     println!("send post block");
//             //     round = last_stuck_round;
//             // }
//         }
//     }

//     /// stream_own_certified_mvbas is used to send ReliableMVBAProposal
//     /// todo: reliable send (currently, it only sends once)
//     async fn stream_own_certified_mvbas(
//         acs_manager: Arc<RwLock<ACSManager>>,
//         to: mpsc::Sender<NetworkMessage>,
//         mut round: RoundNumber,
//     ) -> Option<()> {
//         loop {
//             // todo
//             // let blocks = acs_manager
//             //     .read()
//             //     .expect("fails to read my own post block")
//             //     .read_my_post_block_after_round(round);
//             // for block in blocks {
//             //     let last_stuck_round = block.stuck_round;
//             //     to.send(NetworkMessage::ProofOfStuckBlock(block))
//             //         .await
//             //         .ok()?;
//             //     println!("send post block");
//             //     round = last_stuck_round;
//             // }
//         }
//     }
// }
