## Workflow of handling a block received from a peer
net_sync -> spawned -> syncer -> core

## Workflow of sending a PoST block
refer to disseminator.disseminate_own_blocks

## TODO:
- generate PoST blocks -> done
- implement a signature_service for ```PoSTBlockVote``` -> done
- handle vote of own PoST from other peers (after that, we might need to implement ```stream_own_acs_blocks``` in synchronizer.rs)
- handle meta PoST (generate Vote and send it back to the authority)
- update own PoST with signature
- impl sending PoST blocks interface, refer to '''disseminate_own_blocks''' -> done
- impl '''verify''' function for UncertifiedPoSTBlockData
- impl '''add_post_blocks''' function for handling PoST blocks in core module  -> done
- impl ACS consensus mode after generate a PoST block