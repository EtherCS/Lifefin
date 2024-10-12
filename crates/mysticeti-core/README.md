## Workflow of handling a block received from a peer
net_sync -> spawned -> syncer -> core

## Workflow of sending a PoST block
refer to disseminator.disseminate_own_blocks

## TODO:
1. generate PoST blocks
2. impl sending PoST blocks interface, refer to '''disseminate_own_blocks'''
3. impl '''verify''' function for UncertifiedPoSTBlockData
4. impl '''add_post_blocks''' function for handling PoST blocks in core module
5. impl ACS consensus mode after generate a PoST block