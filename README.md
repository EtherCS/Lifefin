# DAG-ACS

This branch implemented the inflation attack for testing.

## Attack description
**Attack goal:** the protocol can continue to generate new blocks but no blocks can be committed.

Assume *n=3f+1* nodes, *f* are inflation attackers (defined in [here](https://github.com/EtherCS/dagACS/blob/DAG-inflation/crates/acs/src/adversary.rs#L8)). During the attack evaluation, we are doing two things:
1.  Only running *3f* nodes (simulate that 1 honest node is suffering from DoS attack)
2. *f* inflation attackers create new non-leader blocks but **DO NOT** vote for leader blocks (i.e., not connect leader blocks). Specifically, 
    - attackers do not create leader blocks (see [code](https://github.com/EtherCS/dagACS/blob/DAG-inflation/crates/mysticeti-core/src/core.rs#L290) here)
    - attackers do not vote for leader blocks (see [code](https://github.com/EtherCS/dagACS/blob/DAG-inflation/crates/mysticeti-core/src/core.rs#L296) here)

Since there are only *2f* honest nodes that can vote for leader blocks and *3f* nodes (including attackers) can create new blocks, the protocol will continue to generate new blocks but no blocks can be committed.

## Current issue: the protocol could be stuck 
In the current attack implementation, there is no guarantee that the protocol can continuously generate new blocks. 

Specifically, the DAG protocol allows a node to ***advance*** to a new round *r+1* without creating its block in round *r* after it received *2f+1* blocks in round *r*. In this case, it is possible that there are only *2f+1* blocks generated in round *r*.

After entering round *r+1*, attackers can only connect at most *2f* blocks in round *r* since they do not connect leader blocks (assume one leader block each round). It means that attackers cannot create new blocks in round *r+1* since the protocol asks every new block to connect *2f+1* blocks from the last round.

Eventually, there are at most *2f* new blocks in round *r+1* (*f* attackers cannot create new blocks, and 1 honest node is crashed). The protocol will be stuck since nodes cannot enter round *r+2*.

## Solution
One solution (could be more) is to ask attackers to:
1. ensure *f+2* blocks have been created by honest nodes every round. This has been implemented (see [code](https://github.com/EtherCS/dagACS/blob/DAG-inflation-v2/crates/mysticeti-core/src/core.rs#L314) here).
2. create blocks in *every round*. This has been implemented (see [code](https://github.com/EtherCS/dagACS/blob/DAG-inflation-v2/crates/mysticeti-core/src/threshold_clock.rs#L69) here).

By doing these, attackers can guarantee there are *f+2+f=2f+2* blocks created every round. Therefore, attackers have *2f+1* (excluding the leader block) to connect and can create blocks every round.

## How to test
Enter the ```./scripts``` directory, run:
```bash
bash inflationdryrun.sh
```
This script will recompile all files and run 12 out 13 nodes with the first 4 nodes are inflation attackers (here, *n=13, f=4*). After the script finished, you will see ```attack.v*.log.ansi``` log files in the ```./scripts``` directory. 
