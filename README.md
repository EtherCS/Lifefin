# Sailfish

This repo provides an implementation of Sailfish. The core consensus logic of Bullshark is modified to obtain Sailfish. The codebase has been designed to be small, efficient, and easy to benchmark and modify. It has not been designed to run in production but uses real cryptography ([dalek](https://doc.dalek.rs/ed25519_dalek)), networking ([tokio](https://docs.rs/tokio)), and storage ([rocksdb](https://docs.rs/rocksdb)).

## Quick Start

The core protocols are written in Rust, but all benchmarking scripts are written in Python and run with [Fabric](http://www.fabfile.org/).

To deploy and benchmark a testbed of 4 nodes on your local machine, clone the repo and install the python dependencies:

```
$ git clone https://github.com/nibeshrestha/sailfish.git
$ cd sailfish/benchmark
$ pip install -r requirements.txt
```

You also need to install Clang (required by rocksdb) and [tmux](https://linuxize.com/post/getting-started-with-tmux/#installing-tmux) (which runs all nodes and clients in the background). Finally, run a local benchmark using fabric:

```
$ fab local
```

This command may take a long time the first time you run it (compiling rust code in `release` mode may be slow) and you can customize a number of benchmark parameters in `fabfile.py`. When the benchmark terminates, it displays a summary of the execution similarly to the one below.

```
-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Faults: 0 node(s)
 Committee size: 4 node(s)
 Worker(s) per node: 1 worker(s)
 Collocate primary and workers: True
 Input rate: 50,000 tx/s
 Transaction size: 512 B
 Execution time: 19 s

 Header size: 1,000 B
 Max header delay: 1_000 ms
 GC depth: 50 round(s)
 Sync retry delay: 10,000 ms
 Sync retry nodes: 3 node(s)
 batch size: 500,000 B
 Max batch delay: 100 ms

 + RESULTS:
 Consensus TPS: 46,478 tx/s
 Consensus BPS: 23,796,531 B/s
 Consensus latency: 464 ms

 End-to-end TPS: 46,149 tx/s
 End-to-end BPS: 23,628,541 B/s
 End-to-end latency: 557 ms
-----------------------------------------
```

## Attack evaulation
There are some parameters in the `local` function of `fabfile.py` as follows:
```
bench_params = {
    'faults': 1, # the number of crashed nodes
    'nodes': 7,
    'workers': 1,
    'rate': 50_000,
    'tx_size': 512,
    'duration': 60,
    "burst": 10
}
node_params = {
    'header_size': 1_000,  # bytes
    'max_header_delay': 0,  # ms
    'gc_depth': 50,  # rounds
    'sync_retry_delay': 10_000,  # ms
    'sync_retry_nodes': 3,  # number of nodes
    'batch_size': 50_000,  # bytes
    'max_batch_delay': 200,  # ms
    'node_types': [0, 0, 0, 0, 2, 2, 1]  # 0: honest, 1: crash, 2: attack
}
```
In the above parameters, we run **7** nodes, of which **1** node is crashed (due to the dos attack), and **2** nodes are inflation attackers. The list `node_types` specifies the nodes types.

With this setting, the attack is successful, the throughput will drop to 0 as printed:
```
-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Faults: 1 node(s)
 Committee size: 7 node(s)
 Worker(s) per node: 1 worker(s)
 Collocate primary and workers: True
 Input rate: 4,285,800 tx/s
 Transaction size: 512 B
 Execution time: 0 s

 Header size: 1,000 B
 Max header delay: 0 ms
 GC depth: 50 round(s)
 Sync retry delay: 10,000 ms
 Sync retry nodes: 3 node(s)
 batch size: 50,000 B
 Max batch delay: 200 ms

 + RESULTS:
 Consensus TPS: 0 tx/s
 Consensus BPS: 0 B/s
 Consensus latency: 0 ms
 Consensus leader latency: 0 ms
 Consensus non leader latency: 0 ms

 End-to-end TPS: 0 tx/s
 End-to-end BPS: 0 B/s
 End-to-end latency: 0 ms
-----------------------------------------
```

## Next Steps

The next step is to read the paper Sailfish. It is then recommended to have a look at the README files of the [worker](https://github.com/asonnino/narwhal/tree/bullshark/worker) and [primary](https://github.com/asonnino/narwhal/tree/bullshark/primary) crates. 

The README file of the benchmark folder explains how to benchmark the codebase and read benchmarks' results. It also provides a step-by-step tutorial to run benchmarks on [Amazon Web Services (AWS)](https://aws.amazon.com) accross multiple data centers (WAN).

## License

This software is licensed as [Apache 2.0](LICENSE).
