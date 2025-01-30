# DAGACS

[![build status](https://img.shields.io/github/actions/workflow/status/asonnino/shamir-bip39/code.yml?branch=main&logo=github&style=flat-square)](https://github.com/asonnino/shamir-bip39/actions)
[![rustc](https://img.shields.io/badge/rustc-1.78+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)


## License

This software is licensed as [Apache 2.0](LICENSE).

## Test
```bash
cd benchmark
fab local
```
By default, it will run **10** nodes for **60** seconds, where nodes will be stuck (i.e., entering the fallback consensus mode) in round **10**. After finishing the execution, the terminal will output:
```
-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Faults: 0 node(s)
 Committee size: 10 node(s)
 Worker(s) per node: 1 worker(s)
 Collocate primary and workers: True
 Input rate: 5,000,000 tx/s
 Transaction size: 512 B
 Execution time: 24 s

 Header size: 1 B
 Max header delay: 1,000 ms
 GC depth: 50 round(s)
 Sync retry delay: 10,000 ms
 Sync retry nodes: 3 node(s)
 batch size: 50,000 B
 Max batch delay: 200 ms

 + RESULTS:
 Consensus TPS: 174,542 tx/s
 Consensus BPS: 89,365,729 B/s
 Consensus latency: 2,762 ms
 Consensus leader latency: 150 ms
 Consensus non leader latency: 658 ms

 End-to-end TPS: 174,492 tx/s
 End-to-end BPS: 89,340,148 B/s
 End-to-end latency: 4,056 ms

 Fallback latency: 125 ms
-----------------------------------------
```