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
 Execution time: 48 s

 Header size: 1 B
 Max header delay: 1,000 ms
 GC depth: 50 round(s)
 Sync retry delay: 10,000 ms
 Sync retry nodes: 3 node(s)
 batch size: 50,000 B
 Max batch delay: 200 ms

 + RESULTS:
 Consensus TPS: 145,346 tx/s
 Consensus BPS: 74,417,319 B/s
 Consensus latency: 1,370 ms
 Consensus leader latency: 295 ms
 Consensus non leader latency: 933 ms

 End-to-end TPS: 145,331 tx/s
 End-to-end BPS: 74,409,489 B/s
 End-to-end latency: 3,279 ms

 ACS Leader latency: 210 ms
 Fallback latency: 114 ms
-----------------------------------------
```