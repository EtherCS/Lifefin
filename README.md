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
 Execution time: 13 s

 Header size: 1 B
 Max header delay: 1,000 ms
 GC depth: 50 round(s)
 Sync retry delay: 10,000 ms
 Sync retry nodes: 3 node(s)
 batch size: 50,000 B
 Max batch delay: 200 ms

 + RESULTS:
 Consensus TPS: 195,176 tx/s
 Consensus BPS: 99,930,002 B/s
 Consensus latency: 1,239 ms
 Consensus leader latency: 79 ms
 Consensus non leader latency: 601 ms

 End-to-end TPS: 195,059 tx/s
 End-to-end BPS: 99,870,214 B/s
 End-to-end latency: 2,330 ms

 ACS Leader latency: 97 ms
 Fallback latency: 94 ms
 ACS data size: 145,681 B
-----------------------------------------
```