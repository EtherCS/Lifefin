# DAGACS

[![build status](https://img.shields.io/github/actions/workflow/status/asonnino/shamir-bip39/code.yml?branch=main&logo=github&style=flat-square)](https://github.com/asonnino/shamir-bip39/actions)
[![rustc](https://img.shields.io/badge/rustc-1.78+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)


## License

This software is licensed as [Apache 2.0](LICENSE).

## Test
```bash
cd scripts
bash acsdryrun 4 50 10
```

This command runs **4** nodes for **10** seconds, where nodes will be stuck (i.e., entering the fallback consensus mode) in round 50. After executing this command, check the log file (e.g., `v0.acs.log.ansi`). The nodes are considered to run the fallback consensus mode successfully if the relevant information are printed as follows:
```
...
2024-11-09T20:49:00.766472Z DEBUG mysticeti_core::core: Committing ACS output ACSOutput { round: 50, [A50:[A49,C49,B49,](), B50:[B49,C49,D49,](), C50:[C49,B49,D49,]()] }
2024-11-09T20:49:00.766577Z DEBUG mysticeti_core::core: New leader block C50:[C49,B49,D49,]()
...
```

## TODO: support general ACS test

- Support arbitrary stuck round numbers, e.g., committed ACS output = [A100, B100, C30]
    - Currently, a new block can only connect to blocks from **the last round**.
    - Therefore, this can be done by bypassing the normal verification of the block's references when the protocol is under the fallback (ACS) consensus mode. 