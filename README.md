# DAGACS

[![build status](https://img.shields.io/github/actions/workflow/status/asonnino/shamir-bip39/code.yml?branch=main&logo=github&style=flat-square)](https://github.com/asonnino/shamir-bip39/actions)
[![rustc](https://img.shields.io/badge/rustc-1.78+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)


## License

This software is licensed as [Apache 2.0](LICENSE).

## Test
```bash
cd scripts
bash acsdryrun.sh 4 1 500 60
```

This command runs **4** nodes (**1** of which are crashed) for **60** seconds, where nodes will be stuck (i.e., entering the fallback consensus mode) in round **500**. After executing this command, check the log file (e.g., `v0.acs.log.ansi`). The nodes are considered to run the fallback consensus mode successfully if the relevant information are printed as follows:
```
...
2024-11-09T20:49:00.766472Z DEBUG mysticeti_core::core: Committing ACS output ACSOutput { round: 500, [A500:[A499,B498,C499,D499,](), B500:[B499,C499,D499,A499,](), C500 [C499,B498,D499,A499,]()] }
2024-11-09T20:49:00.766577Z DEBUG mysticeti_core::core: New leader block A500:[A499,B498,C499,D499,]()
...
```

## Observations
**Performance degradation:** While recovering to optmistic mode from ACS mode, nodes may experience a *hangover* period, leading to the performance degradation. Specifically, some nodes need to synchronize the missing blocks included by the ACS output and cannot catch up the latest round. The other nodes therefore have to either be stuck (if *>f* nodes need to sync) or wait for a leader timeout (if *<=f* nodes need to sync) to move to next rounds.