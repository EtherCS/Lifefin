# Lifefin

[![Paper](https://img.shields.io/badge/arXiv-2511.15936-b31b1b.svg)](https://arxiv.org/abs/2511.15936)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Research code for **[Lifefin: Escaping Mempool Explosions in DAG-based BFT](https://arxiv.org/pdf/2511.15936)**.

Lifefin adds an Agreement on Common Subset (ACS) fallback to DAG-based Byzantine fault-tolerant consensus. When normal ordering stalls, the fallback commits pending DAG vertices with bounded resource usage. The paper instantiates this mechanism in **Mysticeti-Lifefin** and **Sailfish-Lifefin**, and evaluates their performance and resistance to inflation attacks.

## Choose an implementation or experiment

The artifact spans several branches. Each branch has its own build configuration, command-line interface, and benchmark scripts; use the instructions for the branch you check out.

| Goal | Branch | Entry point |
| --- | --- | --- |
| Browse the artifact and an earlier Mysticeti integration snapshot | [`main`](https://github.com/EtherCS/Lifefin/tree/main) | Repository layout below |
| Run the Mysticeti-Lifefin implementation | [`ACS-mysticeti`](https://github.com/EtherCS/Lifefin/tree/ACS-mysticeti) | Quick start below |
| Run the Sailfish-Lifefin implementation | [`dev-ACS-sailfish-v2`](https://github.com/EtherCS/Lifefin/tree/dev-ACS-sailfish-v2) | Sailfish benchmark below |
| Compare Mysticeti under inflation attacks, with and without Lifefin | [`mysticeti-resist-eval`](https://github.com/EtherCS/Lifefin/tree/mysticeti-resist-eval) | Mysticeti attack evaluation below |
| Compare Sailfish under inflation attacks, with and without Lifefin | [`sailfish-resist-eval`](https://github.com/EtherCS/Lifefin/tree/sailfish-resist-eval) | Sailfish attack evaluation below |

For independent experiments, use separate clones so that binaries, Python environments, logs, and validator storage belong to the same branch.

## Prerequisites

- Git and [Rust installed through rustup](https://www.rust-lang.org/tools/install).
- A C compiler and linker (for example, `build-essential` on Ubuntu or the Xcode Command Line Tools on macOS).
- For the Python benchmark harnesses: Python with `venv` and `pip`, and `tmux`.
- For Sailfish: Clang/libclang and CMake for the RocksDB dependency. Its requirements pin older Python packages, including [Matplotlib 3.3.4](https://pypi.org/project/matplotlib/3.3.4/#files); use a compatible Python environment, such as Python 3.9. The commands below also constrain NumPy to version 1.x for [compatibility with older compiled packages](https://numpy.org/doc/stable/user/troubleshooting-importerror.html#downstream-importerror-attributeerror-or-c-api-abi-incompatibility).

The Mysticeti build and local demo below use **Rust 1.89.0** explicitly. Some branches, including `main`, still select Rust 1.78, which cannot parse some currently resolved dependencies that use the Rust 2024 edition. The `+1.89.0` argument selects the toolchain for each command. For Python scripts that launch Cargo, set `RUSTUP_TOOLCHAIN=1.89.0` instead.

## Quick start: Mysticeti on one machine

### Build

```bash
git clone --branch ACS-mysticeti https://github.com/EtherCS/Lifefin.git
cd Lifefin
rustup toolchain install 1.89.0
cargo +1.89.0 build -p mysticeti
./target/debug/mysticeti --help
```

Use `ACS-mysticeti` for fallback experiments; `main` contains an earlier snapshot. Build the validator package with `-p mysticeti`; building the entire workspace also compiles the cloud orchestrator and its AWS SDK dependencies. The executable retains the name `mysticeti`.

### Run four validators and trigger the fallback

Run the following **from the repository root**. It starts four validators on localhost, requests a fallback at round 10, and stops the processes after 30 seconds. No separate client or `tmux` session is needed for this functional demo.

```bash
bash <<'EOF'
set -eu
binary="$(pwd)/target/debug/mysticeti"
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/lifefin.XXXXXX")
pids=()
cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM
echo "Logs and validator storage: $run_dir"
cd "$run_dir"
for authority in 0 1 2 3; do
    RUST_LOG=warn,mysticeti_core::core=debug \
        "$binary" dry-acs-run \
        --committee-size 4 --authority "$authority" --stuck-round 10 \
        > "v${authority}.log.ansi" 2>&1 &
    pids+=("$!")
done
sleep 30
for pid in "${pids[@]}"; do
    kill -0 "$pid"  # All four validators should still be running.
done
for authority in 0 1 2 3; do
    grep -q 'Committing ACS output' "v${authority}.log.ansi"
done
grep -m 3 -E 'Switched to fallback mode|Committing ACS output|Switched to optimistic mode' v*.log.ansi
EOF
```

A successful fallback produces these messages in the validator logs:

```text
Switched to fallback mode in 0 view
Committing ACS output in view 0
Switched to optimistic mode in 0 view
```

The printed temporary directory preserves the logs and `dryacsrun-validator-*` storage directories for inspection. Each invocation creates a fresh directory. The four-node demo uses TCP ports **1500–1503** for consensus and **1504–1507** for Prometheus metrics; run only one such committee at a time. While validators are running, metrics for authority 0 are available at `http://127.0.0.1:1504/metrics`.

To exercise the normal DAG path, replace the validator command inside the loop with:

```bash
RUST_LOG=info,mysticeti_core::consensus=debug \
    "$binary" dry-run --committee-size 4 --authority "$authority" \
    > "v${authority}.log.ansi" 2>&1 &
```

Also replace the final log-check loop and `grep` with `tail -n 10 v*.log.ansi`, since this mode does not force a fallback. These short runs check protocol execution; they do not measure the paper's WAN performance.

## Sailfish-Lifefin local benchmark

After installing the Sailfish prerequisites, create a separate checkout and Python environment:

```bash
git clone --branch dev-ACS-sailfish-v2 https://github.com/EtherCS/Lifefin.git Lifefin-sailfish
cd Lifefin-sailfish
python3.9 -m venv .venv
source .venv/bin/activate
python -m pip install 'numpy<2' -r benchmark/requirements.txt
cd benchmark
RUSTUP_TOOLCHAIN=1.89.0 fab local
```

The harness builds release binaries with the `benchmark` feature, generates keys and configuration, starts validators and clients, and prints a performance summary. The checked-in defaults run 10 nodes for 60 seconds and trigger fallback at round 10. Change `bench_params` and `node_params` in `benchmark/fabfile.py` to vary the workload, faults, duration, and `fallback_round`.

The summary includes consensus and end-to-end throughput/latency, ACS leader latency, fallback latency, and ACS data size. Logs are written under `benchmark/logs/`. See the branch's [benchmark guide](https://github.com/EtherCS/Lifefin/blob/dev-ACS-sailfish-v2/benchmark/README.md) for parameter definitions and remote deployment instructions.

## Inflation attack evaluation

The following experiments compare continued DAG growth and stalled ordering under an inflation attack with recovery through Lifefin. They correspond to the attack and resistance experiments discussed in Sections 3.2 and 7.3 of the paper.

These harnesses launch multiple processes, overwrite their benchmark logs/storage, and stop the default `tmux` server. Run them in separate checkouts on a dedicated benchmark machine. Complete and plot one experiment before starting the next.

### Mysticeti: without and with Lifefin

```bash
git clone --branch mysticeti-resist-eval https://github.com/EtherCS/Lifefin.git Lifefin-mysticeti-eval
cd Lifefin-mysticeti-eval
python3 -m venv .venv
source .venv/bin/activate
python -m pip install fabric matplotlib networkx pandas seaborn
cargo +1.89.0 build --release -p mysticeti
cd benchmark

# Without Lifefin.
RUSTUP_TOOLCHAIN=1.89.0 fab inflation
fab plot --log-dir=. --log-prex=attack --output-path=my-inflation.pdf

# With Lifefin.
RUSTUP_TOOLCHAIN=1.89.0 fab resist
fab plot --log-dir=. --log-prex=resist --output-path=my-resist.pdf
```

This branch has no `benchmark/requirements.txt`; install the imports listed above. Build the release binary before invoking Fabric: its fallback build command otherwise builds the entire workspace. Rebuild explicitly after changing the Rust code, since the harness reuses an existing release binary.

The defaults use 10 nodes, including 3 inflation attackers, a total input rate of 50,000 transactions/s, 512-byte transactions, and a 100-second run. One honest node is stopped at 20 seconds. The `resist` task forces fallback at round 80; adjust `stuck_round` in `benchmark/fabfile.py` if necessary so that the trigger occurs after the attack begins and before the run ends.

The plots are saved in `benchmark/my-inflation.pdf` and `benchmark/my-resist.pdf`. They show committed bytes/s, proposed bytes/s, and cumulative uncommitted bytes. Inspect whether ordering stalls while proposals continue, and whether fallback restores commitment.

### Sailfish: without and with Lifefin

```bash
git clone --branch sailfish-resist-eval https://github.com/EtherCS/Lifefin.git Lifefin-sailfish-eval
cd Lifefin-sailfish-eval
python3.9 -m venv .venv
source .venv/bin/activate
python -m pip install 'numpy<2' -r benchmark/requirements.txt
cd benchmark

# Without Lifefin: disable the forced fallback.
RUSTUP_TOOLCHAIN=1.89.0 fab inflation --fallback-round=0
fab attackplot --output-path=sf-inflation.pdf

# With Lifefin: trigger the fallback at round 1000.
RUSTUP_TOOLCHAIN=1.89.0 fab inflation --fallback-round=1000
fab attackplot --output-path=sf-resist.pdf
```

The checked-in task uses 10 nodes with 3 inflation attackers, stops an honest node at 20 seconds, and runs for **120 seconds**. Configure the workload and timing in `benchmark/fabfile.py`. Choose a fallback round reached after the attack starts and before the experiment finishes. Output figures are saved in `benchmark/sf-inflation.pdf` and `benchmark/sf-resist.pdf`.

## Performance experiments and reproducibility

For performance and scalability experiments (Sections 7.1–7.2), vary committee size, input rate, and faults in the implementation branches' benchmark configurations. The paper evaluates geo-distributed deployments on AWS `c5a.4xlarge` instances running Ubuntu 20.04 across `us-east-1`, `us-east-2`, `us-west-1`, `eu-west-1`, and `eu-west-2`, using 512-byte transactions and 240-second experiments. Consult Section 7 for the complete methodology and per-experiment settings.

For Mysticeti, the Rust cloud orchestrator is in `crates/orchestrator/`. Its settings template is `crates/orchestrator/assets/settings-template.yml`; copy it to `settings.yml` in the same directory and configure your credentials, SSH key, regions, instance type, and repository URL/branch. The template references the upstream Mysticeti repository, so update `repository.url` to `https://github.com/EtherCS/Lifefin.git` and select the implementation revision in `repository.commit`. The orchestrator's AWS SDK dependencies may require a newer Rust toolchain than the validator. The local validator instructions above do not validate a cloud build or provision resources.

For Sailfish, use the [implementation branch's AWS benchmark guide](https://github.com/EtherCS/Lifefin/blob/dev-ACS-sailfish-v2/benchmark/README.md), and update its repository settings to this repository and the intended branch before deployment. Cloud experiments require your own account and incur provider charges.

Record `git rev-parse HEAD`, `rustc +1.89.0 --version`, the generated `Cargo.lock`, Python dependencies (`python -m pip freeze`), benchmark parameters, and hardware alongside each result. `Cargo.lock` is currently ignored by Git, so preserve it with experiment outputs to retain the resolved dependency versions. The local examples above provide functional checks and experiment entry points; reproducing every paper figure also requires the corresponding WAN setup and workload sweeps.

## Repository layout on `main`

```text
crates/acs/               Shared ACS interfaces and adversarial node types
crates/mysticeti/         Validator CLI and benchmark genesis generation
crates/mysticeti-core/    DAG consensus, ACS fallback, networking, and metrics
crates/orchestrator/      Cloud testbed and benchmark orchestration
crates/third-party/       Vendored utility crate
scripts/                 Local demos and development checks
```

## Citation

```bibtex
@misc{zhang2025lifefin,
  title         = {Lifefin: Escaping Mempool Explosions in {DAG}-based {BFT}},
  author        = {Jianting Zhang and Sen Yang and Alberto Sonnino and Sebasti{\'a}n Loza and Aniket Kate},
  year          = {2025},
  eprint        = {2511.15936},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2511.15936}
}
```

## Acknowledgments and license

The implementations build on [Mysticeti](https://github.com/asonnino/mysticeti) and [Sailfish](https://github.com/nibeshrestha/sailfish).

This software is licensed under the [Apache License 2.0](LICENSE).
