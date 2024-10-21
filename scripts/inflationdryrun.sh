# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# bash run.sh

export RUST_LOG=warn,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG

# Change to the previous directory
cd ..

# Execute cargo build
cargo build

# Return to the original directory
cd -

tmux kill-server || true

tmux new -d -s "v0" "cargo run --bin mysticeti -- dry-attack-run --committee-size 4 --authority 0 --attack-type 0 > attack.v0.log.ansi"
tmux new -d -s "v1" "cargo run --bin mysticeti -- dry-attack-run --committee-size 4 --authority 1 --attack-type 1 > attack.v1.log.ansi"
tmux new -d -s "v2" "cargo run --bin mysticeti -- dry-attack-run --committee-size 4 --authority 2 --attack-type 2 > attack.v2.log.ansi"
tmux new -d -s "v3" "cargo run --bin mysticeti -- dry-attack-run --committee-size 4 --authority 3 --attack-type 3 > attack.v3.log.ansi"

sleep 5
tmux kill-server
