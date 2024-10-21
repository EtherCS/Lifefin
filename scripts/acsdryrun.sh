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

tmux new -d -s "v0" "cargo run --bin mysticeti -- dry-acs-run --committee-size 4 --authority 0 > v0.acs.log.ansi"
tmux new -d -s "v1" "cargo run --bin mysticeti -- dry-acs-run --committee-size 4 --authority 1 > v1.acs.log.ansi"
tmux new -d -s "v2" "cargo run --bin mysticeti -- dry-acs-run --committee-size 4 --authority 2 > v2.acs.log.ansi"
tmux new -d -s "v3" "cargo run --bin mysticeti -- dry-acs-run --committee-size 4 --authority 3 > v3.acs.log.ansi"

sleep 5
tmux kill-server
