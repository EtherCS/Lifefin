# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# bash run.sh

export RUST_LOG=warn,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG,

# for acs debug
# export RUST_LOG=warn,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG,mysticeti_core::acs_manager=DEBUG,mysticeti_core::acs_types=DEBUG,mysticeti_core::synchronizer=DEBUG,mysticeti_core::block_store=DEBUG
#export RUST_LOG=debug

# Change to the previous directory
cd ..

# Execute cargo build
cargo build

# Return to the original directory
cd -

tmux kill-server || true

# Remove all v*.acs.log.ansi files
rm -f v*.acs.log.ansi
rm -rf dryacsrun-validator-*

# Number of nodes
num_nodes=${1}
crashes=${2}
stuck_round=${3}
run_time=${4}

# Loop to create and run nodes
for i in $(seq 0 $((num_nodes - $crashes - 1))); do
    tmux new -d -s "v$i" "cargo run --bin mysticeti -- dry-acs-run --stuck-round $stuck_round --committee-size $num_nodes --authority $i > v$i.acs.log.ansi"
done

sleep $run_time
tmux kill-server
