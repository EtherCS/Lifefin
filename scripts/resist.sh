# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# bash run.sh

export RUST_LOG=warn,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG

# Change to the previous directory
cd ..

# Execute cargo build
cargo build --release

# Return to the original directory
cd -

tmux kill-server || true

load_per_node=100
tx_size=512
delay=0
stuck_round=10

tmux new -d -s "v0" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 0 --attack-type 1 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v0.log.ansi"
tmux new -d -s "v1" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 1 --attack-type 1 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v1.log.ansi"
tmux new -d -s "v2" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 2 --attack-type 1 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v2.log.ansi"
tmux new -d -s "v3" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 3 --attack-type 0 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v3.log.ansi"
tmux new -d -s "v4" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 4 --attack-type 0 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v4.log.ansi"
tmux new -d -s "v5" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 5 --attack-type 0 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v5.log.ansi"
tmux new -d -s "v6" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 6 --attack-type 0 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v6.log.ansi"
tmux new -d -s "v7" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 7 --attack-type 0 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v7.log.ansi"
tmux new -d -s "v8" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 8 --attack-type 0 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v8.log.ansi"
tmux new -d -s "v9" "cargo run --bin mysticeti attack-resist-run --committee-size 10 --authority 9 --attack-type 0 --load $load_per_node --transaction-size $tx_size --initial-delay $delay --stuck-round $stuck_round > resist.v9.log.ansi"

sleep 50
tmux kill-server
