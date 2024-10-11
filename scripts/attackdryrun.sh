# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# bash run.sh

export RUST_LOG=warn,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG

tmux kill-server || true

tmux new -d -s "v0" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 0 --attack-type 1 > attack.v0.log.ansi"
tmux new -d -s "v1" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 1 --attack-type 1 > attack.v1.log.ansi"
tmux new -d -s "v2" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 2 --attack-type 1 > attack.v2.log.ansi"
tmux new -d -s "v3" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 3 --attack-type 1 > attack.v3.log.ansi"
tmux new -d -s "v4" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 4 --attack-type 0 > attack.v4.log.ansi"
tmux new -d -s "v5" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 5 --attack-type 0 > attack.v5.log.ansi"
tmux new -d -s "v6" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 6 --attack-type 0 > attack.v6.log.ansi"
tmux new -d -s "v7" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 7 --attack-type 0 > attack.v7.log.ansi"
tmux new -d -s "v8" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 8 --attack-type 0 > attack.v8.log.ansi"
tmux new -d -s "v9" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 9 --attack-type 0 > attack.v9.log.ansi"
tmux new -d -s "v10" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 10 --attack-type 0 > attack.v10.log.ansi"
tmux new -d -s "v11" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 11 --attack-type 0 > attack.v11.log.ansi"
# tmux new -d -s "v12" "cargo run --bin mysticeti -- dry-attack-run --committee-size 13 --authority 12 --attack-type 0 > attack.v12.log.ansi"


sleep 30
tmux kill-server
