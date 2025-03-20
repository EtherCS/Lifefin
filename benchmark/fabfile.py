import math
import os
import time

from fabric import task

from logs import Parser
from plot import Plotter
from utils import get_mysticeti_path, build_mysticeti, check_mysticeti_path, clean, clean_resist


@task
def inflation(ctx):
    ''' Run benchmarks on localhost '''
    f = 3
    committee_size = 3*f + 1
    bench_params = {
        'rate': 1_000,
        'tx_size': 512,
        'delay': 0,
    }

    total_time = 100 # total time to run the benchmark
    crash_time = 20 # time to crash the honest node

    if not check_mysticeti_path():
        mysticeti_path = build_mysticeti()
    else:
        mysticeti_path = get_mysticeti_path()
    print(f"mysticeti_path: {mysticeti_path}")
    # clean up
    clean()

    load_per_node = math.ceil(bench_params['rate'] / committee_size)
    tx_size = bench_params['tx_size']
    delay = bench_params['delay']

    rust_log = "warn,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG"
    os.environ["RUST_LOG"] = rust_log

    for i in range(3*f + 1):
        # the first f nodes are attackers
        attack_type = 1 if i < f else 0
        session_name = f"v{i}"
        log_file = f"attack.v{i}.log.ansi"
        cmd = f"export RUST_LOG={rust_log} && {mysticeti_path} dry-attack-run --committee-size {committee_size} --authority {i} --attack-type {attack_type}  --load {load_per_node} --transaction-size {tx_size} --initial-delay {delay} > {log_file}"
        ctx.run(f"tmux new -d -s {session_name} \"{cmd}\"")

    print(f"Running benchmark for {total_time} seconds")
    print(f"Crashing the last node after {crash_time} seconds")
    time.sleep(crash_time)

    # kill the last node
    print("Crashing the last node (honest node)")
    ctx.run(f"tmux send-keys -t v{3*f}:0 C-c") # crash the last node (honest node)


    time.sleep(total_time - crash_time) # wait for the rest of the time
    ctx.run("tmux kill-server || true") 

@task
def resist(ctx):
    ''' Run benchmarks on localhost '''
    f = 3
    committee_size = 3*f + 1
    bench_params = {
        'rate': 1_000,
        'tx_size': 512,
        'delay': 0,
    }

    total_time = 100 # total time to run the benchmark
    crash_time = 20 # time to crash the honest node
    
    stuck_round = 80 # round to trigger fallback

    if not check_mysticeti_path():
        mysticeti_path = build_mysticeti()
    else:
        mysticeti_path = get_mysticeti_path()

    # clean up
    clean_resist()
    ctx.run("tmux kill-server || true") 

    load_per_node = math.ceil(bench_params['rate'] / committee_size)
    tx_size = bench_params['tx_size']
    delay = bench_params['delay']

    rust_log = "warn,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG"
    os.environ["RUST_LOG"] = rust_log
    tmux_id = "resistv"
    for i in range(3*f + 1):
        # the first f nodes are attackers
        attack_type = 1 if i < f else 0
        session_name = f"{tmux_id}{i}"
        log_file = f"resist.v{i}.log.ansi"
        cmd = f"export RUST_LOG={rust_log} && {mysticeti_path} attack-resist-run --committee-size {committee_size} --authority {i} --attack-type {attack_type}  --load {load_per_node} --transaction-size {tx_size} --initial-delay {delay} --stuck-round {stuck_round} > {log_file}"
        ctx.run(f"tmux new -d -s {session_name} \"{cmd}\"")

    print(f"Running benchmark for {total_time} seconds")
    print(f"Crashing the last node after {crash_time} seconds")
    time.sleep(crash_time)

    # kill the last node
    print("Crashing the last node (honest node)")
    ctx.run(f"tmux send-keys -t {tmux_id}{3*f-1}:0 C-c") # crash the last node (honest node)

    time.sleep(total_time - crash_time) # wait for the rest of the time
    ctx.run("tmux kill-server") 
    
@task
def plot(ctx, log_dir=".", log_prex="attack", output_path="my-inflation.pdf"):
    ''' Plot the results of the benchmark '''
    bench_params = {
        'rate': 1_000,
        'tx_size': 512,
        'block_size': 512,
    }

    print("Plotting the results, parsing logs...")
    parser = Parser(bench_params['block_size'], bench_params['tx_size'])
    parser.parse_logs(log_dir, log_prex)
    print("Parsing done, plotting...")
    commits_df, proposals_df, uncommits_df = parser.get_metrics_data()
    plotter = Plotter(proposals_df, commits_df, uncommits_df)
    plotter.plot(output_path)
