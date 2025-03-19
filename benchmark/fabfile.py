import math
import os
import time

from fabric import task

from utils import get_mysticeti_path, build_mysticeti, check_mysticeti_path, clean


@task
def inflation(c):
    ''' Run benchmarks on localhost '''
    f = 3
    committee_size = 3*f + 1
    bench_params = {
        'rate': 5_000,
        'tx_size': 512,
        'delay': 1,
    }

    total_time = 101 # total time to run the benchmark
    crash_time = 51 # time to crash the honest node

    if not check_mysticeti_path():
        mysticeti_path = build_mysticeti()
    else:
        mysticeti_path = get_mysticeti_path()

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
        c.run(f"tmux new -d -s {session_name} \"{cmd}\"")

    time.sleep(crash_time)

    c.run("curl http://0.0.0.0:1520/metrics > ./log1.txt")

    # kill the last node
    c.run(f"tmux send-keys -t v{3*f}:0 C-c") # crash the last node (honest node)


    time.sleep(total_time - crash_time) # wait for the rest of the time
    c.run("curl http://0.0.0.0:1520/metrics > ./log2.txt")
    c.run("tmux kill-server || true") 


@task
def plot(ctx):
    pass
