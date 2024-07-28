# bash

# set the repo directory
WORKSPACE=$(git rev-parse --show-toplevel)

# enter bullshark test
cd $WORKSPACE/crates/bullshark/benchmark

# test bullshark locally
fab local