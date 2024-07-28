# bash

# set the repo directory
WORKSPACE=$(git rev-parse --show-toplevel)

# enter tusk test
cd $WORKSPACE/crates/tusk/benchmark

# test tusk locally
fab local