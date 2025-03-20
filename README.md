# Evaluation of Inflation Attacks on Sailfish

## Evaluation of Attack without Mitigation
Run the following command to run the protocol for **60** seconds and attack begins in **20** seconds. With the parameter *fallback-round=0*, we don't have fallback mode.
```
fab inflation --fallback-round=0
```
Get a figure named **sf-inflation.pdf**:
```
fab attackplot --output-path=sf-inflation.pdf
```

Description of parameters
```
node_params = {
    'header_size': 1_000,  # bytes
    'max_header_delay': 0,  # ms, set 0 for attack
    'gc_depth': 50,  # rounds
    'sync_retry_delay': 10_000,  # ms
    'sync_retry_nodes': 3,  # number of nodes
    'batch_size': 50_000,  # bytes
    'max_batch_delay': 200,  # ms
    'acs_timeout': 3_600_000,  # ms, we set it to 1 hour
    'fallback_round': 0,  # round to trigger fallback, 0 indicates no mitigation
    'node_types': [0]*(2*f+1) + [2]*f  # 2*f+1 honest, f attacker
}
```

## Evaluation of Attack with Mitigation
Run the following command to run the protocol for **60** seconds and attack begins in **20** seconds, and trigger fallback in *fallback_round=1000*.
> Note: for test, *fallback_round* should be set appropriately (after a node is crashed but before the test is finished). In our test, we find set fallback_round=1000 is enough.
```
fab inflation --fallback-round=1000
```
Get a figure named **sf-resist.pdf**:
```
fab attackplot --output-path=sf-resist.pdf
```

Description of parameters
```
node_params = {
    'header_size': 1_000,  # bytes
    'max_header_delay': 0,  # ms, set 0 for attack
    'gc_depth': 50,  # rounds
    'sync_retry_delay': 10_000,  # ms
    'sync_retry_nodes': 3,  # number of nodes
    'batch_size': 50_000,  # bytes
    'max_batch_delay': 200,  # ms
    'acs_timeout': 3_600_000,  # ms, we set it to 1 hour
    'fallback_round': 1000,  # round to trigger fallback, 0 indicates no mitigation
    'node_types': [0]*(2*f+1) + [2]*f  # 2*f+1 honest, f attacker
}
```