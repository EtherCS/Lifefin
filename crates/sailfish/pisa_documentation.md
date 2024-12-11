# Pisa Documentation

## Main Functionalities
I will show them in the order of the file structure of the github.

**In config/lib.rs:**

- [`majority_threshold`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/config/src/lib.rs#L183)

    Give us the value of $\left\lceil \frac{n + f + 1}{2} \right\rceil$

**In primary/acs_fin.rs:**

- [`decide`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L131)

    This function set the variable decide (whether this node has decided yet or not) to true and broadcast the decision message to the other nodes.
- [`try_decide_round_0`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L204)

    After receiving n - f aux(*, *) messages this function is called to check whether this primary can decide ( if $V_2(vals_r, b) \ge \left\lceil \frac{n + f + 1}{2} \right\rceil$ and  $b = 1$). It also updates the values of $est_{r + 1}$ and  $maj_{r+1}$.
- [`try_decide`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L226)

    This function is also called after receiving n - f aux(*, *) messages and perform all the checks, like if $V_2(vals_r, b) \ge \left\lceil \frac{n + f + 1}{2} \right\rceil$ or if ($V_1(vals_r) = \perp$ or $V_2(vals_r, b) < \left\lceil \frac{n + f + 1}{2} \right\rceil$) or if $est_{r+1}$ has not been set yet, in order to check if the node can decide in a round  > 0. 
- [`advance_round`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L310)

    Reset all the variables that are bounded to a round and perform the default part of pillar protocol for every single round which is broadcast $bval_r(est_r, maj_r)$.

**In primary/aggregators.rs:**

Here we have structs that help the node to save the $bval_r$ and $aux_r$ messages that he has received for a round.

- [`PisaBvalAggregator`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/aggregators.rs#L180)

    - `append`: Saves the $bval_r(b, *)$ messages. It separates the messages were b = 1 and b = 0. To make sure that the $f + 1$ $bval_r(b, *)$ messages have the same value for b. It returns true if this is achieved.
    - `enough_bvals_for_quorum`: check if we have at least $2f + 1$  $bval_r(1, *)$ or $bval(0, *)$ messages.

- [`PisaAuxAggregator`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/aggregators.rs#L236)

    - `append`: Saves the $aux_r(*, *)$ messages. It returns true if the node has received $n - f$ or $2f + 1$ messages.
    - `get_vals_round`: For the messages $aux_r(v1, v2)$ it returns a vector of all the v1 values of the messages it has already received.
    - `get_avals_round`: For the messages $aux_r(v1, v2)$ it returns a vector of all the v2 values of the messages it has already received.

- [`PisaDecisionAggregator`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/aggregators.rs#L287)

    - `append`: Saves the decision messages that a node has received and separates the messages with decision 1 and the ones with decision 0. It returns true if it has received $2f + 1$ decision messages with the same value.

**In primary/core.rs:**

- [`switch_to_fallback_mode`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/core.rs#L493)

    Switch the consensus mode of the node to fallback mode and perform the default behavior of the pisa protocol for round 0.

- [`switch_to_optimistic_mode`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/core.rs#L545)

    Switch the consensus mode of the node to optimistic and processes all the messages that were buffered when changed to fallback mode.

- [`process_pisa_bval`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/core.rs#L598C14-L598C31)

    Manage the bval message reception and decides to process it with the pisa protocol (if we are in round 0) or with the pillar protocol (round > 0).

- [`process_pisa_bval_start`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/core.rs#L609C14-L609C37)

    Aggregates the bval message with the respective aggregator and performs the behavior if we have $f + 1$ $bval_r(b, *)$ messages or if we have $n - f$ $bval_r(b, *)$ messages for round 0.

- [`process_pillar_bval`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/core.rs#L711C14-L711C33)

    Aggregates the bval message with the respective aggregator and performs the behavior if we have $f + 1$ $bval_r(b, *)$ messages or if we have $n - f$ $bval_r(b, *)$ messages for round > 0.

- [`process_pisa_aux`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/core.rs#L804C14-L804C30)

    Manage the aux message reception and decides to process it with the pisa protocol (if we are in round 0) or with the pillar protocol (round > 0).

- [`process_pisa_aux_start`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/core.rs#L814C14-L814C36)

    Aggregates the aux message and if it has $n - f$ messages with the *try_decide_round_0* function of *acs_fin.rs* checks if it can decide and does it or just advance round.

- [`process_pillar_aux`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/core.rs#L861C14-L861C32)

    Aggregates the aux message and if it has $n - f$ messages with the *try_decide* function of *acs_fin.rs* checks if it can decide and does it or just advance round. This behaviour if for the rounds > 0.

- [`process_pisa_desicion`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/core.rs#L912)

    It manages the decision messages reception and aggregates them. If we have $2f + 1$ decision messages wwith the same value if the node hasn't already decide it decide and switch to optimistic mode.

## Extra Functionalities

**In primary/acs_fin.rs:**

- [`propose`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L58): Set the intial values of the pisa protocol.
- [`create_bval_message `](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L63C12-L63C32): Creates a $bval_r(b, b)$ message.
- [`create_aux_message  `](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L70C12-L70C31): Creates a $aux_r(v1, v2)$ message.
- [`add_bin_value`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L77): Adds a binary value to the list of bin_values for a round.
- [`add_maj_value`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L86): Adds a binary value to the list of majs for a round.
- [`broadcast_bval_message`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L95C18-L95C40): Broadcasts a $bval_r(b, b)$ message.
- [`broadcast_aux_message`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L113): Broadcasts a $aux_r(v1, v2)$ message.
- [`v2_check`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L155C8-L155C16): Perfoms the *V2(list, binary_value)* operation.
- [`v1_check`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L171): Perfoms the *V1(list)* operation.
- [`majority`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L188): Perfoms the *majority(list)* operation.
- [`coin`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L329): Returns the coin of a round.
- [`delta_b`](https://github.com/EtherCS/dagACS/blob/4a975bc933dcadcfe7b29cbd9d2b750744e3ae76/crates/sailfish/primary/src/acs_fin.rs#L333C12-L333C19): Gives th value of $\delta_r(b)$ based on the conditions it must check.