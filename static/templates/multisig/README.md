# Multisig Template

This template requires the current owner quorum for payments, adding an
owner, and changing the threshold. It is an example, not an independently
audited custody product.

## Setup

Deploy with constructor arguments `[first, second, third, threshold]`, where
the first three values are distinct Octra addresses and the threshold is an
integer from 1 to 3. Use threshold 2 for a two-of-three wallet. All owners and
the threshold are installed in the same deployment; there is no single-owner
setup interval. The deployment sender is not automatically an owner.

Verify the committed owner addresses and threshold before funding. A threshold
of 1 deliberately permits any single owner to act. Adding more owners, up to
five in total, requires an approved `add_owner(address)` proposal.

## Proposals

`propose(target, amount, description)` creates a payment proposal. Creation
does not cast a vote. Distinct current owners call `vote(id)`; the final
required vote executes the action. A payment uses native base units.

`add_owner` and `set_threshold` no longer change configuration immediately
or return a boolean. They return proposal IDs and require the same approval
process as payments. Configuration changes use the quorum in force before
the change, never the proposed new threshold.

An executed configuration change invalidates every other unfinished
proposal, including existing approvals. Recreate and approve the intended
actions under the new configuration. Missing IDs, duplicate votes and
repeated execution are refused. If a payment fails, the transaction rolls
back its final vote and can be retried after funding.

## Trust And Compatibility

The node still permits the deployment owner to replace a program through
the system upgrade operation. Template voting does not govern that separate
authority. Users must trust the deployment owner; this template must not be
presented as enforcing a quorum against a malicious deployment owner.

This source update changes the constructor arguments, not any deployed
program. Do not replace an old instance in place: stored proposals and owner
configuration belong to its original rules. Deploy a new instance and move
funds only through an action approved under the old instance's rules.

## Local Check

From `webcli`, run `sh tests/multisig.sh`. It compiles the actual template
with the node compiler and executes it with the node VM, transaction journals
and ledger in an isolated local store. The check covers governance,
payments, old approvals, missing IDs, duplicates and rollback. It does not
connect to a network or validate a live deployment.

The same check verifies `tests/Multisig.v` without axioms. Its abstract voting
model proves distinct eligible approvals, the execution quorum, refusal of a
repeated vote and isolation across configuration changes. This is not a
proof of the compiler, the VM, or the system upgrade policy; those are
separate from the model.