# cusf_enforcer — a soft-fork enforcer template

A **CUSF** ("Core Untouched Soft Fork") enforcer: a sidecar daemon that watches
an unmodified Bitcoin Core node and enforces additional consensus rules
out-of-band. When a block violates the rules, the enforcer tells the node to
`invalidateblock` it; when a mempool transaction violates them, the enforcer
keeps it out of its own template-building mempool and evicts it from the node's
mempool. Miners point at the enforcer's `getblocktemplate` server and only ever
build on rule-compliant blocks.

**This repository is a template.** It ships the full enforcer machinery with an
intentionally empty rule set — every block and transaction is accepted. Fork it,
add your soft-fork's validation logic, and you have a deployable enforcer that
composes with the rest of the CUSF stack.

## What the template provides

- **Chain sync**: headers via Bitcoin Core's REST interface (with a JSON-RPC
  fallback when REST is off), blocks via JSON-RPC or direct `blk*.dat` reads,
  `assumeutxo` support, reorg handling with automatic state rollback, and
  recovery from transient node errors (`lib/validator/`).
- **Enforcement plumbing** via the `CusfEnforcer` trait
  (`cusf-enforcer-mempool`): `connect_block` → `invalidateblock` on reject;
  `accept_tx` → mempool filtering; `validate_block` → `getblocktemplate`
  proposal mode; a `getblocktemplate` server for miners.
- **State scaffolding**: LMDB block/header store with a reversible per-block
  diff (`lib/validator/dbs/diff.rs`) — track your rule's state there and reorgs
  undo it automatically. A deterministic consensus-state digest
  (`--verify-consensus-state`) for cross-run consistency checks.
- **Wallet** (BDK; encrypted seed storage, locked start until `UnlockWallet`,
  Electrum or Esplora sync with background reconnects) and **mining** support
  (`GenerateToAddress` with in-process signet signing for regtest and signet;
  the template server for real miners).
- **gRPC API** (connect-rpc): chain and header queries, event subscriptions,
  wallet operations (`proto/cusf/`), plus the JSON-RPC `getblocktemplate`
  endpoint.
- **Integration test harness** driving real `bitcoind`, `electrs` and enforcer
  processes (`integration_tests/`; `just it-all`).

## Where to add your soft fork

1. Implement validation over transactions and blocks (your own module tree under
   `lib/validator/`).
2. Wire it into `BlockHandler::{validate_tx, connect_block_pass_through}`
   (`lib/validator/task/mod.rs`) and `CusfEnforcer::validate_block`
   (`lib/validator/enforcer.rs`) — the fork points are marked with comments.
   Rejecting a block means returning a non-fatal `error::ConnectBlock` variant;
   the driver then has Bitcoin Core `invalidateblock` it. The activation height
   comes from `NetworkParams` (`lib/types.rs`): it is resolved per fork and
   network (`--fork`), and read from `self.params.activation_height` in the
   handler.
3. Track block-derived state in `dbs::diff::Block` so reorgs roll it back.
4. If your rules need transactions that stock Core will not relay, inject them
   into mined blocks from `BlockProducer::{initial,finalize}_block_template`
   (`lib/block_producer/mod.rs`).
5. Keep eCash replay protection. Give every transaction your enforcer builds
   itself `NetworkParams::spend_lock_time` and `types::input_sequence`, as the
   wallet's sends already do. If your rules execute `OP_CHECKLOCKTIMEVERIFY`,
   fail it when `NetworkParams::cltv_rejects_lock_time` holds, as eCash nodes
   do.
6. Add integration trials to `integration_tests/` and wire them into
   `just it-all`.
7. Rename the crates/binary (`cusf_enforcer` → `your_enforcer`) if desired.

To run **several soft forks against one node**, run each fork's enforcer as its
own validator-only process — each independently invalidates blocks that violate
its rules — and point miners at exactly one enforcer's `getblocktemplate`
server.

## Build and test

```bash
just build          # debug build
just test           # fmt + clippy + unit tests (needs cargo-nextest + nightly rustfmt)
just verify         # pre-submit subset without nextest
just setup-core     # download stock Bitcoin Core; write integrationtests.env
just setup-ecash    # download the eCash node; write integrationtests.ecash-mainnet.env
just it-all         # integration trials against real bitcoind
just it <trial>     # one trial by name
```

The wallet trials need an `electrs` binary; point `integrationtests.env` at one
(see `integration_tests/example.env`).

## Requirements

A stock Bitcoin Core or eCash node with the ZMQ `pubsequence` notifier enabled,
the REST interface (`-rest`) on (or the JSON-RPC fallback accepted), and
`-txindex` when running with a wallet. The node must not be pruned; the enforcer
checks this at startup. The three latest major Bitcoin Core versions are
supported; the set lives in [`lib/version.rs`](./lib/version.rs) and `--help`
documents the override flags.

The enforcer detects an eCash node from its user agent and takes that fork's
parameters: magics, activation height and replay-protection lock time. The
alphanet and betanet builds report a stock user agent, so `--fork` selects them;
a `--fork` that contradicts an eCash user agent is refused. Data and logs live
under `<data-dir>/<fork>/<chain>`.
