# cusf_enforcer

A template for building a **CUSF** ("Core Untouched Soft Fork") enforcer: a
daemon that runs beside an unmodified Bitcoin Core or eCash node and enforces
additional consensus rules on its behalf.

The template ships the complete enforcer machinery with an empty rule set, so as
built it accepts every block and every transaction. You add your rules at a
handful of marked points, and the result is a deployable enforcer for your soft
fork.

## How an enforcer works

The node stays stock. The enforcer does four things around it:

- **Follows the chain.** It reads headers over REST, or JSON-RPC when REST is
  off, blocks over JSON-RPC or straight from `blk*.dat`, and new tips over ZMQ
  `sequence`. Every block runs through your rules as it connects. A block that
  breaks them is `invalidateblock`ed on the node, which then follows the best
  valid chain.
- **Filters the mempool.** It keeps its own mempool, admitting only transactions
  your rules accept. A rejected transaction is deprioritised on the node with
  `prioritisetransaction` and a fee delta of −21 million BTC, so the node's own
  templates never pick it up.
- **Serves block templates.** Miners call its `getblocktemplate` server, which
  builds templates from the filtered mempool. Blocks mined that way follow your
  rules.
- **Survives reorgs.** State your rules derive from blocks is recorded per block
  and undone when the block disconnects.

A miner that mines from the node directly can still produce blocks your rules
reject. The enforcer invalidates those on every node that runs it.

Optional parts switch on with flags:

| Flag                             | Adds                                                                                   |
| -------------------------------- | -------------------------------------------------------------------------------------- |
| `--enable-mempool`               | the filtered mempool                                                                   |
| `--enable-block-template-server` | `getblocktemplate` on `--serve-rpc-addr` (default `127.0.0.1:8122`); needs the mempool |
| `--enable-wallet`                | a BDK wallet with an encrypted seed, synced over Esplora or Electrum                   |

The gRPC API on `--serve-grpc-addr` (default `127.0.0.1:50051`) serves
`ValidatorService`, `WalletService`, `MiningService` and `CryptoService` from
[`proto/cusf/`](./proto/cusf), plus health and reflection.

## Running on eCash

### Get a node

The enforcer supports the eCash node `ecash-v1.0.0-core31.1` from
[releases.ecash.com](https://releases.ecash.com). The setup recipe downloads a
release, verifies its build provenance and installs it under
`.integration-deps/bitcoin-ecash-<channel>/`:

```bash
just setup-ecash            # eCash mainnet
just setup-ecash alphanet
just setup-ecash betanet
```

### Start the node

```bash
bitcoind -server -rest -txindex \
  -zmqpubsequence=tcp://127.0.0.1:29000 \
  -rpcuser=user -rpcpassword=password
```

- The node must not be pruned. The enforcer checks at startup.
- `-txindex` is needed only with `--enable-wallet`.
- Without `-rest` the enforcer falls back to JSON-RPC for headers, which is
  slower.
- The enforcer finds the ZMQ endpoint through `getzmqnotifications`, or from
  `--node-zmq-addr-sequence`.

### Start the enforcer

```bash
cusf_enforcer \
  --node-rpc-addr=127.0.0.1:8332 \
  --node-rpc-user=user --node-rpc-pass=password \
  --enable-mempool --enable-block-template-server \
  --coinbase-recipient=<address>
```

`--node-rpc-addr` defaults to the regtest port, so set it on every other chain.

The enforcer works out which fork the node runs:

- **eCash mainnet** is detected from the node's user agent, which starts with
  `/eCash`.
- **Alphanet and betanet** report the same user agent as Bitcoin Core. Pass
  `--fork=ecash-alphanet` or `--fork=ecash-betanet`. Without it the enforcer
  runs with Bitcoin's parameters, including no replay protection.
- A `--fork` that contradicts the node's user agent is refused at startup.

Data lives under `<data-dir>/<fork>/<chain>`, for example `ecash/mainnet`, with
logs in its `logs` directory.

### What the enforcer takes from the fork

Each fork's parameters live in `NetworkParams::new` in
[`lib/types.rs`](./lib/types.rs):

| Fork           | `--fork`         | Mainnet activation height | Mainnet magic | Replay nLockTime |
| -------------- | ---------------- | ------------------------- | ------------- | ---------------- |
| Bitcoin        | `bitcoin`        | 0                         | stock         | none             |
| eCash          | `ecash`          | 973,728                   | `eca5dcb7`    | 499,999,998      |
| eCash alphanet | `ecash-alphanet` | 963,648                   | `eca5a104`    | 499,999,999      |
| eCash betanet  | `ecash-betanet`  | 967,680                   | `eca5b104`    | 499,999,999      |

- **Activation height.** Blocks below it are recorded but not run through your
  rules. Test chains activate at 0. If your soft fork activates later than the
  fork itself, change the height there.
- **Magic.** eCash test chains use `eca5 <fork byte> <chain byte>`: fork byte
  `a1` on alphanet and `b1` on eCash and betanet, chain byte `14` testnet, `24`
  testnet4, `34` regtest. eCash signets hash an `ecash` tag ahead of the
  challenge.

### Replay protection

eCash nodes treat a transaction whose nLockTime is the fork's replay value as
final. Bitcoin treats the same value as a lock until a block height thousands of
years away, so it never relays or mines that transaction. Bitcoin ignores
nLockTime when every input's nSequence is `0xffffffff`, so at least one input
must be non-final for the protection to hold.

eCash also changes `OP_CHECKLOCKTIMEVERIFY`: it fails, whatever its argument, in
a transaction carrying the replay value. That value is larger than any real
block height, so it would otherwise satisfy every height lock. A spend of a
CLTV-locked output therefore cannot carry replay protection through nLockTime.

What this means for your enforcer:

- **Transactions it builds** take `NetworkParams::spend_lock_time()` as
  nLockTime and `types::input_sequence()` as each input's nSequence. The
  wallet's sends already do, in `Wallet::apply_replay_protection`.
- **Script your rules execute** must fail `OP_CHECKLOCKTIMEVERIFY` when
  `NetworkParams::cltv_rejects_lock_time()` holds. This matters most for script
  the node itself never runs, where the enforcer is the only check.

On Bitcoin all three helpers are no-ops.

### The `getblocktemplate` rule

eCash nodes refuse template requests that do not acknowledge the rule
`bip300301`, unless started with `-deprecatedrpc=getblocktemplate`. They also
mark their templates `!bip300301`, which tells mining software that does not
know the rule to refuse them.

The enforcer acknowledges the rule in its own requests and strips `!bip300301`
from the templates it serves, so stock mining software accepts them. Bitcoin
Core ignores rules it does not know. The string is
`rpc_client::ECASH_TEMPLATE_RULE`.

## Building your enforcer

### 1. Rename

This step is optional. The recipe renames the crates, binary, environment
variables, Docker image and CI artifacts. It leaves the `cusf_enforcer_mempool`
dependency, its `cusf_enforcer` module and the `CusfEnforcer` trait alone.

```bash
new=my_enforcer
dash="${new//_/-}"
upper="$(printf '%s' "$new" | tr '[:lower:]' '[:upper:]')"
git grep -lz -E 'cusf_enforcer|cusf-enforcer|CUSF_ENFORCER' -- . ':!Cargo.lock' ':!lib/proto/generated' |
  xargs -0 perl -pi -e "
    s/(?<![\w-])cusf_enforcer(?=_lib|_integration_tests)/$new/g;
    s/code\(cusf_enforcer::/code($new::/g;
    s/(?<![\w-])cusf_enforcer(?![\w-]|::)/$new/g;
    s/CUSF_ENFORCER/$upper/g;
    s/cusf-enforcer(?!-mempool)/$dash/g;
  "
cargo update --workspace
just fmt
just verify
```

Change the GitHub organisation in the Docker image name in
[`.github/workflows/build_docker.yaml`](./.github/workflows/build_docker.yaml)
by hand.

### 2. Write your rules

Put them in your own module tree under `lib/validator/`. Rules written as
functions of the block or transaction, the height, `NetworkParams` and your own
state are easy to call from every hook below.

### 3. Wire the hook points

Each hook is marked with a `Fork point` comment.

| Hook                                                   | File                                                       | Runs                                      | To reject                                  |
| ------------------------------------------------------ | ---------------------------------------------------------- | ----------------------------------------- | ------------------------------------------ |
| `BlockHandler::connect_block_pass_through`             | [`lib/validator/task/mod.rs`](./lib/validator/task/mod.rs) | every block, during initial sync and live | return a non-fatal `error::ConnectBlock`   |
| `BlockHandler::validate_tx`                            | [`lib/validator/task/mod.rs`](./lib/validator/task/mod.rs) | every transaction offered to the mempool  | return `Ok(false)`                         |
| `CusfEnforcer::validate_block`                         | [`lib/validator/enforcer.rs`](./lib/validator/enforcer.rs) | `getblocktemplate` proposals, read-only   | return `Ok(Some(reason))`                  |
| `CusfBlockProducer::{initial,finalize}_block_template` | [`lib/block_producer/mod.rs`](./lib/block_producer/mod.rs) | building each served template             | not a check: injects your own transactions |

- **Gate on activation.** Skip your rules while
  `height < self.params.activation_height`.
- **Call your rules from `validate_block` too.** As shipped it runs nothing, so
  a proposal would pass even when connecting the same block would fail. Validate
  against height `tip_height + 1`, and fail closed on anything it cannot resolve
  locally.
- **Inject transactions** the node will not relay by reserving their weight in
  `initial_block_template` through `template.suffix_txs`, then appending them in
  `finalize_block_template`.

### 4. Tell rejections apart from failures

`error::ConnectBlock` in
[`lib/validator/task/error.rs`](./lib/validator/task/error.rs) marks every
variant with `#[fatal(...)]`:

- `#[fatal(false)]` means the block is invalid. The enforcer has the node
  `invalidateblock` it.
- `#[fatal(true)]` means the enforcer could not decide, for example on a
  database or I/O error. Sync stops, and the block is never invalidated.

```rust
#[error("transaction `{txid}` breaks my rule")]
#[fatal(false)]
MyRuleViolated { txid: bitcoin::Txid },
```

Never mark a failure to fetch or read data as non-fatal. The node has already
accepted the block, so the enforcer would invalidate a block its peers accept.

### 5. Keep state reorg-safe

- Add your tables to `Dbs` in
  [`lib/validator/dbs/mod.rs`](./lib/validator/dbs/mod.rs), and raise `NUM_DBS`
  to match.
- Record every change a block makes as fields of `diff::Block` in
  [`lib/validator/dbs/diff.rs`](./lib/validator/dbs/diff.rs). `apply` writes
  them on connect and `undo` reverses them on disconnect.
- Raise `DB_VERSION` whenever tables or encodings change. A datadir from another
  version refuses to open and has to be resynced, since all state is derived
  from the chain.

### 6. Get the outputs transactions spend

The hooks see the block or transaction and your own state. They do not see the
outputs being spent. If your rules need input amounts or scripts, either index
those outputs yourself as reorg-safe state, or fetch them from the node before
connecting the block. `getblock <hash> 3` returns every input's prevout without
`-txindex`. A failed fetch is fatal, as in step 4.

### 7. Add integration trials

Trials drive real `bitcoind`, `electrs` and enforcer processes.

1. Write
   `pub async fn test_my_rule(post_setup: PostSetup) -> anyhow::Result<()>` in
   `integration_tests/test_my_rule.rs`, and declare the module in
   `integration_tests/lib.rs`.
2. Register it in `tests()` in
   [`integration_tests/integration_test.rs`](./integration_tests/integration_test.rs).
3. Add its name to the `it-all` list in the [`Justfile`](./Justfile).

The hidden `--activation-height` flag overrides the activation height, so a
trial can mine below and above it on a fresh chain.

Run every trial against both nodes before shipping:

```bash
just setup-core
just it-all

just setup-ecash
export ELECTRS=/path/to/electrs
CUSF_ENFORCER_INTEGRATION_TEST_ENV=integrationtests.ecash-mainnet.env just it-all
```

## Several soft forks on one node

Run one enforcer per soft fork against the same node. Each one invalidates
blocks that break its own rules.

A template server filters only by its own enforcer's rules. Miners mining from
one fork's server can include transactions that another fork rejects, and that
fork's enforcer will then invalidate the block. To mine safely under several
soft forks, run all their rule sets in one enforcer.

## Build and test

```bash
just build          # debug build
just verify         # fmt check, unit tests, clippy, integration-harness build
just test           # fmt check, clippy, all unit tests through cargo-nextest
just setup-core     # download stock Bitcoin Core; write integrationtests.env
just setup-ecash    # download the eCash node; write integrationtests.ecash-mainnet.env
just it-all         # every integration trial
just it <trial>     # one integration trial by name
just generate       # regenerate lib/proto/generated/ from proto/
```

The tools: a Rust toolchain plus nightly `rustfmt`, `cargo-nextest` for
`just test`, `buf` for `just generate`, and an `electrs` binary for the wallet
trials, set through `ELECTRS` or `integrationtests.env`. See
[`integration_tests/README.md`](./integration_tests/README.md).

## Requirements

- **Node:** Bitcoin Core 29, 30 or 31, or eCash `ecash-v1.0.0-core31.1`, which
  reports Core 31. The supported set lives in
  [`lib/version.rs`](./lib/version.rs), and `--help` documents the override
  flags.
- **ZMQ:** the `pubsequence` notifier enabled.
- **REST:** `-rest` on, or the slower JSON-RPC fallback accepted.
- **Indexes:** `-txindex` when running with `--enable-wallet`.
- **Pruning:** none. The enforcer syncs full blocks from genesis.
- **Wallet sync:** an Esplora or Electrum server for the same chain, on any
  chain other than regtest.
