# Integration tests

Trials drive real processes — `bitcoind`, `electrs` and the enforcer binary —
via a `libtest-mimic` harness.

## Setup

```bash
just setup-core   # downloads Bitcoin Core, writes integrationtests.env (export ELECTRS too)
```

or point the harness at binaries you already have:

```bash
export CUSF_ENFORCER_INTEGRATION_TEST_ENV=$PWD/integration_tests/example.env
```

Env vars (see `example.env`): `CUSF_ENFORCER`, `BITCOIND`, `BITCOIND_FORK`,
`ELECTRS`.

To run against an eCash build instead of Bitcoin Core:

```bash
just setup-ecash          # fetches the latest eCash release, writes integrationtests.ecash-mainnet.env
CUSF_ENFORCER_INTEGRATION_TEST_ENV=integrationtests.ecash-mainnet.env just it-all
```

`BITCOIND_FORK` names the build, and every enforcer the harness starts gets it
as `--fork`.

## Running

```bash
just it-all               # every trial
just it <trial-name>      # one trial
cargo run --example integration_tests -- --list   # list trial names
```

Every trial that goes through `PostSetup::setup` starts electrs. The trials that
start their own bitcoind and enforcer (`file_based_block_parser`,
`mempool_dat_sync`, `assumeutxo_*`, `pruned_node`) run without it.
