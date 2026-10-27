//! Registration of every integration trial, and the helpers they share.

use std::{convert::Infallible, future::Future, panic::AssertUnwindSafe};

use cusf_enforcer_lib::proto::mainchain::{
    CreateNewAddressRequest, GetChainTipRequest, GetInfoRequest,
};
use futures::{FutureExt as _, channel::mpsc};
use jsonrpsee::{core::client::ClientT as _, rpc_params};
use tracing::Instrument as _;

use crate::{
    mine::mine_signet_check,
    setup::{
        Directories, EnforcerWallet, Mode, Network, PostSetup, PreSetup, SetupOpts, wait_until,
    },
    util::{AsyncTrial, BinPaths, FileDumpConfig, TestFailureCollector, TestFileRegistry},
};

type TestFuture = std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;
type TestTrial = AsyncTrial<TestFuture>;

struct TestSetupComponents {
    bin_paths: BinPaths,
    network: Network,
    mode: Mode,
    file_registry: TestFileRegistry,
    failure_collector: TestFailureCollector,
}

fn register_files(file_registry: &TestFileRegistry, name: &str, directories: &Directories) {
    // Register specific files with their own configurations
    file_registry.register_file(
        name,
        directories.bitcoin_dir.join("stdout.txt"),
        FileDumpConfig::new().with_label("Bitcoin Core stdout"),
    );

    file_registry.register_file(
        name,
        directories.bitcoin_dir.join("stderr.txt"),
        FileDumpConfig::new().with_label("Bitcoin Core stderr"),
    );

    file_registry.register_file(
        name,
        directories.enforcer_dir.join("stdout.txt"),
        FileDumpConfig::new().with_label("Enforcer stdout"),
    );

    file_registry.register_file(
        name,
        directories.enforcer_dir.join("stderr.txt"),
        FileDumpConfig::new().with_label("Enforcer stderr"),
    );
}

async fn catch_unwind<Fut>(test_future: Fut) -> anyhow::Result<()>
where
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    match AssertUnwindSafe(test_future).catch_unwind().await {
        Ok(result) => result,
        Err(panic_payload) => {
            // Convert panic to an error
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            Err(anyhow::anyhow!("Test panicked: {panic_msg}"))
        }
    }
}

/// For tests that start their own bitcoind (and enforcer) from a
/// [`PreSetup`], because the processes need arguments or paths only known
/// once the temp dirs exist.
fn new_trial<F, Fut>(
    name: impl Into<String>,
    network: Network,
    bin_paths: &BinPaths,
    file_registry: &TestFileRegistry,
    failure_collector: &TestFailureCollector,
    test_fn: F,
) -> TestTrial
where
    F: FnOnce(PreSetup) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let name: String = name.into();
    let bin_paths = bin_paths.clone();
    let registry = file_registry.clone();
    AsyncTrial::new(
        name.clone(),
        Box::pin(async move {
            let pre_setup = PreSetup::new(bin_paths, network)?;

            register_files(&registry, &name, &pre_setup.directories);

            let test_future =
                test_fn(pre_setup).instrument(tracing::info_span!("test", name = %name));

            catch_unwind(test_future).await
        }),
        file_registry.clone(),
        failure_collector.clone(),
    )
}

fn new_trial_with_setup<F, Fut>(name: String, comps: TestSetupComponents, test_fn: F) -> TestTrial
where
    F: FnOnce(PostSetup) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    new_trial_with_setup_opts(name, comps, Default::default(), test_fn)
}

/// Like [`new_trial_with_setup`], for tests that need non-default
/// [`SetupOpts`] (e.g. extra enforcer CLI flags).
fn new_trial_with_setup_opts<F, Fut>(
    name: String,
    comps: TestSetupComponents,
    setup_opts: crate::setup::SetupOpts,
    test_fn: F,
) -> TestTrial
where
    F: FnOnce(PostSetup) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let file_registry = comps.file_registry.clone();
    AsyncTrial::new(
        name.clone(),
        Box::pin(async move {
            let (res_tx, _) = mpsc::unbounded();
            let pre_setup = PreSetup::new(comps.bin_paths.clone(), comps.network)?;
            register_files(&file_registry, &name, &pre_setup.directories);
            let post_setup = pre_setup.setup(comps.mode, setup_opts, res_tx).await?;

            let test_future =
                test_fn(post_setup).instrument(tracing::info_span!("test", name = %name));

            catch_unwind(test_future).await
        }) as TestFuture,
        comps.file_registry,
        comps.failure_collector,
    )
}

/// For tests that need direct [`BinPaths`] (to respawn the enforcer or
/// electrs mid-test) and therefore run their own setup, rather than going
/// through [`new_trial_with_setup`].
fn new_bespoke_trial<F, Fut>(
    name: impl Into<String>,
    bin_paths: &BinPaths,
    file_registry: &TestFileRegistry,
    failure_collector: &TestFailureCollector,
    test_fn: F,
) -> TestTrial
where
    F: FnOnce(BinPaths) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let name: String = name.into();
    AsyncTrial::new(
        name.clone(),
        Box::pin({
            let bin_paths = bin_paths.clone();
            async move {
                let test_future =
                    test_fn(bin_paths).instrument(tracing::info_span!("test", name = %name));
                catch_unwind(test_future).await
            }
        }) as TestFuture,
        file_registry.clone(),
        failure_collector.clone(),
    )
}

/// Block until the validator's reported chain tip reaches bitcoind's height.
pub async fn wait_for_validator_tip(post_setup: &PostSetup) -> anyhow::Result<()> {
    let target_height: u32 = post_setup
        .bitcoind_client
        .request("getblockcount", rpc_params![])
        .await?;
    wait_until(
        &format!("validator tip reaches height {target_height}"),
        || async {
            let tip_height = post_setup
                .validator_service_client
                .get_chain_tip(GetChainTipRequest::default())
                .await?
                .into_owned()
                .block_header_info
                .into_option()
                .map(|info| info.height)
                .unwrap_or(0);
            Ok(tip_height >= target_height)
        },
    )
    .await
}

/// Wait until the enforcer wallet has applied every block Bitcoin Core has
/// mined. The wallet connects blocks as the node advances, so poll its tip
/// until it has caught up rather than sleeping a fixed duration — this returns
/// as soon as the wallet is in sync, and fails loudly if it never catches up.
pub async fn wait_for_wallet_sync(post_setup: &mut PostSetup) -> anyhow::Result<()> {
    let target_height: u32 = post_setup
        .bitcoind_client
        .request("getblockcount", rpc_params![])
        .await?;
    tracing::debug!("Waiting for wallet to sync to block {target_height}");
    wait_until(
        &format!("wallet tip reaches height {target_height}"),
        || async {
            let wallet_height = post_setup
                .wallet_service_client
                .get_info(GetInfoRequest::default())
                .await?
                .into_owned()
                .tip
                .into_option()
                .map(|tip| tip.height)
                .unwrap_or(0);
            Ok(wallet_height >= target_height)
        },
    )
    .await
}

pub async fn fund_enforcer(post_setup: &mut PostSetup) -> anyhow::Result<()> {
    const BLOCKS: u32 = 100;
    tracing::info!("Funding enforcer");
    let () = match post_setup.network {
        Network::Regtest => {
            let address = post_setup
                .wallet_service_client
                .create_new_address(CreateNewAddressRequest::default())
                .await?
                .into_owned()
                .address;

            crate::util::node_rpc(
                &post_setup.bitcoind_client,
                "generatetoaddress",
                [BLOCKS.to_string(), address],
            )
            .await?;
        }
        Network::Signet => {
            mine_signet_check::<_, Infallible>(post_setup, BLOCKS, |_| Ok(())).await?;
        }
    };
    tracing::debug!("Waiting for wallet sync...");
    let () = wait_for_wallet_sync(post_setup).await?;
    Ok(())
}

pub fn tests(
    bin_paths: &BinPaths,
    file_registry: TestFileRegistry,
    failure_collector: TestFailureCollector,
) -> Vec<TestTrial> {
    let components = |network, mode| TestSetupComponents {
        bin_paths: bin_paths.clone(),
        network,
        mode,
        file_registry: file_registry.clone(),
        failure_collector: failure_collector.clone(),
    };
    let mut async_trials = vec![
        new_trial(
            "file_based_block_parser",
            Network::Regtest,
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_file_based_block_parser::test_file_based_block_parser,
        ),
        new_bespoke_trial(
            "gbt_during_initial_sync",
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_gbt_during_initial_sync::test_gbt_during_initial_sync,
        ),
        new_trial_with_setup_opts(
            "gbt_rule_ack".to_owned(),
            components(Network::Regtest, Mode::GetBlockTemplate),
            SetupOpts {
                enforcer_wallet: EnforcerWallet::Disabled,
                ..SetupOpts::default()
            },
            crate::test_gbt_rule_ack::test_gbt_rule_ack,
        ),
    ];
    // Mines from templates served by the enforcer's own `getblocktemplate`
    // server. On signet, the node's wallet also signs.
    async_trials.extend([Network::Regtest, Network::Signet].map(|network| {
        new_trial(
            format!("generate_to_address (mode: GetBlockTemplate, network: {network})"),
            network,
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_generate_to_address::test_generate_to_address,
        )
    }));
    async_trials.extend([
        new_trial(
            "generate_to_address_requires_template_server",
            Network::Regtest,
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_generate_to_address::test_generate_to_address_requires_template_server,
        ),
        new_trial(
            "mempool_dat_sync",
            Network::Regtest,
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_mempool_dat_sync::test_mempool_dat_sync,
        ),
        new_trial_with_setup_opts(
            "no_secrets_in_logs".to_owned(),
            components(Network::Regtest, Mode::Mempool),
            SetupOpts {
                wallet_mnemonic: Some(crate::test_no_secrets_in_logs::MNEMONIC.to_owned()),
                ..SetupOpts::default()
            },
            crate::test_no_secrets_in_logs::test_no_secrets_in_logs,
        ),
        // Nodes the enforcer must refuse or follow specially (pruned,
        // assumeutxo), spawned by the tests themselves.
        new_trial(
            "assumeutxo_node",
            Network::Regtest,
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_node_requirements::test_assumeutxo_node,
        ),
        new_trial(
            "assumeutxo_enforcer_above_snapshot_base",
            Network::Regtest,
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_node_requirements::test_assumeutxo_enforcer_above_snapshot_base,
        ),
        new_trial(
            "pruned_node",
            Network::Regtest,
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_node_requirements::test_pruned_node,
        ),
        new_trial(
            "fork_mismatch",
            Network::Regtest,
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_node_requirements::test_fork_mismatch,
        ),
        new_trial_with_setup(
            "replay_protection (mode: GetBlockTemplate)".to_owned(),
            components(Network::Regtest, Mode::GetBlockTemplate),
            crate::test_replay_protection::test_replay_protection,
        ),
        new_trial_with_setup(
            "replay_protection (mode: Mempool)".to_owned(),
            components(Network::Regtest, Mode::Mempool),
            crate::test_replay_protection::test_replay_protection,
        ),
        new_trial_with_setup_opts(
            "rest_disabled_header_sync".to_owned(),
            components(Network::Regtest, Mode::NoMempool),
            SetupOpts {
                bitcoind_args: vec!["-norest".to_owned()],
                enforcer_wallet: EnforcerWallet::Disabled,
                ..SetupOpts::default()
            },
            crate::test_rest_disabled_header_sync::test_rest_disabled_header_sync,
        ),
        new_trial_with_setup_opts(
            "testmempoolaccept_no_insert".to_owned(),
            components(Network::Regtest, Mode::NoMempool),
            SetupOpts {
                bitcoind_args: vec!["-fallbackfee=0.0002".to_owned()],
                enforcer_wallet: EnforcerWallet::Disabled,
                ..SetupOpts::default()
            },
            crate::test_testmempoolaccept_no_insert::test_testmempoolaccept_no_insert,
        ),
        new_trial_with_setup(
            "unconfirmed_transactions (mode: Mempool, network: Regtest)".to_owned(),
            components(Network::Regtest, Mode::Mempool),
            crate::test_unconfirmed_transactions::test_unconfirmed_transactions,
        ),
        new_bespoke_trial(
            "wallet_encrypted_restart",
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_wallet_encrypted_restart::test_wallet_encrypted_restart,
        ),
        new_bespoke_trial(
            "wallet_large_gap_sync",
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_wallet_large_gap_sync::test_wallet_large_gap_sync,
        ),
        new_trial(
            "wallet_less_block_template",
            Network::Regtest,
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_wallet_less_block_template::test_wallet_less_block_template,
        ),
        new_bespoke_trial(
            "wallet_reorg_multi_block",
            bin_paths,
            &file_registry,
            &failure_collector,
            crate::test_wallet_reorg_multi_block::test_wallet_reorg_multi_block,
        ),
    ]);
    // Both sync tasks consume the same sequence stream and both die on a gap
    // in it, so both need to recover: `Mempool` drives the mempool sync task,
    // `NoMempool` the tip-chasing task that is the default mode.
    async_trials.extend([Mode::Mempool, Mode::NoMempool].map(|mode| {
        new_trial_with_setup_opts(
            format!("zmq_sequence_gap (mode: {mode})"),
            components(Network::Regtest, mode),
            SetupOpts {
                bitcoind_args: crate::test_zmq_sequence_gap::BITCOIND_ARGS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                ..SetupOpts::default()
            },
            crate::test_zmq_sequence_gap::test_zmq_sequence_gap,
        )
    }));
    async_trials
}
