//! The enforcer syncs a node's blocks by reading its block files
//! (`--node-blocks-dir`) instead of fetching them over RPC.

use std::time::Duration;

use connectrpc::client::{ClientConfig, HttpClient};
use cusf_enforcer_lib::proto::mainchain_service::ValidatorServiceClient;
use futures::channel::mpsc;
use jsonrpsee::{core::client::ClientT as _, rpc_params};

use crate::{
    setup::{
        PreSetup, new_bitcoind, wait_for_bitcoind_ready, wait_for_port, wait_for_validator_synced,
    },
    util::Enforcer,
};

pub async fn test_file_based_block_parser(setup: PreSetup) -> anyhow::Result<()> {
    let (res_tx, _) = mpsc::unbounded::<anyhow::Result<()>>();

    let bitcoind = new_bitcoind(
        &setup.bin_paths,
        setup.directories.bitcoin_dir.clone(),
        &setup.reserved_ports,
        setup.network,
        None,
    )?;

    tracing::info!("Starting bitcoind for the first time");
    let first_bitcoind = bitcoind.spawn_command_with_args::<String, String, _, _, _>([], [], {
        let res_tx = res_tx.clone();
        move |err| {
            tracing::error!("Error starting bitcoind: {err:#}");
            let _err: Result<(), _> = res_tx.unbounded_send(Err(err));
        }
    });

    let bitcoind_client = bitcoind.rpc_client()?;

    let () = wait_for_bitcoind_ready(&bitcoind_client).await?;

    tracing::info!("Generating blocks");
    // Any regtest address: the coins are never spent.
    let address = "bcrt1qrmxr2qc8eedpqw8wsdtg4spzkcmcs2adkrc9rh";
    let generated_blocks: Vec<String> = bitcoind_client
        .request("generatetoaddress", rpc_params![100, address])
        .await?;

    // Flush the blocks to disk
    tracing::info!("Stopping bitcoind");
    let _stop_output: String = bitcoind_client.request("stop", rpc_params![]).await?;
    // An open connection keeps bitcoind serving `503`s through shutdown.
    drop(bitcoind_client);

    first_bitcoind.into_inner().await?;

    // Restart bitcoind
    tracing::info!("Restarting bitcoind");
    let _second_bitcoind = bitcoind.spawn_command_with_args::<String, String, _, _, _>([], [], {
        let res_tx = res_tx.clone();
        move |err| {
            let _err: Result<(), _> = res_tx.unbounded_send(Err(err));
        }
    });

    let bitcoind_client = bitcoind.rpc_client()?;
    let () = wait_for_bitcoind_ready(&bitcoind_client).await?;

    let enforcer = Enforcer {
        path: setup.bin_paths.cusf_enforcer()?.clone(),
        data_dir: setup.directories.enforcer_dir.clone(),
        enable_mempool: false,
        enable_wallet: false,
        enable_block_template_server: false,
        coinbase_recipient: None,
        node_mempool_dat: None,
        node_blocks_dir: Some(
            setup
                .directories
                .bitcoin_dir
                .clone()
                .join("regtest")
                .join("blocks"),
        ),
        node_rpc_user: bitcoind.rpc_user,
        node_rpc_pass: bitcoind.rpc_pass,
        node_rpc_port: bitcoind.rpc_port,
        serve_grpc_port: setup.reserved_ports.enforcer_serve_grpc.port(),
        serve_rpc_port: setup.reserved_ports.enforcer_serve_rpc.port(),
        wallet_electrum_rpc_port: 0,
        wallet_electrum_http_port: 0,
        wallet_seed_file: None,
    };

    // A bitcoind build that rebrands the P2P magic writes its own bytes as the
    // per-block prefix in blk*.dat. The parser takes them from `--fork`.
    tracing::info!("Starting enforcer");
    let _enforcer_task = enforcer.spawn_command_with_args(
        [(
            "RUST_LOG",
            "h2=info,hyper_util=info,jsonrpsee-client=debug,jsonrpsee-http=debug,connectrpc=debug,trace",
        )],
        Vec::<String>::new(),
        move |err| {
            let _err: Result<(), _> = res_tx.unbounded_send(Err(err));
        },
    );

    // Wait for enforcer gRPC port to open
    wait_for_port(
        "127.0.0.1",
        enforcer.serve_grpc_port,
        Duration::from_secs(10),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed waiting for enforcer gRPC port: {e}"))?;

    // verify we were able to sync

    let uri: http::Uri = format!("http://127.0.0.1:{}", enforcer.serve_grpc_port).parse()?;
    let http = HttpClient::plaintext();
    let config = ClientConfig::new(uri);
    let client = ValidatorServiceClient::new(http, config);

    let header_info = wait_for_validator_synced(&client).await?;

    // The validator synced to the right height and tip.
    anyhow::ensure!(
        header_info.height == 100,
        "synced to {}",
        header_info.height
    );
    anyhow::ensure!(generated_blocks.len() == 100);
    let tip_hash = header_info
        .block_hash
        .into_option()
        .and_then(|hash| hash.hex.into_option())
        .map(|hex| hex.value)
        .ok_or_else(|| anyhow::anyhow!("chain tip has no block hash"))?;
    anyhow::ensure!(
        generated_blocks.last() == Some(&tip_hash),
        "synced to {tip_hash}, not the last generated block"
    );

    // It got there by parsing the block files, as the enforcer's own log
    // reports.

    let stdout_lines = {
        let stdout = std::fs::read_to_string(setup.directories.enforcer_dir.join("stdout.txt"))?;
        stdout
            .split("\n")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    };

    anyhow::ensure!(
        stdout_lines
            .iter()
            .any(|line| line.contains("Completed block sync from files: 101 blocks processed")),
        "the enforcer did not sync its blocks from the block files"
    );

    Ok(())
}
