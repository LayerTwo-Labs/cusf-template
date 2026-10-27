//! On eCash builds, wallet sends carry the fork's replay-protection
//! `nLockTime` and a non-final input, so Bitcoin never accepts them;
//! elsewhere they don't.

use std::collections::HashMap;

use cusf_enforcer_lib::proto::{
    self,
    mainchain::{SendTransactionRequest, SendTransactionResponse},
};
use jsonrpsee::{core::client::ClientT as _, rpc_params};
use serde::Deserialize;

use crate::{
    integration_test::{fund_enforcer, wait_for_wallet_sync},
    mine::mine,
    setup::PostSetup,
};

const SEQUENCE_FINAL: u32 = 0xFFFF_FFFF;

#[derive(Deserialize)]
struct RawTxInput {
    sequence: u32,
}

#[derive(Deserialize)]
struct RawTx {
    locktime: u32,
    vin: Vec<RawTxInput>,
    #[serde(default)]
    confirmations: u32,
}

async fn raw_tx(post_setup: &PostSetup, txid: bitcoin::Txid) -> anyhow::Result<RawTx> {
    Ok(post_setup
        .bitcoind_client
        .request("getrawtransaction", rpc_params![txid, true])
        .await?)
}

async fn send(post_setup: &PostSetup) -> anyhow::Result<bitcoin::Txid> {
    let txid = post_setup
        .wallet_service_client
        .send_transaction(SendTransactionRequest {
            destinations: HashMap::from([(post_setup.receive_address.to_string(), 1_000_000_u64)])
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .await?
        .into_owned()
        .txid
        .into_option()
        .ok_or_else(|| proto::Error::missing_field::<SendTransactionResponse>("txid"))?
        .decode::<SendTransactionResponse, _>("txid")?;
    Ok(txid)
}

pub async fn test_replay_protection(mut post_setup: PostSetup) -> anyhow::Result<()> {
    let () = fund_enforcer(&mut post_setup).await?;

    let txid = send(&post_setup).await?;
    let tx = raw_tx(&post_setup, txid).await?;
    match crate::setup::bitcoind_regtest_params().replay_protection_lock_time {
        Some(lock_time) => {
            anyhow::ensure!(
                tx.locktime == lock_time,
                "send {txid} has nLockTime {}, want the replay-protection value {lock_time}",
                tx.locktime
            );
            anyhow::ensure!(
                tx.vin.iter().any(|input| input.sequence < SEQUENCE_FINAL),
                "send {txid} has only final inputs, so Bitcoin ignores its nLockTime and it can \
                 replay"
            );
        }
        None => {
            let tip_height: u32 = post_setup
                .bitcoind_client
                .request("getblockcount", rpc_params![])
                .await?;
            anyhow::ensure!(
                tx.locktime <= tip_height,
                "send {txid} has nLockTime {} on a fork without replay protection (tip \
                 {tip_height})",
                tx.locktime
            );
        }
    }
    tracing::info!(%txid, lock_time = tx.locktime, "send has the expected nLockTime");

    let () = mine(&mut post_setup, 1).await?;
    let confirmations = raw_tx(&post_setup, txid).await?.confirmations;
    anyhow::ensure!(
        confirmations > 0,
        "send {txid} was not mined into the next block"
    );
    wait_for_wallet_sync(&mut post_setup).await
}
