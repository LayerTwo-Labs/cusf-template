//! Unconfirmed wallet transactions are listed, with their outputs, as soon as
//! they are sent.

use std::collections::HashMap;

use cusf_enforcer_lib::proto::mainchain::{
    ListTransactionsRequest, ListUnspentOutputsRequest, SendTransactionRequest,
};

use crate::{integration_test, setup::PostSetup};

pub async fn test_unconfirmed_transactions(mut post_setup: PostSetup) -> anyhow::Result<()> {
    integration_test::fund_enforcer(&mut post_setup).await?;

    let txs_pre = post_setup
        .wallet_service_client
        .list_transactions(ListTransactionsRequest::default())
        .await?
        .into_owned();

    let utxos_pre = post_setup
        .wallet_service_client
        .list_unspent_outputs(ListUnspentOutputsRequest::default())
        .await?
        .into_owned();

    let destination_address = "bcrt1quzsfstj6aspah0yqzumnek9s2nmeh2ctax8tgy";

    let send_tx_res = post_setup
        .wallet_service_client
        .send_transaction(SendTransactionRequest {
            destinations: HashMap::from([(destination_address.to_string(), 123_456_u64)])
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .await?
        .into_owned();

    let txs_post = post_setup
        .wallet_service_client
        .list_transactions(ListTransactionsRequest::default())
        .await?
        .into_owned();

    anyhow::ensure!(
        txs_post.transactions.len() == txs_pre.transactions.len() + 1,
        "the sent transaction is not listed"
    );

    let new_txs = txs_post
        .transactions
        .iter()
        .filter(|maybe_new_tx| {
            !txs_pre
                .transactions
                .iter()
                .any(|tx| tx.txid == maybe_new_tx.txid)
        })
        .collect::<Vec<_>>();

    anyhow::ensure!(
        new_txs.len() == 1,
        "expected one new transaction: {new_txs:?}"
    );
    anyhow::ensure!(
        new_txs[0].txid == send_tx_res.txid,
        "the new transaction is not the one sent"
    );

    tracing::info!("new transaction: {:?}", new_txs);

    let unspent_post = post_setup
        .wallet_service_client
        .list_unspent_outputs(ListUnspentOutputsRequest::default())
        .await?
        .into_owned();

    let new_utxos = unspent_post
        .outputs
        .iter()
        .filter(|maybe_new_utxo| {
            !utxos_pre.outputs.iter().any(|utxo_pre| {
                utxo_pre.txid == maybe_new_utxo.txid && utxo_pre.vout == maybe_new_utxo.vout
            })
        })
        .collect::<Vec<_>>();

    anyhow::ensure!(!new_utxos.is_empty(), "the change output is not listed");

    Ok(())
}
