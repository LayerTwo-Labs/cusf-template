//! Pins a Bitcoin Core mempool invariant the enforcer relies on:
//! `testmempoolaccept` validates a transaction without inserting it into the
//! mempool. If this changes, the enforcer's mempool handling must be revisited.

use crate::setup::PostSetup;

/// After `testmempoolaccept`, the txid must be absent from `getrawmempool`.
/// Control: the same hex via `sendrawtransaction` appears in the mempool.
///
/// Funded from the bitcoind wallet's mature coinbases, so the enforcer runs
/// validator-only.
pub async fn test_testmempoolaccept_no_insert(post_setup: PostSetup) -> anyhow::Result<()> {
    // The bitcoind wallet funds the tx from a mature coinbase.
    crate::util::node_rpc(
        &post_setup.bitcoind_client,
        "generatetoaddress",
        ["101".to_string(), post_setup.mining_address.to_string()],
    )
    .await?;
    let dest = post_setup.receive_address.to_string();
    // outputs JSON object form required by createrawtransaction
    let outputs = format!(r#"{{"{dest}":0.001}}"#);
    let raw = crate::util::node_rpc(
        &post_setup.bitcoind_client,
        "createrawtransaction",
        ["[]".to_string(), outputs],
    )
    .await?;
    let funded = crate::util::node_rpc(
        &post_setup.bitcoind_client,
        "fundrawtransaction",
        [raw.trim().to_string()],
    )
    .await?;
    let funded_val: serde_json::Value = serde_json::from_str(&funded)?;
    let hex = funded_val
        .get("hex")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow::anyhow!("fundrawtransaction missing hex: {funded}"))?
        .to_string();
    let signed = crate::util::node_rpc(
        &post_setup.bitcoind_client,
        "signrawtransactionwithwallet",
        [hex],
    )
    .await?;
    let signed_val: serde_json::Value = serde_json::from_str(&signed)?;
    let signed_hex = signed_val
        .get("hex")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow::anyhow!("signrawtransactionwithwallet missing hex: {signed}"))?
        .to_string();
    anyhow::ensure!(
        signed_val.get("complete").and_then(|c| c.as_bool()) == Some(true),
        "wallet could not fully sign: {signed}"
    );

    let decoded = crate::util::node_rpc(
        &post_setup.bitcoind_client,
        "decoderawtransaction",
        [signed_hex.clone()],
    )
    .await?;
    let decoded_val: serde_json::Value = serde_json::from_str(&decoded)?;
    let txid = decoded_val
        .get("txid")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("decoderawtransaction missing txid"))?
        .to_string();

    let accept = crate::util::node_rpc(
        &post_setup.bitcoind_client,
        "testmempoolaccept",
        [format!(r#"["{signed_hex}"]"#)],
    )
    .await?;
    tracing::info!(%accept, %txid, "testmempoolaccept result");

    let mempool =
        crate::util::node_rpc(&post_setup.bitcoind_client, "getrawmempool", [""; 0]).await?;
    anyhow::ensure!(
        !mempool.contains(&txid),
        "testmempoolaccept left txid {txid} in getrawmempool: {mempool}"
    );

    drop(
        crate::util::node_rpc(
            &post_setup.bitcoind_client,
            "sendrawtransaction",
            [signed_hex, "0".to_string()],
        )
        .await?,
    );
    let mempool_after =
        crate::util::node_rpc(&post_setup.bitcoind_client, "getrawmempool", [""; 0]).await?;
    anyhow::ensure!(
        mempool_after.contains(&txid),
        "control failed: sendrawtransaction did not put {txid} in the mempool: {mempool_after}"
    );

    tracing::info!(%txid, "testmempoolaccept did not insert; sendrawtransaction did");
    Ok(())
}
