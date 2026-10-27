//! Templates the enforcer serves never mark the rule eCash nodes require
//! acknowledged as required, so miners that do not know it still mine them.

use cusf_enforcer_lib::{rpc_client::ECASH_TEMPLATE_RULE, types::Fork};
use cusf_enforcer_mempool::server::RpcClient as _;
use serde::Deserialize;

use crate::{
    mine::mine_gbt_check,
    setup::{PostSetup, bitcoind_fork},
};

#[derive(Deserialize)]
struct Rules {
    rules: Vec<String>,
}

pub async fn test_gbt_rule_ack(mut post_setup: PostSetup) -> anyhow::Result<()> {
    let required_rule = format!("!{ECASH_TEMPLATE_RULE}");

    // Guard the premise: an eCash node marks the rule required, so this test
    // covers the enforcer removing it. Elsewhere the node never sets it.
    let request = format!(r#"{{"rules":["segwit","{ECASH_TEMPLATE_RULE}"]}}"#);
    let node_template =
        crate::util::node_rpc(&post_setup.bitcoind_client, "getblocktemplate", [request]).await?;
    let node_rules: Rules = serde_json::from_str(&node_template)?;
    let node_requires = node_rules.rules.contains(&required_rule);
    anyhow::ensure!(
        node_requires == (bitcoind_fork() != Fork::Bitcoin),
        "node template rules {:?} disagree with the fork under test ({})",
        node_rules.rules,
        bitcoind_fork(),
    );

    let request = bitcoin_jsonrpsee::client::BlockTemplateRequest::default();
    let template = crate::util::expect_block_template(
        post_setup.gbt_client.get_block_template(request).await?,
    )?;
    anyhow::ensure!(
        !template.rules.contains(&required_rule),
        "enforcer template rules {:?} contain `{required_rule}`",
        template.rules,
    );

    // The served template must still be mineable.
    let () = mine_gbt_check::<_, std::convert::Infallible>(&mut post_setup, 1, |_| Ok(()))
        .await
        .map_err(|err| match err {
            either::Either::Left(err) => anyhow::anyhow!("mine_gbt failed: {err}"),
        })?;

    drop(post_setup);
    Ok(())
}
