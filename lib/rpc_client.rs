//! The Bitcoin Core JSON-RPC client.

use bitcoin_jsonrpsee::{
    MainClient,
    jsonrpsee::{core::ClientError, http_client::HttpClient},
};
use miette::Diagnostic;
use thiserror::Error;

use crate::{cli::NodeRpcConfig, errors::ErrorChain};

#[derive(Debug, Diagnostic, Error)]
pub enum Error {
    #[error("failed to create mainchain RPC client")]
    CreateClient(#[source] bitcoin_jsonrpsee::Error),
    #[error("failed to get RPC password")]
    GetRpcPassword,
    #[error("failed to get RPC user name")]
    GetRpcUser,
    #[error("unable to read bitcoind cookie at {cookie_path}")]
    ReadCookie {
        cookie_path: String,
        source: std::io::Error,
    },
    #[error("RPC user and password must be set together")]
    UserAndPasswordMustBeSetTogether,
    #[error("precisely one of RPC user and cookie must be set")]
    UserOrCookieMustBeSet,
}

pub fn create_client(conf: &NodeRpcConfig) -> Result<HttpClient, Error> {
    if conf.user.is_none() != conf.pass.is_none() {
        return Err(Error::UserAndPasswordMustBeSetTogether);
    }

    if conf.user.is_none() == conf.cookie_path.is_none() {
        return Err(Error::UserOrCookieMustBeSet);
    }

    let mut conf_user = conf.user.clone().unwrap_or_default();
    // The secret is exposed here, at the boundary where it is handed to the
    // RPC client, and nowhere else.
    let mut conf_pass = conf
        .pass
        .as_ref()
        .map_or_else(String::new, |pass| pass.expose().to_owned());

    if conf.cookie_path.is_some() {
        let cookie_path = conf.cookie_path.clone().unwrap();
        let auth =
            std::fs::read_to_string(cookie_path.clone()).map_err(|err| Error::ReadCookie {
                cookie_path: cookie_path.clone(),
                source: err,
            })?;

        let mut auth = auth.split(':');

        conf_user = auth.next().ok_or(Error::GetRpcUser)?.to_string().clone();

        conf_pass = auth
            .next()
            .ok_or(Error::GetRpcPassword)?
            .to_string()
            .clone();
    }

    // A mempool of default size might contain >300k txs.
    // batch Requesting 300k txs requires ~30MiB,
    // so 100MiB should be enough
    const MAX_REQUEST_SIZE: u32 = 100 * (1 << 20);

    // Default mempool size is 300MB, so 1GiB should be enough
    //
    // TODO: it'd be nice to extract what this setting is from
    // the RPC client at call site. Would require wrapping
    // the RPC client into a struct containing the config values?
    const MAX_RESPONSE_SIZE: u32 = 1 << 30;
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    let client_builder = bitcoin_jsonrpsee::jsonrpsee::http_client::HttpClientBuilder::default()
        .max_request_size(MAX_REQUEST_SIZE)
        .max_response_size(MAX_RESPONSE_SIZE)
        .request_timeout(REQUEST_TIMEOUT);

    let client = bitcoin_jsonrpsee::client(conf.addr, Some(client_builder), &conf_pass, &conf_user)
        .map_err(Error::CreateClient)?;

    Ok(client)
}

/// The `getblocktemplate` rule eCash nodes require template-mode requests to
/// acknowledge (unless run with `-deprecatedrpc=getblocktemplate`). Bitcoin
/// Core ignores rules it does not know.
pub const ECASH_TEMPLATE_RULE: &str = "bip300301";

/// The `maxburnamount` passed to `sendrawtransaction`. Bitcoin Core refuses
/// a transaction with provably unspendable outputs carrying value unless this
/// allows it; the wallet sends what its callers ask for, so any amount is
/// allowed.
const MAX_BURN_AMOUNT: f64 = 21_000_000.0;

/// Broadcasts a transaction to the Bitcoin network via `sendrawtransaction`.
/// Returns `Some(txid)` if broadcast successfully, `None` if the node
/// rejected the tx as nonstandard under the NOPx / upgradable-opcode policy.
/// All other errors are returned as-is.
pub async fn broadcast_transaction<RpcClient>(
    rpc_client: &RpcClient,
    tx: &bdk_wallet::bitcoin::Transaction,
) -> Result<Option<bitcoin::Txid>, ClientError>
where
    RpcClient: MainClient + Sync,
{
    // Bitcoin Core 30 renamed the reject reason; the reason in parentheses is
    // the same in both, so match on that.
    const NONSTANDARD_NOPX_REASON: &str = "(NOPx reserved for soft-fork upgrades)";

    let encoded_tx = bitcoin::consensus::encode::serialize_hex(tx);
    match rpc_client
        .send_raw_transaction(encoded_tx, None, Some(MAX_BURN_AMOUNT))
        .await
    {
        Ok(txid) => {
            tracing::debug!(%txid, "broadcast tx successfully");
            Ok(Some(txid))
        }
        Err(ClientError::Call(err)) if err.message().contains(NONSTANDARD_NOPX_REASON) => {
            tracing::warn!(
                reason = %err.message(),
                "node rejected tx, tolerated",
            );
            Ok(None)
        }
        Err(err) => {
            tracing::error!("failed to broadcast tx: {:#}", ErrorChain::new(&err));
            Err(err)
        }
    }
}
