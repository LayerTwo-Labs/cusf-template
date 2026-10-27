//! The validator: follows the node's chain, applies the enforcer's rules,
//! and records the outcome.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use bitcoin::{self, BlockHash};
use bitcoin_jsonrpsee::jsonrpsee;
use fallible_iterator::FallibleIterator as _;
use futures::{StreamExt as _, stream::FusedStream};
use miette::Diagnostic;
use nonempty::NonEmpty;
use sneed::{db, env};
use thiserror::Error;
use tokio::sync::{broadcast, watch::Receiver as WatchReceiver};

use crate::{
    proto::{StatusBuilder, ToStatus, mainchain::HeaderSyncProgress},
    types::{BlockInfo, Event, HeaderInfo, NetworkParams},
    validator::main_rest_client::MainRestClient,
};

mod dbs;
pub mod enforcer;
pub mod main_rest_client;
pub mod parse_block_files;
mod sync_state_summary;
mod task;
#[cfg(test)]
mod test_utils;

use self::dbs::Dbs;
pub use self::sync_state_summary::SyncStateSummary;

#[derive(Debug, Error)]
pub enum InitError {
    #[error(transparent)]
    CreateDbs(#[from] dbs::CreateDbsError),
    #[error("JSON RPC error (`{method}`)")]
    JsonRpc {
        method: String,
        source: jsonrpsee::core::ClientError,
    },
}

#[derive(Debug, Diagnostic, Error)]
enum GetHeaderInfoErrorInner {
    #[error(transparent)]
    GetHeaderInfo(#[from] dbs::block_hash_dbs_error::GetHeaderInfo),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

impl ToStatus for GetHeaderInfoErrorInner {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::GetHeaderInfo(err) => StatusBuilder::new(err),
            Self::ReadTxn(err) => StatusBuilder::new(err),
        }
    }
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct GetHeaderInfoError(GetHeaderInfoErrorInner);

impl<T> From<T> for GetHeaderInfoError
where
    GetHeaderInfoErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

impl ToStatus for GetHeaderInfoError {
    fn builder(&self) -> StatusBuilder<'_> {
        self.0.builder()
    }
}

#[derive(Debug, Diagnostic, Error)]
enum TryGetHeaderInfosErrorInner {
    #[error(transparent)]
    Db(#[from] db::Error),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct TryGetHeaderInfosError(TryGetHeaderInfosErrorInner);

impl<T> From<T> for TryGetHeaderInfosError
where
    TryGetHeaderInfosErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
enum GetBlockInfoErrorInner {
    #[error(transparent)]
    GetBlockInfo(#[from] dbs::block_hash_dbs_error::GetBlockInfo),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

#[derive(Debug, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct GetBlockInfoError(GetBlockInfoErrorInner);

impl<T> From<T> for GetBlockInfoError
where
    GetBlockInfoErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
enum TryGetBlockInfosErrorInner {
    #[error(transparent)]
    Db(#[from] db::Error),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

#[derive(Debug, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct TryGetBlockInfosError(TryGetBlockInfosErrorInner);

impl<T> From<T> for TryGetBlockInfosError
where
    TryGetBlockInfosErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
enum GetBlockInfosErrorInner {
    #[error("Missing header or block: {0}")]
    MissingHeaderBlock(BlockHash),
    #[error(transparent)]
    TryGetBlockInfos(#[from] TryGetBlockInfosError),
}

#[derive(Debug, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct GetBlockInfosError(GetBlockInfosErrorInner);

impl<T> From<T> for GetBlockInfosError
where
    GetBlockInfosErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
pub enum ListHeadersError {
    #[error(transparent)]
    DbGet(#[from] db::error::Get),
    #[error(transparent)]
    DbTryGet(#[from] db::error::TryGet),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

#[derive(Debug, Diagnostic, Error)]
pub enum TryGetMainchainTipError {
    #[error(transparent)]
    DbTryGet(#[from] db::error::TryGet),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

impl ToStatus for TryGetMainchainTipError {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::DbTryGet(err) => StatusBuilder::new(err),
            Self::ReadTxn(err) => StatusBuilder::new(err),
        }
    }
}

#[derive(Debug, Diagnostic, Error)]
pub enum GetMainchainTipError {
    #[error(transparent)]
    DbGet(#[from] db::error::Get),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

impl ToStatus for GetMainchainTipError {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::DbGet(err) => StatusBuilder::new(err),
            Self::ReadTxn(err) => StatusBuilder::new(err),
        }
    }
}

#[derive(Debug, Diagnostic, Error)]
pub enum TryGetMainchainTipHeightError {
    #[error(transparent)]
    DbGet(#[from] db::error::Get),
    #[error(transparent)]
    DbTryGet(#[from] db::error::TryGet),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

impl ToStatus for TryGetMainchainTipHeightError {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::DbGet(err) => StatusBuilder::new(err),
            Self::DbTryGet(err) => StatusBuilder::new(err),
            Self::ReadTxn(err) => StatusBuilder::new(err),
        }
    }
}

#[derive(Debug, Diagnostic, Error)]
pub enum EventsStreamError {
    #[error("Events stream closed due to overflow")]
    Overflow,
}

impl ToStatus for EventsStreamError {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::Overflow => StatusBuilder::new(self),
        }
    }
}

#[derive(Clone)]
pub struct Validator {
    dbs: Dbs,
    events_tx: broadcast::Sender<Event>,
    header_sync_progress_rx: Arc<parking_lot::RwLock<Option<WatchReceiver<HeaderSyncProgress>>>>,
    mainchain_client: jsonrpsee::http_client::HttpClient,
    mainchain_rest_client: Option<MainRestClient>,
    mainchain_blocks_dir: Option<PathBuf>,
    network: bitcoin::Network,
    network_params: NetworkParams,
}

impl Validator {
    /// `mainchain_rest_client` is `None` when Core is running without its REST
    /// interface; header sync then falls back to batched JSON-RPC.
    pub fn new(
        mainchain_client: jsonrpsee::http_client::HttpClient,
        mainchain_rest_client: Option<MainRestClient>,
        mainchain_blocks_dir: Option<PathBuf>,
        data_dir: &Path,
        network: bitcoin::Network,
        network_params: NetworkParams,
    ) -> Result<Self, InitError> {
        // Subscribers that fall this far behind see the stream end with
        // an overflow error, so leave room for a burst of blocks during
        // sync.
        const EVENTS_CHANNEL_CAPACITY: usize = 2_000;

        let (events_tx, _) = broadcast::channel(EVENTS_CHANNEL_CAPACITY);

        let dbs = Dbs::new(data_dir, network)?;
        Ok(Self {
            dbs,
            events_tx,
            header_sync_progress_rx: Arc::new(parking_lot::RwLock::new(None)),
            mainchain_client,
            mainchain_rest_client,
            mainchain_blocks_dir,
            network,
            network_params,
        })
    }

    /// Height at which this enforcer's rules activate, from the selected
    /// [`NetworkParams`].
    pub fn activation_height(&self) -> u32 {
        self.network_params.activation_height
    }

    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    pub fn network_params(&self) -> NetworkParams {
        self.network_params
    }

    pub fn subscribe_events(
        &self,
    ) -> impl FusedStream<Item = Result<Event, EventsStreamError>> + use<> {
        futures::stream::try_unfold(self.events_tx.subscribe(), |mut receiver| async {
            match receiver.recv().await {
                Ok(event) => Ok(Some((event, receiver))),
                Err(broadcast::error::RecvError::Closed) => Ok(None),
                Err(broadcast::error::RecvError::Lagged(_)) => Err(EventsStreamError::Overflow),
            }
        })
        .fuse()
    }

    /// Returns `None` if there is not a header sync in progress
    pub fn subscribe_header_sync_progress(&self) -> Option<WatchReceiver<HeaderSyncProgress>> {
        self.header_sync_progress_rx.read().clone()
    }

    pub fn get_header_info(
        &self,
        block_hash: &BlockHash,
    ) -> Result<HeaderInfo, GetHeaderInfoError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self.dbs.block_hashes.get_header_info(&rotxn, block_hash)?;
        Ok(res)
    }

    /// Get header infos for the specified block hash, and up to max_ancestors
    /// ancestors.
    /// Returns header infos newest-first.
    pub fn try_get_header_infos(
        &self,
        block_hash: &BlockHash,
        max_ancestors: usize,
    ) -> Result<Option<NonEmpty<HeaderInfo>>, TryGetHeaderInfosError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self
            .dbs
            .block_hashes
            .try_get_header_infos(&rotxn, block_hash, max_ancestors)?;
        Ok(res)
    }

    pub fn get_block_info(&self, block_hash: &BlockHash) -> Result<BlockInfo, GetBlockInfoError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self.dbs.block_hashes.get_block_info(&rotxn, block_hash)?;
        Ok(res)
    }

    /// Get block infos for the specified block hash, and up to max_ancestors
    /// ancestors.
    /// Returns block infos newest-first.
    pub fn try_get_block_infos(
        &self,
        block_hash: &BlockHash,
        max_ancestors: usize,
    ) -> Result<Option<NonEmpty<(HeaderInfo, BlockInfo)>>, TryGetBlockInfosError> {
        let rotxn = self.dbs.read_txn()?;
        let Some(header_infos) =
            self.dbs
                .block_hashes
                .try_get_header_infos(&rotxn, block_hash, max_ancestors)?
        else {
            return Ok(None);
        };
        let Some(info) = self
            .dbs
            .block_hashes
            .try_get_block_info(&rotxn, block_hash)?
        else {
            return Ok(None);
        };
        let mut res = NonEmpty::new((header_infos.head, info));
        for header_info in header_infos.tail {
            if let Some(info) = self
                .dbs
                .block_hashes
                .try_get_block_info(&rotxn, &header_info.block_hash)?
            {
                res.push((header_info, info));
            } else {
                break;
            }
        }
        Ok(Some(res))
    }

    pub fn get_block_infos(
        &self,
        block_hash: &BlockHash,
        max_ancestors: usize,
    ) -> Result<NonEmpty<(HeaderInfo, BlockInfo)>, GetBlockInfosError> {
        match self.try_get_block_infos(block_hash, max_ancestors)? {
            Some(res) => Ok(res),
            None => Err(GetBlockInfosErrorInner::MissingHeaderBlock(*block_hash).into()),
        }
    }

    /// Lists active chain block heights and their corresponding header hashes
    /// in ascending order.
    pub fn list_headers(
        &self,
        start_height: u32,
    ) -> Result<Vec<(u32, BlockHash)>, ListHeadersError> {
        let rotxn = self.dbs.read_txn()?;
        // Not synced yet, so there is no active chain to list.
        let Some(tip) = self.dbs.current_chain_tip.try_get(&rotxn, &())? else {
            return Ok(Vec::new());
        };
        // Headers on stale branches are never removed, so once a fork has been
        // seen, the height DB holds several hashes at the same height. Walk
        // back from the tip instead of iterating that DB, so that exactly one
        // header is listed per height, as consumers (the wallet checkpoint)
        // require strictly increasing heights.
        let heights = self.dbs.block_hashes.height();
        let mut ancestors = self.dbs.block_hashes.ancestor_headers(&rotxn, tip);
        let mut res = Vec::new();
        while let Some((block_hash, _header)) = ancestors.next()? {
            let height = heights.get(&rotxn, &block_hash)?;
            if height < start_height {
                break;
            }
            res.push((height, block_hash));
        }
        res.reverse();

        debug_assert!(res.is_sorted_by(|(first_height, _), (second_height, _)| {
            first_height < second_height
        }));
        Ok(res)
    }

    /// Get the mainchain tip. Returns `None` if not synced
    pub fn try_get_mainchain_tip(&self) -> Result<Option<BlockHash>, TryGetMainchainTipError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self.dbs.current_chain_tip.try_get(&rotxn, &())?;
        Ok(res)
    }

    /// Get the mainchain tip. Returns an error if not synced
    pub fn get_mainchain_tip(&self) -> Result<BlockHash, GetMainchainTipError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self.dbs.current_chain_tip.get(&rotxn, &())?;
        Ok(res)
    }

    /// Get the mainchain tip height. Returns `None` if not synced
    pub fn try_get_block_height(&self) -> Result<Option<u32>, TryGetMainchainTipHeightError> {
        let rotxn = self.dbs.read_txn()?;
        let Some(tip) = self.dbs.current_chain_tip.try_get(&rotxn, &())? else {
            return Ok(None);
        };
        let height = self.dbs.block_hashes.height().get(&rotxn, &tip)?;
        Ok(Some(height))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;

    use super::*;
    use crate::validator::test_utils::{dummy_validator, test_block_header};

    /// Headers on stale branches are never removed, so a fork leaves two
    /// headers at one height. Only the active chain may be listed: the wallet
    /// builds a checkpoint out of the result, which needs strictly increasing
    /// heights.
    #[test]
    fn list_headers_lists_active_chain_only() {
        let dir = temp_dir::TempDir::new().unwrap();
        let validator = dummy_validator(dir.path());
        let header0 = test_block_header(BlockHash::all_zeros());
        let header1a = test_block_header(header0.block_hash());
        // Sibling of `header1a`, on the branch that lost.
        let mut header1b = test_block_header(header0.block_hash());
        header1b.nonce = 1;
        let header2 = test_block_header(header1a.block_hash());

        let mut rwtxn = validator.dbs.write_txn().unwrap();
        validator
            .dbs
            .block_hashes
            .put_headers(
                &mut rwtxn,
                &[(header0, 0), (header1a, 1), (header1b, 1), (header2, 2)],
            )
            .unwrap();
        rwtxn.commit().unwrap();
        assert!(
            validator.list_headers(0).unwrap().is_empty(),
            "no chain tip, so no active chain to list"
        );

        let mut rwtxn = validator.dbs.write_txn().unwrap();
        validator
            .dbs
            .current_chain_tip
            .put(&mut rwtxn, &(), &header2.block_hash())
            .unwrap();
        rwtxn.commit().unwrap();
        assert_eq!(
            validator.list_headers(0).unwrap(),
            vec![
                (0, header0.block_hash()),
                (1, header1a.block_hash()),
                (2, header2.block_hash()),
            ],
            "the stale header at height 1 must not be listed"
        );
        assert_eq!(
            validator.list_headers(2).unwrap(),
            vec![(2, header2.block_hash())],
            "headers below `start_height` must not be listed"
        );
    }
}
