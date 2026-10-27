//! Connecting and disconnecting blocks, and syncing headers and blocks to
//! the node's tip.

use std::{path::PathBuf, time::Instant};

use bitcoin::{Block, BlockHash, Network, Transaction, Work, hashes::Hash as _};
use error_fatality::Split;
use fallible_iterator::FallibleIterator as _;
use futures::FutureExt as _;
use jsonrpsee::core::{
    client::BatchResponse,
    params::{ArrayParams, BatchRequestBuilder},
};
use sneed::{RoTxn, RwTxn};
use tokio::sync::broadcast::{self, error::SendError};
use tokio_util::sync::CancellationToken;

use crate::{
    proto::mainchain::HeaderSyncProgress,
    types::{BlockInfo, Event, HeaderInfo, NetworkParams},
    validator::{
        dbs::{
            Dbs,
            diff::{self, Diff as _},
        },
        main_rest_client::MainRestClient,
    },
};

mod block_files;
mod chainstates;
pub mod error;

/// A block that the mainchain node accepted, but that the validator rejected
/// as invalid, encountered while syncing. Reported to the
/// cusf-enforcer-mempool crate as `SyncToTipError::InvalidBlock`, so that it
/// calls out to `invalidateblock` and re-syncs to the node's resulting tip.
pub(in crate::validator) struct InvalidBlock {
    pub block_hash: BlockHash,
    /// Deliberately the non-fatal half of [`error::ConnectBlock`]: a fatal
    /// failure (DB, env, ...) says nothing about the block's validity, so it
    /// must not be representable here, where it would end up driving
    /// `invalidateblock`.
    pub reason: Box<<error::ConnectBlock as Split>::Jfyi>,
}

/// Bundles the consensus inputs that every handler needs.
#[derive(Clone)]
pub(in crate::validator) struct BlockHandler<'a> {
    pub(super) dbs: &'a Dbs,
    pub(super) network: Network,
    /// Network parameters, including the height at which the soft fork's
    /// rules activate. Blocks below it are plain Bitcoin history: still
    /// recorded, but not validated.
    pub(super) params: NetworkParams,
}

impl<'a> BlockHandler<'a> {
    pub(in crate::validator) fn new(dbs: &'a Dbs, network: Network, params: NetworkParams) -> Self {
        Self {
            dbs,
            network,
            params,
        }
    }
}

impl BlockHandler<'_> {
    pub(in crate::validator) fn validate_tx(
        &self,
        parent_rwtxn: &mut RwTxn,
        transaction: &Transaction,
    ) -> Result<bool, error::ValidateTransaction> {
        let dbs = self.dbs;
        let child_rwtxn = dbs.nested_write_txn(parent_rwtxn)?;
        let tip_hash = dbs
            .current_chain_tip
            .try_get(&child_rwtxn, &())?
            .ok_or(error::ValidateTransactionInner::NoChainTip)?;
        let tip_height = dbs.block_hashes.height().get(&child_rwtxn, &tip_hash)?;
        // Fork point: validate `transaction` against your soft fork's mempool
        // rules here, returning Ok(false) to keep it out of the enforcer's
        // mempool. The template accepts everything.
        let _ = (transaction, tip_height, self.params.activation_height);
        Ok(true)
    }

    fn connect_block_pass_through(
        &self,
        rwtxn: &mut RwTxn,
        block: &Block,
        height: u32,
        coinbase: &Transaction,
        block_hash: BlockHash,
        prev_mainchain_block_hash: BlockHash,
    ) -> Result<Event, error::ConnectBlock> {
        let dbs = self.dbs;
        // Fork point: validate `block` (at `height`, against your soft fork's
        // rules once `height >= self.params.activation_height`) and compute the
        // reversible state diff it produces. A validation failure must be a
        // non-fatal `error::ConnectBlock` variant: the driver then has Bitcoin
        // Core `invalidateblock` it. The template accepts every block and
        // tracks no state.
        let _ = (block, height, self.params.activation_height);

        let block_info = BlockInfo {
            coinbase_txid: coinbase.compute_txid(),
        };
        let block_diff = diff::Block {};
        let () = block_diff.apply(rwtxn, dbs, height)?;
        let () = dbs
            .block_hashes
            .put_block_info(rwtxn, &block_hash, &block_info, &block_diff)
            .map_err(error::ConnectBlock::PutBlockInfo)?;
        let current_tip_cumulative_work: Option<Work> = 'work: {
            let Some(current_tip) = dbs.current_chain_tip.try_get(rwtxn, &())? else {
                break 'work None;
            };
            Some(
                dbs.block_hashes
                    .cumulative_work()
                    .get(rwtxn, &current_tip)?,
            )
        };
        let cumulative_work = dbs.block_hashes.cumulative_work().get(rwtxn, &block_hash)?;
        if Some(cumulative_work) > current_tip_cumulative_work {
            dbs.current_chain_tip.put(rwtxn, &(), &block_hash)?;
            tracing::trace!("updated current chain tip: {}", height);
        }
        Ok(Event::ConnectBlock {
            header_info: HeaderInfo {
                block_hash,
                prev_block_hash: prev_mainchain_block_hash,
                height,
                work: block.header.work(),
                timestamp: block.header.time,
            },
            block_info,
        })
    }

    /// Check that the current chain tip is the parent of the incoming block
    fn ensure_tip_is_parent(
        &self,
        rotxn: &RoTxn,
        parent: BlockHash,
    ) -> Result<(), error::ConnectBlock> {
        let dbs = self.dbs;
        match dbs.current_chain_tip.try_get(rotxn, &())? {
            Some(tip) if parent == tip => Ok(()),
            None if parent == BlockHash::all_zeros() => Ok(()),
            tip => {
                let tip = tip.unwrap_or_else(BlockHash::all_zeros);
                let tip_height = dbs
                    .block_hashes
                    .height()
                    .get(rotxn, &tip)
                    .unwrap_or_default();
                tracing::error!(
                    chain_tip = %tip,
                    incoming_block_parent = %parent,
                    "chain tip is not the parent of the incoming block"
                );
                Err(error::ConnectBlock::BlockParent {
                    parent,
                    tip,
                    tip_height,
                })
            }
        }
    }

    /// Block header should be stored before calling this. Runs the soft
    /// fork's validation via [`Self::connect_block_pass_through`]; an invalid
    /// block produces a non-fatal rejection.
    #[tracing::instrument(skip_all)]
    pub(in crate::validator) fn connect_block(
        &self,
        rwtxn: &mut RwTxn,
        block: &Block,
    ) -> Result<Event, error::ConnectBlock> {
        let dbs = self.dbs;
        let parent = block.header.prev_blockhash;

        tracing::trace!("verifying chain tip is block parent");
        let () = self.ensure_tip_is_parent(rwtxn, parent)?;

        tracing::trace!("starting block processing");
        let block_hash = block.block_hash();
        let height = dbs.block_hashes.height().get(rwtxn, &block_hash)?;
        let Some(coinbase) = block.txdata.first() else {
            return Err(error::ConnectBlock::NoCoinbase);
        };

        self.connect_block_pass_through(rwtxn, block, height, coinbase, block_hash, parent)
    }

    pub(in crate::validator) fn disconnect_block(
        &self,
        rwtxn: &mut RwTxn,
        events: &mut Vec<Event>,
        block_hash: BlockHash,
    ) -> Result<(), error::DisconnectBlock> {
        let dbs = self.dbs;
        // Absence of a stored diff means we rejected the block. Nothing to undo.
        let Some(diff) = dbs.block_hashes.diff().try_get(rwtxn, &block_hash)? else {
            tracing::trace!(
                %block_hash,
                "disconnect_block: block was rejected, treating as no-op"
            );
            return Ok(());
        };

        if let Some(tip_hash) = dbs.current_chain_tip.try_get(rwtxn, &())?
            && tip_hash != block_hash
        {
            return Err(error::DisconnectBlock::TipHash {
                block_hash,
                tip_hash,
            });
        }
        let header_info = dbs.block_hashes.get_header_info(rwtxn, &block_hash)?;
        let () = diff.undo(rwtxn, dbs)?;
        if header_info.prev_block_hash != BlockHash::all_zeros() {
            dbs.current_chain_tip
                .put(rwtxn, &(), &header_info.prev_block_hash)?;
        } else {
            dbs.current_chain_tip.delete(rwtxn, &())?;
        }
        events.push(Event::DisconnectBlock { block_hash });
        Ok(())
    }
}

/// Broadcast events for state that has already been committed.
pub(in crate::validator) fn broadcast_events(
    event_tx: &broadcast::Sender<Event>,
    events: Vec<Event>,
) {
    for event in events {
        // Only fails when nobody is subscribed
        let _send_err: Result<usize, SendError<_>> = event_tx.send(event);
    }
}

/// Find the best ancestor of the node's tip that the enforcer has
/// Returns hash and height of the best ancestor.
async fn fetch_best_ancestor<MainRpcClient>(
    dbs: &Dbs,
    mainchain: &MainRpcClient,
    node_tip: BlockHash,
    node_tip_height: u32,
) -> Result<Option<(BlockHash, u32)>, error::Sync>
where
    MainRpcClient: bitcoin_jsonrpsee::client::MainClient + Sync,
{
    if node_tip == BlockHash::all_zeros() {
        return Ok(None);
    }

    // Check if enforcer already has the node tip
    {
        let rotxn = dbs.read_txn()?;
        if dbs.block_hashes.contains_header(&rotxn, &node_tip)? {
            return Ok(Some((node_tip, node_tip_height)));
        }
    }

    // Find best ancestor via binary search
    let mut best_known_ancestor: Option<(BlockHash, u32)> = None;
    let mut oldest_known_missing_ancestor_height = node_tip_height;

    loop {
        let best_known_ancestor_height = best_known_ancestor.map(|(_, height)| height);
        let midpoint_height =
            oldest_known_missing_ancestor_height.midpoint(best_known_ancestor_height.unwrap_or(0));
        if Some(midpoint_height) == best_known_ancestor_height
            || midpoint_height == oldest_known_missing_ancestor_height
        {
            return Ok(best_known_ancestor);
        }

        let midpoint = mainchain
            .getblockhash(midpoint_height as usize)
            .await
            .map_err(|err| error::Sync::JsonRpc {
                method: "getblockhash".to_owned(),
                source: err,
            })?;
        let rotxn = dbs.read_txn()?;
        if dbs.block_hashes.contains_header(&rotxn, &midpoint)? {
            best_known_ancestor = Some((midpoint, midpoint_height));
        } else {
            oldest_known_missing_ancestor_height = midpoint_height;
        }
    }
}

/// Validate that the two JSON-RPC batches describe one contiguous segment of
/// the active chain. Bitcoin Core executes each request in a batch separately,
/// so a reorg can otherwise mix hashes from different active chains.
fn validate_rpc_header_batch(
    start_block_hash: BlockHash,
    start_height: u32,
    block_hashes: Vec<BlockHash>,
    raw_headers: Vec<String>,
) -> Result<Vec<(bitcoin::block::Header, BlockHash, u32)>, error::Sync> {
    if block_hashes.first().copied() != Some(start_block_hash) {
        return Err(error::Sync::BlockNotInActiveChain {
            block_hash: start_block_hash,
        });
    }

    let mut validated = Vec::with_capacity(block_hashes.len());
    let mut previous_block_hash = None;
    for (offset, (block_hash, raw_header)) in block_hashes.into_iter().zip(raw_headers).enumerate()
    {
        let offset = u32::try_from(offset).expect("header batches contain at most 2000 entries");
        let expected_height = start_height
            .checked_add(offset)
            .expect("a header batch cannot extend beyond the mainchain tip");

        let header: bitcoin::block::Header =
            bitcoin::consensus::encode::deserialize_hex(&raw_header)?;
        if header.block_hash() != block_hash
            || previous_block_hash
                .is_some_and(|previous_block_hash| header.prev_blockhash != previous_block_hash)
        {
            return Err(error::Sync::BlockNotInActiveChain { block_hash });
        }

        previous_block_hash = Some(block_hash);
        validated.push((header, block_hash, expected_height));
    }
    Ok(validated)
}

#[tracing::instrument(skip_all)]
async fn sync_headers<MainRpcClient>(
    dbs: &Dbs,
    main_rest_client: Option<&MainRestClient>,
    main_rpc_client: &MainRpcClient,
    main_tip: BlockHash,
    progress_tx: &tokio::sync::watch::Sender<HeaderSyncProgress>,
    cancel: CancellationToken,
) -> Result<(), error::Sync>
where
    MainRpcClient: bitcoin_jsonrpsee::client::MainClient + Sync,
{
    let start = Instant::now();

    if main_tip == BlockHash::all_zeros() {
        return Ok(());
    }

    let main_tip_height = main_rpc_client
        .getblockheader(main_tip)
        .await
        .map_err(|err| error::Sync::JsonRpc {
            method: "getblockheader".to_owned(),
            source: err,
        })?
        .height;

    let best_ancestor: Option<(BlockHash, u32)> =
        fetch_best_ancestor(dbs, main_rpc_client, main_tip, main_tip_height).await?;

    // Return early if all headers are already available.
    let (mut current_block_hash, mut current_height, new_headers_needed) = match best_ancestor {
        Some((ancestor, height)) => {
            if ancestor == main_tip {
                return Ok(());
            } else {
                (ancestor, height, main_tip_height - height)
            }
        }
        None => {
            let genesis_block_hash =
                main_rpc_client
                    .getblockhash(0)
                    .await
                    .map_err(|err| error::Sync::JsonRpc {
                        method: "getblockhash".to_owned(),
                        source: err,
                    })?;
            (genesis_block_hash, 0, main_tip_height + 1)
        }
    };

    // Fetch headers in batches for efficiency
    // 2000 is max allowed by Bitcoin Core
    const HEADER_FETCH_BATCH_SIZE: usize = 2000;

    tracing::debug!(
        "Syncing headers starting from #{current_height} `{current_block_hash}` up to `{main_tip}`"
    );

    // The requested block header is the /first/ header in the batch. This means we
    // need to loop from our current tip, until we find the requested main tip.
    loop {
        if cancel.is_cancelled() {
            tracing::warn!("Header sync interrupted");
            return Err(error::Sync::Shutdown);
        }

        tracing::debug!(
            "Fetching batch of headers starting from #{current_height} `{current_block_hash}`"
        );

        // It is possible that the first header is not new
        let headers_needed = (main_tip_height - current_height) + 1;
        let batch_size = std::cmp::min(HEADER_FETCH_BATCH_SIZE, headers_needed as usize);
        // Fetch a batch of headers
        let headers = if let Some(main_rest_client) = main_rest_client {
            main_rest_client
                .get_block_headers(&current_block_hash, current_height, batch_size)
                .await?
        } else {
            // REST is optional. Fetch each RPC stage as a batch so
            // REST-disabled Core nodes retain the same round-trip shape as
            // the REST path instead of making one request per header.
            let mut get_block_hash_batch = BatchRequestBuilder::new();
            for offset in 0..batch_size {
                let offset =
                    u32::try_from(offset).expect("header batches contain at most 2000 entries");
                let height = current_height
                    .checked_add(offset)
                    .expect("a header batch cannot extend beyond the mainchain tip");
                let mut params = ArrayParams::new();
                params
                    .insert(height as usize)
                    .expect("failed to insert block height");
                get_block_hash_batch
                    .insert("getblockhash", params)
                    .map_err(error::Sync::JsonSerialize)?;
            }
            let block_hashes: Vec<BlockHash> = match main_rpc_client
                .batch_request(get_block_hash_batch)
                .boxed()
                .await
                .map_err(|err| error::Sync::JsonRpc {
                    method: "getblockhash (batched)".to_owned(),
                    source: err,
                })?
                .ok()
            {
                Ok(hashes) => hashes.copied().collect(),
                Err(errors) => {
                    return Err(error::Sync::BatchJsonRpc {
                        errors: errors.map(|error| error.message().to_owned()).collect(),
                    });
                }
            };
            let mut get_block_header_batch = BatchRequestBuilder::new();
            for block_hash in &block_hashes {
                let mut params = ArrayParams::new();
                params
                    .insert(block_hash.to_string())
                    .expect("failed to insert block hash");
                // Request the raw 80-byte header rather than the verbose JSON
                // object. Core computes chainwork, confirmations and nTx for
                // the verbose form, which is a real per-header cost when
                // syncing an IBD-sized range.
                params.insert(false).expect("failed to insert verbosity");
                get_block_header_batch
                    .insert("getblockheader", params)
                    .map_err(error::Sync::JsonSerialize)?;
            }
            let raw_headers: Vec<String> = match main_rpc_client
                .batch_request(get_block_header_batch)
                .boxed()
                .await
                .map_err(|err| error::Sync::JsonRpc {
                    method: "getblockheader (batched)".to_owned(),
                    source: err,
                })?
                .ok()
            {
                Ok(headers) => headers.cloned().collect(),
                Err(errors) => {
                    return Err(error::Sync::BatchJsonRpc {
                        errors: errors.map(|error| error.message().to_owned()).collect(),
                    });
                }
            };
            validate_rpc_header_batch(
                current_block_hash,
                current_height,
                block_hashes,
                raw_headers,
            )?
        };

        match headers.last() {
            Some((_, last_block_hash, last_block_height)) => {
                // Update the block_hash to the latest header fetched in this
                // batch to continue the loop
                current_block_hash = *last_block_hash;
                current_height = *last_block_height;
            }
            None => {
                // This will be empty if the requested block hash is not in the
                // current active chain, i.e. if we're dealing with a reorg,
                // or the provided mainchain tip was invalid.

                // Syncing headers is a reasonably quick operation.
                // We therefore deal with it by erroring out here, and then
                // retrying the sync from further out in the call stack.
                //
                // This branch only hits if we're dealing with a reorg /while/
                // we're syncing headers.
                // If we've reorged before starting the sync, it is picked up
                // at the beginning. Erroring out here is enough for an edge
                // case this rare.
                return Err(error::Sync::BlockNotInActiveChain {
                    block_hash: current_block_hash,
                });
            }
        }

        // Store the fetched headers
        let mut rwtxn = dbs.write_txn()?;
        dbs.block_hashes.put_headers(
            &mut rwtxn,
            &headers
                .iter()
                .map(|(header, _, height)| (*header, *height))
                .collect::<Vec<_>>(),
        )?;
        let () = rwtxn.commit()?;

        // Send progress update
        let progress = HeaderSyncProgress {
            current_height: Some(current_height),
        };
        if let Err(err) = progress_tx.send(progress) {
            tracing::warn!("Failed to send header sync progress: {err:#}");
        }

        // Important: break out here /after/ storing the last header.
        if current_block_hash == main_tip {
            tracing::info!(main_tip = %main_tip, "Reached main tip at height {current_height}!");
            break;
        } else if current_height == main_tip_height {
            return Err(error::Sync::BlockNotInActiveChain {
                block_hash: main_tip,
            });
        }
    }

    tracing::info!(
        main_tip = ?main_tip,
        "Synced {new_headers_needed} headers in {}",
        jiff::SignedDuration::try_from(start.elapsed()).unwrap_or_default()
    );
    Ok(())
}

async fn fetch_blocks_batch<MainRpcClient>(
    main_rpc_client: &MainRpcClient,
    block_hashes: &[BlockHash],
) -> Result<Vec<Block>, error::Sync>
where
    MainRpcClient: bitcoin_jsonrpsee::client::MainClient + Sync,
{
    let mut get_block_batch = BatchRequestBuilder::new();
    for block_hash in block_hashes {
        // By default (1) a deserialized block is returned. We want to do this ourselves!
        let verbosity = 0;

        let mut params = ArrayParams::new();
        params
            .insert(block_hash.to_string())
            .expect("failed to insert block hash");

        params
            .insert(verbosity)
            .expect("failed to insert verbosity");

        get_block_batch
            .insert("getblock", params)
            .map_err(error::Sync::JsonSerialize)?;
    }

    let start = Instant::now();

    let batch_response: BatchResponse<String> = main_rpc_client
        .batch_request(get_block_batch)
        .boxed() // IMPORTANT: omitting this box leads to cryptic a lifetime error
        .await
        .map_err(|err| error::Sync::JsonRpc {
            method: "getblock (batched)".to_owned(),
            source: err,
        })?;

    let fetch_duration = start.elapsed();

    let blocks = match batch_response.ok() {
        Ok(blocks) => blocks
            .map(|block| {
                let bytes = hex::decode(block)?;
                let block: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;

                Ok::<_, error::Sync>(block)
            })
            .collect::<Result<Vec<_>, _>>()?,
        Err(errors) => {
            return Err(error::Sync::BatchJsonRpc {
                errors: errors.map(|e| e.message().to_string()).collect(),
            });
        }
    };

    let deserialization_duration = start.elapsed() - fetch_duration;

    tracing::debug!(
        "Fetched ({:?}) and deserialized ({:?}) batch of {} block(s) with {} total transactions",
        fetch_duration,
        deserialization_duration,
        blocks.len(),
        blocks.iter().map(|block| block.txdata.len()).sum::<usize>(),
    );

    Ok(blocks)
}

/// The range of heights the node has no block data for while it is
/// background-validating an assumeutxo snapshot, see
/// [`chainstates::BackgroundSync`].
#[derive(Clone, Copy, Debug)]
struct BlockDataGap {
    /// Block data is available at and below this height.
    background_height: u32,
    /// Block data is available above this height. The base block itself is
    /// part of the gap.
    snapshot_base_height: u32,
}

impl BlockDataGap {
    fn contains(&self, height: u32) -> bool {
        self.background_height < height && height <= self.snapshot_base_height
    }
}

/// The heights the node cannot serve `getblock` for, or `None` if every
/// block on the active chain is available. Only limited while the node is
/// background-validating an assumeutxo snapshot. The snapshot base height
/// comes from the enforcer's own header db, which `sync_headers` has already
/// brought up to the node's tip.
async fn block_data_gap<MainRpcClient>(
    dbs: &Dbs,
    main_rpc_client: &MainRpcClient,
) -> Result<Option<BlockDataGap>, error::Sync>
where
    MainRpcClient: bitcoin_jsonrpsee::client::MainClient + Sync,
{
    let chainstates = chainstates::get_chainstates(main_rpc_client)
        .await
        .map_err(|err| error::Sync::JsonRpc {
            method: "getchainstates".to_owned(),
            source: err,
        })?;
    let Some(background_sync) = chainstates.background_sync()? else {
        return Ok(None);
    };
    let rotxn = dbs.read_txn()?;
    let snapshot_base_height = dbs
        .block_hashes
        .height()
        .try_get(&rotxn, &background_sync.snapshot_blockhash)?
        .ok_or(error::Sync::SnapshotBaseHeaderUnknown {
            snapshot_blockhash: background_sync.snapshot_blockhash,
        })?;
    Ok(Some(BlockDataGap {
        background_height: background_sync.background_height,
        snapshot_base_height,
    }))
}

impl BlockHandler<'_> {
    /// Handle and commit a block batch, then broadcast events for the committed
    /// prefix. A non-fatal rejected block commits the preceding valid blocks;
    /// fatal errors and commit failures broadcast nothing.
    pub(in crate::validator) fn handle_block_batch_and_commit(
        &self,
        mut rwtxn: RwTxn<'_>,
        blocks: &[Block],
        event_tx: &broadcast::Sender<Event>,
    ) -> Result<Option<InvalidBlock>, error::Sync> {
        let mut events = Vec::new();
        let invalid_block = self.handle_block_batch(&mut rwtxn, blocks, &mut events)?;
        rwtxn.commit()?;
        broadcast_events(event_tx, events);
        Ok(invalid_block)
    }

    /// Returns `Some(InvalidBlock)` if a block was rejected as invalid. The
    /// blocks before it in the batch are still connected.
    /// Returns `None` if every block in the batch connected successfully.
    fn handle_block_batch<'a>(
        &self,
        rwtxn: &mut RwTxn<'a>,
        blocks: &[Block],
        events: &mut Vec<Event>,
    ) -> Result<Option<InvalidBlock>, error::Sync> {
        let dbs = self.dbs;
        let start = Instant::now();

        let mut total_txs = 0;

        // Process blocks sequentially to maintain ordering and database consistency
        for block in blocks {
            let block_hash = block.block_hash();

            tracing::trace!("Syncing block #{} `{block_hash}`", {
                // Do the data fetch within the macro, to avoid the cost on higher
                // log levels
                dbs.block_hashes.height().get(rwtxn, &block_hash)?
            });

            let start_block = Instant::now();
            // We should not call out to `invalidateblock` in case of failures here,
            // as that is handled by the cusf-enforcer-mempool crate.
            // FIXME: handle disconnects
            let connect_res = {
                let mut child_rwtxn = dbs.nested_write_txn(rwtxn)?;
                match self.connect_block(&mut child_rwtxn, block) {
                    Ok(event) => {
                        let () = child_rwtxn.commit()?;
                        Ok(event)
                    }
                    Err(err) => {
                        child_rwtxn.abort();
                        Err(err)
                    }
                }
            };

            let event = match connect_res {
                Ok(event) => event,
                Err(err) => match err.split() {
                    Ok(jfyi) => {
                        tracing::info!(
                            %block_hash,
                            "encountered invalid block during batch sync: {:#}",
                            crate::errors::ErrorChain::new(&jfyi),
                        );
                        return Ok(Some(InvalidBlock {
                            block_hash,
                            reason: Box::new(jfyi),
                        }));
                    }
                    Err(fatal) => return Err(error::ConnectBlock::from(fatal).into()),
                },
            };

            let connect_block_duration =
                jiff::SignedDuration::try_from(start_block.elapsed()).unwrap_or_default();

            // Create dynamic fields using a HashMap for structured logging
            match &event {
                Event::ConnectBlock {
                    header_info,
                    block_info: _,
                } => {
                    // Keep all the blocks at info level in the beginning,
                    // and then taper off into less log noise
                    let log_interval = match header_info.height {
                        0..=999 => 1,
                        1000..=9999 => 10,
                        10_000..=99_999 => 100,
                        100_000.. => 1000,
                    };

                    total_txs += block.txdata.len();

                    // Apparently it isn't possible to do dynamic levels? wtf
                    // https://github.com/tokio-rs/tracing/issues/2730
                    if header_info.height % log_interval == 0 {
                        tracing::info!(
                            total_txs = block.txdata.len(),
                            "Synced block #{}: `{}` in {connect_block_duration}",
                            header_info.height,
                            header_info.block_hash,
                        );
                    } else {
                        tracing::debug!(
                            total_txs = block.txdata.len(),
                            "Synced block #{}: `{}` in {connect_block_duration}",
                            header_info.height,
                            header_info.block_hash,
                        );
                    };
                }
                Event::DisconnectBlock { block_hash } => {
                    tracing::debug!(
                        "Disconnected block: `{block_hash}` in {connect_block_duration}",
                    );
                }
            }
            events.push(event);
        }

        tracing::info!(
            total_txs = total_txs,
            "Synced batch of {} blocks in {}",
            blocks.len(),
            jiff::SignedDuration::try_from(start.elapsed()).unwrap_or_default(),
        );
        Ok(None)
    }

    /// Check that `missing_blocks` still describes exactly the blocks that are
    /// left to connect, ie. that the next block to sync is a child of the
    /// current tip, or that the tip is `main_tip` if nothing is left.
    fn missing_blocks_connect_to_tip(
        &self,
        missing_blocks: &[BlockHash],
        main_tip: BlockHash,
    ) -> Result<bool, error::Sync> {
        let dbs = self.dbs;
        let rotxn = dbs.read_txn()?;
        let tip = dbs
            .current_chain_tip
            .try_get(&rotxn, &())?
            .unwrap_or_else(BlockHash::all_zeros);
        match missing_blocks.last() {
            Some(next_block) => {
                let header_info = dbs.block_hashes.get_header_info(&rotxn, next_block)?;
                Ok(header_info.prev_block_hash == tip)
            }
            None => Ok(tip == main_tip),
        }
    }

    // MUST be called after `sync_headers`.
    /// Returns `Some(InvalidBlock)` if a block was rejected as invalid. The
    /// sync stops at the invalid block's parent.
    #[tracing::instrument(skip_all)]
    async fn sync_blocks<MainRpcClient>(
        &self,
        event_tx: &broadcast::Sender<Event>,
        main_rpc_client: &MainRpcClient,
        main_blocks_dir: Option<PathBuf>,
        main_tip: BlockHash,
        cancel: CancellationToken,
    ) -> Result<Option<InvalidBlock>, error::Sync>
    where
        MainRpcClient: bitcoin_jsonrpsee::client::MainClient + Sync,
    {
        // Batch size for concurrent block fetching
        // It's hard to know what a good size here is, without
        // further benchmarking.
        const BLOCK_FETCH_BATCH_SIZE: usize = 50;

        let dbs = self.dbs;
        let start = Instant::now();
        let (mut missing_blocks, main_tip_height) = tokio::task::block_in_place(|| {
            let current_enforcer_tip = {
                let mut rwtxn = dbs.write_txn()?;
                let mut current_enforcer_tip = dbs
                    .current_chain_tip
                    .try_get(&rwtxn, &())?
                    .unwrap_or_else(BlockHash::all_zeros);
                let last_common_ancestor = dbs.block_hashes.last_common_ancestor(
                    &rwtxn,
                    current_enforcer_tip,
                    main_tip,
                )?;
                if current_enforcer_tip != last_common_ancestor {
                    tracing::info!(
                        "Disconnecting tip {current_enforcer_tip} -> {last_common_ancestor}"
                    );
                    let mut events = Vec::new();
                    while current_enforcer_tip != last_common_ancestor {
                        let () =
                            self.disconnect_block(&mut rwtxn, &mut events, current_enforcer_tip)?;
                        current_enforcer_tip = dbs
                            .current_chain_tip
                            .try_get(&rwtxn, &())?
                            .unwrap_or_else(BlockHash::all_zeros);
                    }
                    rwtxn.commit()?;
                    broadcast_events(event_tx, events);
                } else {
                    rwtxn.abort();
                }
                current_enforcer_tip
            };
            let rotxn = dbs.read_txn()?;
            let missing_blocks = dbs
                .block_hashes
                .ancestor_headers(&rotxn, main_tip)
                .map(|(block_hash, _)| Ok(block_hash))
                .take_while(|block_hash| Ok(*block_hash != current_enforcer_tip))
                .collect::<Vec<_>>()
                .map_err(error::Sync::from)?;
            let main_tip_height = dbs.block_hashes.height().get(&rotxn, &main_tip)?;
            Ok::<_, error::Sync>((missing_blocks, main_tip_height))
        })?;

        if missing_blocks.is_empty() {
            tracing::info!("No missing blocks, skipping sync");
            return Ok(None);
        }

        tracing::info!(
            "identified {} missing blocks in {:?}, starting batched sync",
            missing_blocks.len(),
            start.elapsed()
        );

        let mut total_blocks_synced: usize = 0;

        if let Some(main_blocks_dir) = main_blocks_dir {
            let start = Instant::now();
            tracing::debug!(
                network = %self.network,
                "syncing blocks from blocks dir: {}",
                main_blocks_dir.display()
            );

            match block_files::sync_from_directory(
                self,
                event_tx,
                &mut missing_blocks,
                main_blocks_dir,
                cancel.clone(),
            ) {
                Ok(total_handled_blocks) => {
                    total_blocks_synced += total_handled_blocks as usize;
                    tracing::info!(
                        "Synced {total_handled_blocks} blocks from blocks dir in {:?}",
                        start.elapsed()
                    );
                }
                Err(e) => {
                    tracing::error!("Error syncing blocks from blocks dir: {e:#}");
                    // Syncing from the blocks dir is best-effort: Core is not
                    // expected to have flushed all blocks to disk, so the
                    // JSON-RPC sync below finishes the job. That is only sound
                    // as long as `missing_blocks` still describes exactly what
                    // is left to sync. If it doesn't, falling through would
                    // silently skip past a gap, so bail out instead.
                    if !self.missing_blocks_connect_to_tip(&missing_blocks, main_tip)? {
                        tracing::error!("blocks dir sync left a gap in the missing blocks");
                        return Err(e);
                    }
                }
            }
        }

        // While the node is background-validating an assumeutxo snapshot
        // (`loadtxoutset`), it has no block data for the heights above the
        // background chainstate's tip up to and including the snapshot
        // base. Everything else (below the background tip, and above the
        // base) it serves right away. Follow the node's background sync
        // instead of failing. Fetch what is available, and poll
        // `getchainstates` while waiting for blocks inside the gap.
        const BACKGROUND_SYNC_POLL_INTERVAL: std::time::Duration =
            std::time::Duration::from_secs(1);

        const WAIT_LOG_EVERY: u32 = 30;

        let mut block_data_gap = block_data_gap(dbs, main_rpc_client).await?;

        // Process blocks in batches for better network efficiency
        let missing_blocks_rev: Vec<_> = missing_blocks.into_iter().rev().collect();
        // `missing_blocks_rev` is the contiguous range of heights ending at
        // `main_tip_height`
        let first_missing_height = (main_tip_height + 1) - missing_blocks_rev.len() as u32;
        let mut next_idx: usize = 0;
        let mut wait_polls: u32 = 0;
        while next_idx < missing_blocks_rev.len() {
            if cancel.is_cancelled() {
                tracing::warn!("Block sync interrupted");
                return Err(error::Sync::Shutdown);
            }

            let next_height = first_missing_height + next_idx as u32;
            let batch_size = match block_data_gap {
                Some(gap) if gap.contains(next_height) => {
                    let wait_msg = format!(
                        "waiting for the node's background sync: block data is available \
                         up to height {} and above the snapshot base at height {}, next \
                         needed block is at height {next_height}",
                        gap.background_height, gap.snapshot_base_height,
                    );
                    if wait_polls.is_multiple_of(WAIT_LOG_EVERY) {
                        tracing::info!("{wait_msg}");
                    } else {
                        tracing::debug!("{wait_msg}");
                    }
                    wait_polls += 1;
                    tokio::select! {
                        () = cancel.cancelled() => {
                            tracing::warn!("Block sync interrupted");
                            return Err(error::Sync::Shutdown);
                        }
                        () = tokio::time::sleep(BACKGROUND_SYNC_POLL_INTERVAL) => {}
                    }
                    block_data_gap = self::block_data_gap(dbs, main_rpc_client).await?;
                    continue;
                }
                // Below the gap: don't let the batch run into it.
                Some(gap) if next_height <= gap.background_height => {
                    wait_polls = 0;
                    BLOCK_FETCH_BATCH_SIZE.min((gap.background_height - next_height + 1) as usize)
                }
                // Above the snapshot base, or no background sync: every
                // remaining block is available.
                _ => {
                    wait_polls = 0;
                    BLOCK_FETCH_BATCH_SIZE
                }
            };
            let batch_end = (next_idx + batch_size).min(missing_blocks_rev.len());

            let blocks =
                fetch_blocks_batch(main_rpc_client, &missing_blocks_rev[next_idx..batch_end])
                    .await?;
            total_blocks_synced += blocks.len();

            let rwtxn = dbs.write_txn()?;
            let invalid_block = self.handle_block_batch_and_commit(rwtxn, &blocks, event_tx)?;
            if let Some(invalid_block) = invalid_block {
                tracing::warn!(
                    block_hash = %invalid_block.block_hash,
                    "stopping batch sync early: an invalid block was encountered"
                );
                return Ok(Some(invalid_block));
            }
            next_idx = batch_end;
        }

        tracing::info!(
            "Synced {total_blocks_synced} blocks in {:?}",
            start.elapsed()
        );
        Ok(None)
    }
}

/// What a sync listens to and reports on: cancellation in, header-sync
/// progress and connect/disconnect events out.
pub struct SyncSignals {
    pub cancel: CancellationToken,
    pub header_sync_progress_tx: tokio::sync::watch::Sender<HeaderSyncProgress>,
    pub event_tx: broadcast::Sender<Event>,
}

impl BlockHandler<'_> {
    /// Returns `Some(InvalidBlock)` if a block was rejected as invalid; the
    /// sync stops at the invalid block's parent.
    pub(in crate::validator) async fn sync_to_tip<MainClient>(
        &self,
        main_rpc_client: &MainClient,
        main_rest_client: Option<&MainRestClient>,
        main_blocks_dir: Option<PathBuf>,
        main_tip: BlockHash,
        signals: SyncSignals,
    ) -> Result<Option<InvalidBlock>, error::Sync>
    where
        MainClient: bitcoin_jsonrpsee::client::MainClient + Sync,
    {
        let () = sync_headers(
            self.dbs,
            main_rest_client,
            main_rpc_client,
            main_tip,
            &signals.header_sync_progress_tx,
            signals.cancel.clone(),
        )
        .await?;
        self.sync_blocks(
            &signals.event_tx,
            main_rpc_client,
            main_blocks_dir,
            main_tip,
            signals.cancel.clone(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{Block, BlockHash, Transaction, hashes::Hash as _};
    use miette::{IntoDiagnostic as _, Result};

    use super::*;
    use crate::validator::test_utils::{
        TestBlockParts, build_test_block, create_test_dbs, test_block_header,
    };

    fn test_handler(dbs: &crate::validator::dbs::Dbs) -> BlockHandler<'_> {
        BlockHandler::new(
            dbs,
            bitcoin::Network::Regtest,
            crate::types::NetworkParams::for_network(bitcoin::Network::Regtest),
        )
    }

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                ..Default::default()
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    fn block_with_coinbase(prev_hash: BlockHash) -> Block {
        let txdata = vec![coinbase_tx()];
        let merkle_root = bitcoin::merkle_tree::calculate_root(
            txdata
                .iter()
                .map(Transaction::compute_txid)
                .map(|txid| *txid.as_raw_hash()),
        )
        .map(bitcoin::TxMerkleNode::from_raw_hash)
        .unwrap();
        Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: prev_hash,
                merkle_root,
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata,
        }
    }

    /// Template smoke: a block connects (accepted, tip advances, event
    /// emitted) and disconnects (tip rewinds) with the empty rule set.
    #[test]
    fn connect_disconnect_roundtrip_through_handler() -> Result<()> {
        let (_dir, dbs) = create_test_dbs()?;
        let handler = test_handler(&dbs);
        let mut rwtxn = dbs.write_txn().into_diagnostic()?;

        let block = block_with_coinbase(BlockHash::all_zeros());
        let block_hash = block.header.block_hash();
        dbs.block_hashes
            .put_headers(&mut rwtxn, &[(block.header, 0)])
            .into_diagnostic()?;

        let event = handler
            .connect_block(&mut rwtxn, &block)
            .into_diagnostic()?;
        match event {
            super::Event::ConnectBlock { header_info, .. } => {
                assert_eq!(header_info.block_hash, block_hash);
            }
            other => panic!("expected ConnectBlock event, got {other:?}"),
        }
        assert_eq!(
            dbs.current_chain_tip
                .try_get(&rwtxn, &())
                .into_diagnostic()?,
            Some(block_hash)
        );

        let mut events = Vec::new();
        handler
            .disconnect_block(&mut rwtxn, &mut events, block_hash)
            .into_diagnostic()?;
        assert!(matches!(
            events.as_slice(),
            [super::Event::DisconnectBlock { block_hash: event_hash }] if *event_hash == block_hash
        ));
        assert_eq!(
            dbs.current_chain_tip
                .try_get(&rwtxn, &())
                .into_diagnostic()?,
            None
        );
        Ok(())
    }

    #[test]
    fn fatal_batch_error_broadcasts_no_events() -> Result<()> {
        let (_dir, dbs) = create_test_dbs()?;
        let block_a = build_test_block(BlockHash::all_zeros(), TestBlockParts::default());
        let block_b = build_test_block(block_a.block_hash(), TestBlockParts::default());

        // Only the first header is present. Looking up the second block's
        // height fails after the first block has already been applied to the
        // write transaction.
        {
            let mut rwtxn = dbs.write_txn().into_diagnostic()?;
            dbs.block_hashes
                .put_headers(&mut rwtxn, &[(block_a.header, 0)])
                .into_diagnostic()?;
            rwtxn.commit().into_diagnostic()?;
        }

        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(16);
        let rwtxn = dbs.write_txn().into_diagnostic()?;
        let result =
            test_handler(&dbs).handle_block_batch_and_commit(rwtxn, &[block_a, block_b], &event_tx);

        assert!(result.is_err(), "the missing header must fail the batch");
        assert!(
            event_rx.try_recv().is_err(),
            "an aborted batch must not broadcast events"
        );
        let rotxn = dbs.read_txn().into_diagnostic()?;
        assert!(
            dbs.current_chain_tip
                .try_get(&rotxn, &())
                .into_diagnostic()?
                .is_none(),
            "the first block must roll back with the failed batch"
        );
        Ok(())
    }

    #[test]
    fn rejected_batch_broadcasts_committed_prefix() -> Result<()> {
        let (_dir, dbs) = create_test_dbs()?;
        let block_a = build_test_block(BlockHash::all_zeros(), TestBlockParts::default());
        let block_a_hash = block_a.block_hash();
        // No coinbase, so the block is rejected as non-fatal after block_a
        // has been applied.
        let block_b = Block {
            header: test_block_header(block_a_hash),
            txdata: Vec::new(),
        };
        let block_b_hash = block_b.block_hash();
        {
            let mut rwtxn = dbs.write_txn().into_diagnostic()?;
            dbs.block_hashes
                .put_headers(&mut rwtxn, &[(block_a.header, 0), (block_b.header, 1)])
                .into_diagnostic()?;
            rwtxn.commit().into_diagnostic()?;
        }

        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(16);
        let rwtxn = dbs.write_txn().into_diagnostic()?;
        let invalid_block = test_handler(&dbs)
            .handle_block_batch_and_commit(rwtxn, &[block_a, block_b], &event_tx)
            .into_diagnostic()?
            .expect("block_b must be reported as invalid");

        assert_eq!(
            invalid_block.block_hash, block_b_hash,
            "the reported invalid block must be the offending one, so that the \
             caller invalidates the right block on the node"
        );
        let event = event_rx.try_recv().into_diagnostic()?;
        assert!(matches!(
            event,
            super::Event::ConnectBlock { header_info, .. }
                if header_info.block_hash == block_a_hash
        ));
        assert!(
            event_rx.try_recv().is_err(),
            "the rejected block and unprocessed tail must not emit events"
        );
        let rotxn = dbs.read_txn().into_diagnostic()?;
        assert_eq!(
            dbs.current_chain_tip
                .try_get(&rotxn, &())
                .into_diagnostic()?,
            Some(block_a_hash),
            "the valid prefix must be committed before its event is broadcast"
        );
        Ok(())
    }

    fn dummy_block_hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    /// Build a contiguous header chain as the RPC fallback sees it: the block
    /// hashes from the `getblockhash` batch, and the raw hex headers from the
    /// `getblockheader <hash> false` batch.
    fn rpc_header_chain(len: usize) -> (Vec<BlockHash>, Vec<bitcoin::block::Header>) {
        let mut previous_block_hash = BlockHash::all_zeros();
        let mut block_hashes = Vec::with_capacity(len);
        let mut headers = Vec::with_capacity(len);
        for offset in 0..len {
            let mut header = test_block_header(previous_block_hash);
            header.nonce = u32::try_from(offset).expect("test chain is short");
            previous_block_hash = header.block_hash();
            block_hashes.push(previous_block_hash);
            headers.push(header);
        }
        (block_hashes, headers)
    }

    fn raw_headers(headers: &[bitcoin::block::Header]) -> Vec<String> {
        headers
            .iter()
            .map(bitcoin::consensus::encode::serialize_hex)
            .collect()
    }

    #[test]
    fn rpc_header_batch_accepts_a_contiguous_segment() {
        let start_height = 42;
        let (block_hashes, headers) = rpc_header_chain(3);
        let start_block_hash = block_hashes[0];

        let validated = validate_rpc_header_batch(
            start_block_hash,
            start_height,
            block_hashes.clone(),
            raw_headers(&headers),
        )
        .expect("a contiguous header segment must be accepted");

        assert_eq!(
            validated,
            headers
                .into_iter()
                .zip(block_hashes)
                .enumerate()
                .map(|(offset, (header, block_hash))| (
                    header,
                    block_hash,
                    start_height + offset as u32
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rpc_header_batch_rejects_a_stale_start_hash() {
        let (block_hashes, headers) = rpc_header_chain(2);
        let start_block_hash = dummy_block_hash(0x42);
        let err =
            validate_rpc_header_batch(start_block_hash, 42, block_hashes, raw_headers(&headers))
                .expect_err("the requested starting hash must still be active");
        assert!(matches!(
            err,
            error::Sync::BlockNotInActiveChain { block_hash }
                if block_hash == start_block_hash
        ));
    }

    #[test]
    fn rpc_header_batch_rejects_a_mismatched_computed_hash() {
        let (block_hashes, mut headers) = rpc_header_chain(2);
        let start_block_hash = block_hashes[0];
        headers[1].nonce = headers[1].nonce.wrapping_add(1);
        let err = validate_rpc_header_batch(
            start_block_hash,
            42,
            block_hashes.clone(),
            raw_headers(&headers),
        )
        .expect_err("the serialized header must hash to the requested block");
        assert!(matches!(
            err,
            error::Sync::BlockNotInActiveChain { block_hash }
                if block_hash == block_hashes[1]
        ));
    }

    #[test]
    fn rpc_header_batch_rejects_broken_parent_adjacency() {
        let (mut block_hashes, mut headers) = rpc_header_chain(2);
        let start_block_hash = block_hashes[0];
        headers[1].prev_blockhash = dummy_block_hash(0x42);
        // Keep the requested hash consistent with the returned header, so that
        // adjacency is the only broken invariant.
        block_hashes[1] = headers[1].block_hash();
        let err = validate_rpc_header_batch(
            start_block_hash,
            42,
            block_hashes.clone(),
            raw_headers(&headers),
        )
        .expect_err("each header must descend from the preceding response");
        assert!(matches!(
            err,
            error::Sync::BlockNotInActiveChain { block_hash }
                if block_hash == block_hashes[1]
        ));
    }

    #[test]
    fn rpc_header_batch_rejects_a_malformed_header() {
        let (block_hashes, _) = rpc_header_chain(1);
        let err = validate_rpc_header_batch(
            block_hashes[0],
            42,
            block_hashes,
            vec!["not hex".to_owned()],
        )
        .expect_err("a header that does not deserialize must be rejected");
        assert!(matches!(err, error::Sync::DeserializeHex(_)));
    }
}
