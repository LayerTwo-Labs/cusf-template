//! Implementation of [`cusf_enforcer_mempool::cusf_enforcer::CusfEnforcer`]

use std::{collections::HashSet, future::Future};

use bitcoin::{Block, BlockHash, Transaction, Txid, hashes::Hash as _};
use cusf_enforcer_mempool::cusf_enforcer::{
    ConnectBlockAction, CusfEnforcer, DisconnectBlockAction, SyncToTipError, TxAcceptAction,
};
use error_fatality::{Nested as _, Split};
use miette::Diagnostic;
use sneed::{RwTxn, db, env, rwtxn};
use thiserror::Error;
use tokio::sync::broadcast::error::SendError;
use tokio_util::sync::CancellationToken;

use crate::{
    errors::ErrorChain,
    proto::mainchain::HeaderSyncProgress,
    types::Event,
    validator::{
        Validator,
        task::{self, BlockHandler, error::ValidateTransaction as ValidateTransactionError},
    },
};

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct SyncError(#[from] task::error::Sync);

/// Reason a block was rejected by the enforcer's own rules while syncing to
/// tip. Surfaced as [`SyncToTipError::InvalidBlock`] so the
/// cusf-enforcer-mempool driver calls `invalidateblock` and re-syncs.
#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct InvalidBlockReason(Box<<task::error::ConnectBlock as Split>::Jfyi>);

/// Error from the read-only [`CusfEnforcer::validate_block`] dry run (DB reads).
#[derive(Debug, Diagnostic, Error)]
pub enum ValidateBlockError {
    #[error(transparent)]
    TipHeight(#[from] crate::validator::TryGetMainchainTipHeightError),
}

#[derive(Debug, Diagnostic, Error)]
enum ConnectBlockErrorInner {
    #[error(transparent)]
    CommitWriteTxn(#[from] rwtxn::error::Commit),
    #[error(transparent)]
    ConnectBlock(#[from] Box<<task::error::ConnectBlock as Split>::Fatal>),
    #[error(transparent)]
    DbPut(#[from] db::error::Put),
    #[error(transparent)]
    DbRange(Box<db::error::Range>),
    #[error(transparent)]
    DbTryGet(#[from] db::error::TryGet),
    #[error(transparent)]
    NestedWriteTxn(#[from] env::error::NestedWriteTxn),
    #[error(transparent)]
    WriteTxn(#[from] env::error::WriteTxn),
}

impl From<db::error::Range> for ConnectBlockErrorInner {
    fn from(err: db::error::Range) -> Self {
        Self::DbRange(Box::new(err))
    }
}

impl From<<task::error::ConnectBlock as Split>::Fatal> for ConnectBlockErrorInner {
    fn from(err: <task::error::ConnectBlock as Split>::Fatal) -> Self {
        Self::from(Box::new(err))
    }
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct ConnectBlockError(ConnectBlockErrorInner);

impl<Err> From<Err> for ConnectBlockError
where
    ConnectBlockErrorInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Diagnostic, Error)]
enum DisconnectBlockErrorInner {
    #[error(transparent)]
    CommitWriteTxn(#[from] rwtxn::error::Commit),
    #[error(transparent)]
    DisconnectBlock(#[from] task::error::DisconnectBlock),
    #[error(transparent)]
    WriteTxn(#[from] env::error::WriteTxn),
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct DisconnectBlockError(DisconnectBlockErrorInner);

impl<Err> From<Err> for DisconnectBlockError
where
    DisconnectBlockErrorInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Diagnostic, Error)]
enum AcceptTxErrorInner {
    #[error(transparent)]
    Commit(#[from] rwtxn::error::Commit),
    #[error(transparent)]
    Db(#[from] db::Error),
    #[error(transparent)]
    ValidateTransaction(#[from] ValidateTransactionError),
    #[error(transparent)]
    WriteTxn(#[from] env::error::WriteTxn),
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct AcceptTxError(AcceptTxErrorInner);

impl<Err> From<Err> for AcceptTxError
where
    AcceptTxErrorInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
enum RejectReason {
    #[error(transparent)]
    ConnectBlock(#[from] <task::error::ConnectBlock as Split>::Jfyi),
    #[error("Missing parent (`{parent}`) height for block hash `{block_hash}`")]
    MissingParentHeight {
        block_hash: BlockHash,
        parent: BlockHash,
    },
}

/// Connect a block, leaving `mode` to commit or abort the result.
/// The block connect happens in a child rwtxn nested in the rwtxn that
/// stores its header, so that in commit mode a rejected block still keeps
/// its header.
fn connect_block_with_mode<'validator, Mode>(
    mode: Mode,
    validator: &'validator Validator,
    block: &Block,
) -> Result<Mode::Output, ConnectBlockError>
where
    Mode: ConnectBlockMode<'validator>,
{
    let block_hash = block.block_hash();
    let parent = block.header.prev_blockhash;
    let mut parent_rwtxn = validator.dbs.write_txn()?;
    if !validator
        .dbs
        .block_hashes
        .contains_header(&parent_rwtxn, &block_hash)?
    {
        let height = if parent == BlockHash::all_zeros() {
            0
        } else if let Some(parent_height) = validator
            .dbs
            .block_hashes
            .height()
            .try_get(&parent_rwtxn, &parent)?
        {
            parent_height + 1
        } else {
            let reject_reason = RejectReason::MissingParentHeight { block_hash, parent };
            return Mode::reject(parent_rwtxn, reject_reason);
        };
        tracing::trace!("Storing header");
        validator
            .dbs
            .block_hashes
            .put_headers(&mut parent_rwtxn, &[(block.header, height)])?;
    }
    let mut child_rwtxn = validator.dbs.nested_write_txn(&mut parent_rwtxn)?;
    let handler = BlockHandler::new(&validator.dbs, validator.network, validator.network_params);
    match handler
        .connect_block(&mut child_rwtxn, block)
        .into_nested()?
    {
        Ok(event) => {
            let accepted = mode.finish_child(child_rwtxn, event, HashSet::new())?;
            Mode::finish_parent(validator, parent_rwtxn, accepted)
        }
        Err(jfyi) => {
            child_rwtxn.abort();
            Mode::reject(parent_rwtxn, RejectReason::ConnectBlock(jfyi))
        }
    }
}

/// Used to specify commit/dry-run modes
trait ConnectBlockMode<'validator>: Sized {
    type Output;
    /// Carried from finishing the child rwtxn to finishing the parent
    type Accepted;

    fn connect_block(
        self,
        validator: &'validator Validator,
        block: &Block,
    ) -> Result<Self::Output, ConnectBlockError>;

    /// The block was accepted in `child_rwtxn`. Commit or abort it.
    fn finish_child(
        self,
        child_rwtxn: RwTxn<'_>,
        event: Event,
        remove_mempool_txs: HashSet<Txid>,
    ) -> Result<Self::Accepted, ConnectBlockError>;

    /// Commit or abort the parent rwtxn, once the child is finished.
    fn finish_parent(
        validator: &'validator Validator,
        parent_rwtxn: RwTxn<'_>,
        accepted: Self::Accepted,
    ) -> Result<Self::Output, ConnectBlockError>;

    /// The block was rejected. `header_rwtxn` holds its header, if newly
    /// stored.
    fn reject(
        header_rwtxn: RwTxn<'_>,
        reason: RejectReason,
    ) -> Result<Self::Output, ConnectBlockError>;
}

/// Used to implement `ConnectBlockMode`.
/// Connects and commits a block.
struct ConnectBlockCommit;

impl<'validator> ConnectBlockMode<'validator> for ConnectBlockCommit {
    type Output = ConnectBlockAction;
    type Accepted = (Event, HashSet<Txid>);

    fn connect_block(
        self,
        validator: &'validator Validator,
        block: &Block,
    ) -> Result<Self::Output, ConnectBlockError> {
        connect_block_with_mode(self, validator, block)
    }

    fn finish_child(
        self,
        child_rwtxn: RwTxn<'_>,
        event: Event,
        remove_mempool_txs: HashSet<Txid>,
    ) -> Result<Self::Accepted, ConnectBlockError> {
        tracing::info!("accepted block");
        child_rwtxn.commit()?;
        Ok((event, remove_mempool_txs))
    }

    fn finish_parent(
        validator: &'validator Validator,
        parent_rwtxn: RwTxn<'_>,
        (event, remove_mempool_txs): Self::Accepted,
    ) -> Result<Self::Output, ConnectBlockError> {
        parent_rwtxn.commit()?;
        // Send events only once the DB txs are committed, so that a
        // subscriber reacting to one never reads state from before it.
        let _send_err: Result<usize, SendError<_>> = validator.events_tx.send(event);
        Ok(ConnectBlockAction::Accept { remove_mempool_txs })
    }

    fn reject(
        header_rwtxn: RwTxn<'_>,
        reason: RejectReason,
    ) -> Result<Self::Output, ConnectBlockError> {
        tracing::info!("rejecting block: {:#}", ErrorChain::new(&reason));
        header_rwtxn.commit()?;
        Ok(ConnectBlockAction::Reject)
    }
}

impl CusfEnforcer for Validator {
    type SyncError = SyncError;
    type InvalidBlockReason = InvalidBlockReason;

    async fn sync_to_tip<Signal>(
        &mut self,
        shutdown_signal: Signal,
        tip: BlockHash,
    ) -> Result<(), SyncToTipError<Self::InvalidBlockReason, Self::SyncError>>
    where
        Signal: Future<Output = ()> + Send,
    {
        let cancel = CancellationToken::new();

        let header_sync_progress_tx = {
            let mut header_sync_progress_rx_write = self.header_sync_progress_rx.write();
            if header_sync_progress_rx_write.is_some() {
                return Err(SyncToTipError::Other(SyncError(
                    task::error::Sync::HeaderSyncInProgress,
                )));
            }
            let (header_sync_progress_tx, header_sync_progress_rx) =
                tokio::sync::watch::channel(HeaderSyncProgress {
                    current_height: None,
                });
            *header_sync_progress_rx_write = Some(header_sync_progress_rx);
            header_sync_progress_tx
        };
        tracing::debug!(block_hash = %tip, "Syncing to tip");

        let handler = BlockHandler::new(&self.dbs, self.network, self.network_params);
        let sync_future = handler.sync_to_tip(
            &self.mainchain_client,
            self.mainchain_rest_client.as_ref(),
            self.mainchain_blocks_dir.clone(),
            tip,
            task::SyncSignals {
                cancel: cancel.clone(),
                header_sync_progress_tx,
                event_tx: self.events_tx.clone(),
            },
        );

        tokio::select! {
            result = sync_future => {
                *self.header_sync_progress_rx.write() = None;
                match result {
                    Ok(None) => Ok(()),
                    // A block was rejected by our rules while syncing: signal the
                    // driver so it `invalidateblock`s and re-syncs.
                    Ok(Some(invalid_block)) => Err(SyncToTipError::InvalidBlock {
                        block_hash: invalid_block.block_hash,
                        reason: InvalidBlockReason(invalid_block.reason),
                    }),
                    Err(err) => Err(SyncToTipError::Other(SyncError(err))),
                }
            }
            _ = shutdown_signal => {
                cancel.cancel();
                *self.header_sync_progress_rx.write() = None;
                Err(SyncToTipError::Other(SyncError(
                    crate::validator::task::error::Sync::Shutdown,
                )))
            }
        }
    }

    type ConnectBlockError = ConnectBlockError;

    async fn connect_block(
        &mut self,
        block: &Block,
    ) -> Result<ConnectBlockAction, Self::ConnectBlockError> {
        ConnectBlockCommit.connect_block(self, block)
    }

    type DisconnectBlockError = DisconnectBlockError;

    async fn disconnect_block(
        &mut self,
        block_hash: BlockHash,
    ) -> Result<DisconnectBlockAction, Self::DisconnectBlockError> {
        let mut rwtxn = self.dbs.write_txn()?;
        let handler = BlockHandler::new(&self.dbs, self.network, self.network_params);
        let mut events = Vec::new();
        let () = handler.disconnect_block(&mut rwtxn, &mut events, block_hash)?;
        rwtxn.commit()?;
        crate::validator::task::broadcast_events(&self.events_tx, events);
        Ok(DisconnectBlockAction::default())
    }

    type AcceptTxError = AcceptTxError;

    fn accept_tx(&mut self, tx: &Transaction) -> Result<TxAcceptAction, Self::AcceptTxError> {
        let mut rwtxn = self.dbs.write_txn()?;
        // A fatal error here isn't something that means we should
        // call out to the `invalidateblock` RPC. It simply means
        // the transaction will not be accepted into the mempool.
        let handler = BlockHandler::new(&self.dbs, self.network, self.network_params);
        let res = if handler.validate_tx(&mut rwtxn, tx)? {
            TxAcceptAction::Accept {
                conflicts_with: HashSet::new(),
                weight_tweak: 0,
            }
        } else {
            TxAcceptAction::Reject
        };
        Ok(res)
    }

    type ValidateBlockError = ValidateBlockError;

    /// Dry-run the enforcer's rules against `block` without mutating any
    /// state (used by `getblocktemplate` proposal mode). `Ok(None)` accepts,
    /// `Ok(Some(reason))` rejects.
    ///
    /// Fork point: validate `block` at height `tip_height + 1` here. This is
    /// synchronous and read-only, so anything it cannot resolve locally should
    /// fail closed.
    fn validate_block(&self, block: &Block) -> Result<Option<String>, Self::ValidateBlockError> {
        let Some(_tip_height) = self.try_get_block_height()? else {
            return Ok(None); // not synced yet; nothing to enforce
        };
        let _ = block;
        Ok(None)
    }
}
