//! The enforcer's BDK wallet.

use std::{
    collections::HashMap,
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use bdk_chain::ChainPosition;
use bdk_electrum::{
    BdkElectrumClient,
    electrum_client::{self, ElectrumApi},
};
use bdk_esplora::esplora_client;
use bdk_wallet::{
    self, KeychainKind,
    keys::{DerivableKey as _, ExtendedKey, bip39::Mnemonic},
};
use bitcoin::{
    Amount, BlockHash, Network, Transaction, Txid, hashes::Hash as _, script::PushBytesBuf,
};
use bitcoin_jsonrpsee::{
    client::{GetRawTransactionClient, GetRawTransactionVerbose, MainClient as _},
    jsonrpsee::http_client::HttpClient,
};
use either::Either;
use futures::TryFutureExt;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    block_producer::BlockProducer,
    cli::{Config, WalletConfig, WalletSyncSource, redact_embedded_credentials},
    convert,
    errors::ErrorChain,
    types::BDKWalletTransaction,
    validator::Validator,
    wallet::{
        error::WalletInitialization,
        mnemonic::{EncryptedMnemonic, KdfParams, new_mnemonic},
        seed_store::{Seed, SeedStore},
        util::{RwLockReadGuardSome, RwLockUpgradableReadGuardSome, RwLockWriteGuardSome},
    },
};

mod block_producer;
pub mod error;
mod locks;
pub mod mnemonic;
mod seed_store;
mod sync;
mod sync_state;
mod thread_safe_connection;
mod util;

pub(crate) type Persistence = thread_safe_connection::ThreadSafeConnection;
type PersistenceError = <Persistence as bdk_wallet::AsyncWalletPersister>::Error;
type BdkWallet = bdk_wallet::PersistedWallet<Persistence>;

type ElectrumClient = BdkElectrumClient<bdk_electrum::electrum_client::Client>;
type EsploraClient = bdk_esplora::esplora_client::AsyncClient;

/// SLIP-44 coin type for the BIP 44 account path's second level. SLIP-44
/// registers `0` for Bitcoin and reserves `1` for *all* test networks.
pub(crate) const fn slip44_coin_type(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        _ => 1,
    }
}

#[non_exhaustive]
enum ChainSourceClient {
    Electrum(Box<ElectrumClient>),
    Esplora(EsploraClient),
}

/// Retry loop for a sync backend that was not reachable when the wallet was
/// created. Returned by [`Wallet::new`] for the caller to spawn.
pub struct ChainSourceInitTask {
    config: WalletConfig,
    network: Network,
    /// Weak, so that a wallet that has been dropped ends the retry loop.
    state: sync_state::WeakSyncState,
}

impl ChainSourceInitTask {
    /// Publishes the client into the wallet's sync state once the backend
    /// comes up. Returns without publishing on a non-transient error,
    /// on `cancel`, or once the wallet itself has been dropped.
    pub async fn run(self, cancel: CancellationToken) {
        const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(500);
        const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);
        let mut retry_delay = INITIAL_RETRY_DELAY;
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(retry_delay) => (),
            }
            let Some(state) = self.state.upgrade() else {
                return;
            };
            match WalletInner::try_init_chain_source_client(&self.config, self.network).await {
                Ok(client) => {
                    tracing::info!("wallet sync backend became available");
                    state.publish_client(client);
                    return;
                }
                Err(err) if err.is_transient() => {
                    state.set_last_error(&err);
                    retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
                    tracing::warn!(
                        %err,
                        "wallet sync backend not ready, retrying in {retry_delay:?}",
                    );
                }
                Err(err) => {
                    state.set_last_error(&err);
                    tracing::error!(
                        "wallet sync backend initialization failed, the wallet will \
                         operate without a sync source: {:#}",
                        ErrorChain::new(&err)
                    );
                    return;
                }
            }
        }
    }
}

const fn default_esplora_url(network: Network) -> Option<&'static str> {
    match network {
        // No public default beyond regtest: operators supply their own
        // Esplora endpoint via `--wallet-esplora-url`.
        Network::Regtest => Some("http://localhost:3003"),
        _ => None,
    }
}

/// The effective esplora URL, applying the per-network default when unset.
fn esplora_endpoint(
    config: &WalletConfig,
    network: Network,
) -> Result<url::Url, error::InitEsploraClient> {
    match config.esplora_url.as_ref() {
        Some(url) => Ok(url.clone()),
        None => {
            let default_url = default_esplora_url(network)
                .ok_or(error::InitEsploraClient::MissingUrl { network })?;
            Ok(url::Url::parse(default_url)?)
        }
    }
}

/// The effective electrum endpoint (`host:port`), applying per-network
/// defaults for whichever of host and port is unset.
fn electrum_endpoint(
    config: &WalletConfig,
    network: Network,
) -> Result<String, error::InitElectrumClient> {
    let (electrum_host, electrum_port) =
        match (config.electrum_host.as_deref(), config.electrum_port) {
            (Some(host), Some(port)) => (host, port),
            (host, port) => {
                let (default_host, default_port) = default_electrum_host_port(network)
                    .ok_or(error::InitElectrumClient::MissingHostPort { network })?;
                (host.unwrap_or(default_host), port.unwrap_or(default_port))
            }
        };
    Ok(format!("{electrum_host}:{electrum_port}"))
}

/// The configured sync backend endpoint, for reporting in wallet info:
/// `host:port` for electrum, a URL with any embedded credentials redacted for
/// esplora. `None` when the sync source is disabled, or when no endpoint is
/// known for the network.
fn sync_backend_endpoint(config: &WalletConfig, network: Network) -> Option<String> {
    match config.sync_source {
        WalletSyncSource::Electrum => electrum_endpoint(config, network).ok(),
        WalletSyncSource::Esplora => {
            let url = esplora_endpoint(config, network).ok()?.to_string();
            Some(redact_embedded_credentials(&url).unwrap_or(url))
        }
        WalletSyncSource::Disabled => None,
    }
}

const fn default_electrum_host_port(network: Network) -> Option<(&'static str, u16)> {
    match network {
        // No public default beyond regtest: operators supply their own
        // Electrum endpoint via `--wallet-electrum-host`/`--wallet-electrum-port`.
        Network::Regtest =>
        // Default for mempool/electrs
        {
            Some(("127.0.0.1", 60401))
        }
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletStatus {
    /// No seed has been persisted.
    Uninitialized,
    /// An encrypted seed is persisted but not loaded.
    Locked,
    /// The BDK wallet is loaded and serving.
    Unlocked,
}

/// Chronological sort key for a wallet transaction: the confirmation time if
/// it is confirmed, otherwise the time it was last seen in the mempool. BDK
/// reports no `last_seen` for a transaction it has not seen since a reorg
/// orphaned it, and those sort first. The TXID is only a tie-breaker.
///
/// Comparing one key per transaction is a total order, which comparing
/// timestamps for some pairs and TXIDs for the rest is not: those two
/// relations disagree, so mixing them yields cycles, and the sort panics with
/// "user-provided comparison function does not correctly implement a total
/// order" when it notices.
fn wallet_transaction_sort_key(tx: &BDKWalletTransaction) -> (Option<u64>, Txid) {
    let timestamp = match tx.chain_position {
        ChainPosition::Confirmed { anchor, .. } => Some(anchor.confirmation_time),
        ChainPosition::Unconfirmed { last_seen, .. } => last_seen,
    };
    (timestamp, tx.txid)
}

struct WalletInner {
    main_client: HttpClient,
    producer: BlockProducer,
    /// The BDK wallet and its persistence. Held together so that we
    /// ensure at build time that the correct order is applied.
    locks: locks::WalletLocks,
    seed_store: SeedStore,
    seed_is_encrypted: bool,
    sync_state: sync_state::SharedSyncState,
    config: Config,
}

impl WalletInner {
    fn validator(&self) -> &Validator {
        self.producer.validator()
    }
}

impl WalletInner {
    async fn init_esplora_client(
        config: &WalletConfig,
        network: Network,
    ) -> Result<EsploraClient, error::InitEsploraClient> {
        let esplora_url = esplora_endpoint(config, network)?;

        // Redacted: an esplora URL may carry credentials
        tracing::info!(
            esplora_url = %redact_embedded_credentials(esplora_url.as_str())
                .unwrap_or_default(),
            "creating esplora client"
        );

        // URLs with a port number at the end get a `/` when turned back into a string, for
        // some reason. The Esplora library doesn't like that! Remove it.
        let client = esplora_client::Builder::new(esplora_url.as_str().trim_end_matches("/"))
            .build_async()
            .map_err(error::InitEsploraClient::BuildEsploraClient)?;

        let height = client
            .get_height()
            .await
            .map_err(error::InitEsploraClient::EsploraClientHeight)?;

        tracing::info!(height = height, "esplora client initialized");
        Ok(client)
    }

    /// Initialize electrum client
    fn init_electrum_client(
        config: &WalletConfig,
        network: Network,
    ) -> Result<ElectrumClient, error::InitElectrumClient> {
        let electrum_url = electrum_endpoint(config, network)?;

        tracing::debug!(%electrum_url, "creating electrum client");
        // Apply a reasonably short timeout to prevent the wallet from hanging
        let timeout = std::time::Duration::from_secs(5);
        let config = electrum_client::ConfigBuilder::new()
            .timeout(Some(timeout))
            .build();
        let electrum_client = electrum_client::Client::from_config(&electrum_url, config)
            .map_err(error::InitElectrumClient::CreateElectrumClient)?;
        let header = electrum_client
            .block_header(0)
            .map_err(error::InitElectrumClient::GetInitialBlockHeader)?;
        // Verify the Electrum server is on the same chain as we are.
        if header.block_hash().as_byte_array() != network.chain_hash().as_bytes() {
            return Err(error::InitElectrumClient::ChainMismatch {
                electrum_block_hash: header.block_hash(),
                wallet_chain_hash: network.chain_hash(),
            });
        }
        Ok(BdkElectrumClient::new(electrum_client))
    }

    async fn try_init_chain_source_client(
        config: &WalletConfig,
        network: Network,
    ) -> Result<ChainSourceClient, error::InitChainSourceClient> {
        match config.sync_source {
            WalletSyncSource::Electrum => {
                // The electrum client does synchronous socket I/O (with a 5s
                // timeout), which must not stall a runtime worker thread.
                let config = config.clone();
                tokio::task::spawn_blocking(move || Self::init_electrum_client(&config, network))
                    .await
                    .expect("electrum client init task panicked")
                    .map(|client| ChainSourceClient::Electrum(Box::new(client)))
                    .map_err(error::InitChainSourceClient::from)
            }
            WalletSyncSource::Esplora => Self::init_esplora_client(config, network)
                .await
                .map(ChainSourceClient::Esplora)
                .map_err(error::InitChainSourceClient::from),
            WalletSyncSource::Disabled => {
                unreachable!("callers check for a disabled sync source")
            }
        }
    }

    /// The sync backend may not be reachable yet when the enforcer starts.
    /// Rather than blocking startup, a transient connection failure hands the
    /// retrying off to a [`ChainSourceInitTask`], returned here for the
    /// caller to spawn. The returned state is seeded with the startup failure
    /// (if any), so wallet info can report it meanwhile.
    async fn init_chain_source(
        config: &WalletConfig,
        network: Network,
    ) -> Result<
        (sync_state::SharedSyncState, Option<ChainSourceInitTask>),
        error::InitChainSourceClient,
    > {
        if config.sync_source == WalletSyncSource::Disabled {
            return Ok((sync_state::SharedSyncState::default(), None));
        }
        match Self::try_init_chain_source_client(config, network).await {
            Ok(client) => Ok((sync_state::SharedSyncState::with_client(client), None)),
            Err(err) if err.is_transient() => {
                tracing::warn!(
                    %err,
                    "wallet sync backend not reachable at startup, \
                     continuing without it and retrying in the background",
                );
                let state = sync_state::SharedSyncState::with_last_error(Some(format!(
                    "{:#}",
                    ErrorChain::new(&err)
                )));
                let init_task = ChainSourceInitTask {
                    config: config.clone(),
                    network,
                    state: state.downgrade(),
                };
                Ok((state, Some(init_task)))
            }
            Err(err) => Err(err),
        }
    }

    fn chain_source_client(&self) -> Option<Arc<ChainSourceClient>> {
        self.sync_state.client()
    }

    /// Record the outcome of an interaction with the sync backend, so wallet
    /// info can report a backend that is currently failing. Passes the result
    /// through unchanged.
    pub(in crate::wallet) fn record_sync_backend_result<T, E>(
        &self,
        result: Result<T, E>,
    ) -> Result<T, E>
    where
        E: std::error::Error,
    {
        self.sync_state.record_result(result)
    }

    fn bip84_descriptors(
        mnemonic: &Mnemonic,
        network: bdk_wallet::bitcoin::Network,
        coin_type: u32,
    ) -> Result<(String, String), error::InitWalletFromMnemonic> {
        let extended_key: ExtendedKey = mnemonic.clone().into_extended_key()?;

        let xpriv = extended_key
            .into_xprv(network.into())
            .ok_or(error::InitWalletFromMnemonic::DeriveXpriv)?;

        Ok((
            format!("wpkh({xpriv}/84'/{coin_type}'/0'/0/*)"),
            format!("wpkh({xpriv}/84'/{coin_type}'/0'/1/*)"),
        ))
    }

    /// Insists on exactly these descriptors. `Ok(None)` if the database holds
    /// no wallet yet.
    async fn load_bdk_wallet(
        external_desc: &str,
        internal_desc: &str,
        network: bdk_wallet::bitcoin::Network,
        wallet_database: &mut Persistence,
    ) -> Result<Option<BdkWallet>, bdk_wallet::LoadWithPersistError<PersistenceError>> {
        bdk_wallet::Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc.to_owned()))
            .descriptor(KeychainKind::Internal, Some(internal_desc.to_owned()))
            .extract_keys()
            .check_network(network)
            .load_wallet_async(wallet_database)
            .await
    }

    async fn initialize_wallet_from_mnemonic(
        mnemonic: &Mnemonic,
        network: bdk_wallet::bitcoin::Network,
        wallet_database: &mut Persistence,
    ) -> Result<BdkWallet, error::InitWalletFromMnemonic> {
        let coin_type = slip44_coin_type(network);
        let (external_desc, internal_desc) = Self::bip84_descriptors(mnemonic, network, coin_type)?;

        tracing::debug!(%coin_type, "Attempting load of existing BDK wallet");
        let loaded =
            Self::load_bdk_wallet(&external_desc, &internal_desc, network, wallet_database).await;

        let bitcoin_wallet = match loaded {
            Ok(Some(wallet)) => {
                tracing::info!("Loaded existing BDK wallet");
                wallet
            }

            Ok(None) => {
                tracing::info!(%coin_type, "Creating new BDK wallet");

                bdk_wallet::Wallet::create(external_desc, internal_desc)
                    .network(network)
                    .create_wallet_async(wallet_database)
                    .await?
            }

            Err(err) => return Err(err.into()),
        };

        Ok(bitcoin_wallet)
    }

    async fn new(
        data_dir: &Path,
        config: &Config,
        main_client: HttpClient,
        producer: BlockProducer,
    ) -> Result<(Self, Option<ChainSourceInitTask>), error::InitWallet> {
        let network = {
            let validator_network = producer.validator().network();
            bdk_wallet::bitcoin::Network::from_str(validator_network.to_string().as_str())?
        };
        if network == bdk_wallet::bitcoin::Network::Signet && producer.signet_challenge().is_none()
        {
            return Err(error::InitWallet::NoSignetChallengeFound);
        }

        let database_path = data_dir.join("wallet.sqlite.db");

        tracing::info!(
            data_dir = %data_dir.display(),
            database_path = %database_path.display(),
            "Instantiating {} wallet",
            network,
        );

        let mut wallet_database = thread_safe_connection::ThreadSafeConnection::open(database_path)
            .await
            .map_err(error::InitWallet::OpenConnection)?;

        let (sync_state, chain_source_init) =
            Self::init_chain_source(&config.wallet_opts, network).await?;

        // If we:
        // 1. Already have an initialized wallet
        // 2. It's plaintext
        //
        // We can just go ahead and unlock the wallet right away.
        let seed_store = SeedStore::new(data_dir);

        let stored_seed = seed_store.read_mnemonic().await?;
        let seed_is_encrypted = matches!(stored_seed, Some(Either::Right(_)));
        let bitcoin_wallet = match stored_seed {
            Some(Either::Left(mnemonic)) => {
                tracing::debug!("found plaintext mnemonic, going straight to initialization");
                let initialized = WalletInner::initialize_wallet_from_mnemonic(
                    &mnemonic,
                    network,
                    &mut wallet_database,
                )
                .await?;
                Some(initialized)
            }
            _ => None,
        };

        tracing::debug!(
            message = "wallet inner: wired together components",
            wallet_initialized = bitcoin_wallet.is_some()
        );

        let inner = Self {
            config: config.clone(),
            main_client,
            producer,
            locks: locks::WalletLocks::new(bitcoin_wallet, wallet_database),
            seed_store,
            seed_is_encrypted,
            sync_state,
        };
        Ok((inner, chain_source_init))
    }

    async fn status(&self) -> WalletStatus {
        if self.locks.read_slot().await.is_some() {
            WalletStatus::Unlocked
        } else if self.seed_is_encrypted {
            WalletStatus::Locked
        } else {
            WalletStatus::Uninitialized
        }
    }

    async fn read_wallet(&self) -> Result<RwLockReadGuardSome<'_, BdkWallet>, error::NotUnlocked> {
        self.locks.read().await
    }

    /// Obtain an upgradable read lock on the inner wallet
    async fn read_wallet_upgradable(
        &self,
    ) -> Result<RwLockUpgradableReadGuardSome<'_, BdkWallet>, error::NotUnlocked> {
        self.locks.upgradable_read().await
    }

    async fn write_wallet(
        &self,
    ) -> Result<RwLockWriteGuardSome<'_, BdkWallet>, error::NotUnlocked> {
        self.locks.write().await
    }

    /// Apply an unconfirmed transaction to the wallet, marking the wallet
    /// UTXOs it spends as spent, and persist. Returns whether anything
    /// changed.
    async fn apply_unconfirmed_tx(
        &self,
        tx: bdk_wallet::bitcoin::Transaction,
    ) -> Result<bool, error::ApplyUnconfirmedTx> {
        let last_seen = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut wallet_write = self.write_wallet().await?;
        let mut bdk_db = self.locks.db(&wallet_write).await;
        let changed = wallet_write
            .with_mut(|wallet| {
                wallet.apply_unconfirmed_txs([(tx, last_seen)]);
                wallet.persist_async(&mut bdk_db)
            })
            .await?;
        drop(bdk_db);
        drop(wallet_write);
        Ok(changed)
    }

    pub async fn create_new_wallet(
        &self,
        mnemonic: Option<Mnemonic>,
        password: Option<&str>,
    ) -> Result<(), error::CreateNewWallet> {
        let (mnemonic, generated) = match mnemonic {
            Some(mnemonic) => (mnemonic, false),
            None => {
                tracing::info!("create new wallet: no mnemonic provided, generating fresh");
                (new_mnemonic()?, true)
            }
        };

        let birthday_height = if generated {
            let info = self
                .main_client
                .get_blockchain_info()
                .await
                .map_err(|err| {
                    error::CreateNewWallet::FetchBirthdayHeight(error::BitcoinCoreRPC {
                        method: "getblockchaininfo".to_owned(),
                        error: err,
                    })
                })?;
            Some(info.blocks)
        } else {
            None
        };

        match password {
            Some(password) => {
                tracing::info!("create new wallet: persisting encrypted mnemonic");
                let encrypted =
                    EncryptedMnemonic::encrypt(&mnemonic, password, KdfParams::CURRENT)?;
                self.seed_store
                    .insert_seed(Seed::Encrypted(&encrypted), birthday_height)
                    .await?;
            }
            None => {
                tracing::info!(
                    "create new wallet: no password provided, persisting plaintext mnemonic"
                );
                self.seed_store
                    .insert_seed(Seed::Plaintext(&mnemonic), birthday_height)
                    .await?;
            }
        }

        // Same lock order as other places
        let mut write_guard = self.locks.write_slot().await;
        let mut database = self.locks.db(&write_guard).await;
        let network = self.validator().network();
        let wallet =
            WalletInner::initialize_wallet_from_mnemonic(&mnemonic, network, &mut database).await?;
        drop(database);
        *write_guard = Some(wallet);
        drop(write_guard);
        Ok(())
    }

    pub async fn unlock_existing_wallet(
        &self,
        password: &str,
    ) -> Result<(), error::UnlockExistingWallet> {
        if self.locks.read_slot().await.is_some() {
            return Err(WalletInitialization::AlreadyUnlocked.into());
        }

        // Read the mnemonic from the database.
        let read = self.seed_store.read_mnemonic().await?;

        tracing::debug!("unlock wallet: read from DB");

        // Verify that it is encrypted!
        let encrypted = match read {
            None => {
                return Err(WalletInitialization::NotFound.into());
            }
            // Plaintext!
            Some(Either::Left(_)) => {
                return Err(error::UnlockExistingWallet::NotEncrypted);
            }
            Some(Either::Right(encrypted)) => encrypted,
        };

        tracing::debug!("unlock wallet: decrypting mnemonic");

        let mnemonic = encrypted.decrypt(password).map_err(|err| {
            tracing::error!("failed to decrypt mnemonic: {:#}", ErrorChain::new(&err));
            WalletInitialization::InvalidPassword
        })?;

        let mut write_guard = self.locks.write_slot().await;
        let mut database = self.locks.db(&write_guard).await;
        let network = self.validator().network();

        tracing::debug!("unlock wallet: initializing BDK wallet struct");
        let wallet =
            WalletInner::initialize_wallet_from_mnemonic(&mnemonic, network, &mut database).await?;
        drop(database);
        *write_guard = Some(wallet);
        drop(write_guard);

        tracing::info!("unlock wallet: initialized wallet");
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct CreateTransactionParams {
    /// Optional fee policy to use for the transaction
    pub fee_policy: Option<crate::types::FeePolicy>,
    /// Optional OP_RETURN message to include in the transaction
    pub op_return_message: Option<Vec<u8>>,
    /// Optional UTXOs that must be included in the transaction
    pub required_utxos: Vec<bdk_wallet::bitcoin::OutPoint>,
    /// If set, sends ALL UTXOs in the wallet to this address.
    /// Incompatible with `required_utxos`.
    pub drain_wallet_to: Option<bdk_wallet::bitcoin::Address>,
}

pub struct WalletInfo {
    /// Public (i.e. without private keys) descriptors for the wallet
    pub keychain_descriptors: std::collections::HashMap<
        bdk_wallet::KeychainKind,
        bdk_wallet::descriptor::ExtendedDescriptor,
    >,
    pub network: bdk_wallet::bitcoin::Network,
    pub transaction_count: usize,
    pub unspent_output_count: usize,
    pub tip: (BlockHash, u32),
    pub sync_source: SyncSourceInfo,
}

/// The wallet's sync source and its observed status.
pub struct SyncSourceInfo {
    pub kind: WalletSyncSource,
    /// The effective backend endpoint, with credentials redacted. `None`
    /// when the sync source is disabled.
    pub endpoint: Option<String>,
    /// Whether a connection to the backend has been established. A backend
    /// that is unreachable at startup is retried in the background.
    pub connected: bool,
    /// The most recent error from the backend -- a failed connection attempt
    /// or a failed sync. `None` while the backend is healthy.
    pub last_error: Option<String>,
    /// Time of the last successful wallet sync.
    pub last_synced_at: Option<SystemTime>,
}

/// Cheap to clone, since it uses Arc internally
#[derive(Clone)]
pub struct Wallet {
    inner: Arc<WalletInner>,
}

impl Wallet {
    /// Also returns the retry task for a sync backend that was unreachable at
    /// startup (if any), which the caller is responsible for spawning.
    pub async fn new(
        data_dir: &Path,
        config: &Config,
        main_client: HttpClient,
        producer: BlockProducer,
    ) -> Result<(Self, Option<ChainSourceInitTask>), error::InitWallet> {
        let (inner, chain_source_init) =
            WalletInner::new(data_dir, config, main_client, producer).await?;
        let wallet = Self {
            inner: Arc::new(inner),
        };
        Ok((wallet, chain_source_init))
    }

    /// The keyless block producer underneath this wallet.
    pub fn producer(&self) -> &BlockProducer {
        &self.inner.producer
    }

    pub async fn sync_task(&self, cancel: CancellationToken) -> Result<(), miette::Report> {
        const SYNC_INTERVAL: Duration = Duration::from_secs(15);
        tracing::debug!(
            interval = %jiff::SignedDuration::try_from(SYNC_INTERVAL).unwrap(),
            "wallet sync task: starting"
        );

        loop {
            tokio::select! {
                biased;  // Prioritize shutdown

                () = cancel.cancelled() => {
                    tracing::info!("shutting down sync task");
                    return Ok(());
                }
                // A fresh sleep per iteration: the idle gap is measured from
                // the end of the previous sync, so a sync that outlasts the
                // interval never causes back-to-back runs.
                () = tokio::time::sleep(SYNC_INTERVAL) => {
                    let tick = Uuid::new_v4().simple();
                    let span = tracing::span!(tracing::Level::DEBUG,
                        "wallet_sync",
                        %tick,
                    );
                    let guard = span.enter();
                    if !self.inner.sync_state.has_synced() {
                        // Initial sync is incomplete, nothing to do
                        tracing::debug!(
                            "waiting for initial wallet sync to complete"
                        );
                    } else if let Err(err) = self.inner.sync().await {
                        tracing::error!("wallet sync error: {:#}", ErrorChain::new(&err));
                    }
                    drop(guard);
                }
            }
        }
    }

    pub(crate) fn parse_checked_address(
        &self,
        address: &str,
    ) -> Result<bitcoin::Address, connectrpc::ConnectError> {
        let network = self.validator().network();
        let address = bdk_wallet::bitcoin::Address::from_str(address).map_err(|err| {
            connectrpc::ConnectError::invalid_argument(format!("invalid bitcoin address: {err:#}"))
        })?;

        let address = address.require_network(network).map_err(|_| {
            connectrpc::ConnectError::invalid_argument(format!(
                "bitcoin address is not valid for network `{network}`",
            ))
        })?;

        Ok(address)
    }

    /// Full scan the wallet against the chain source. Fails with
    /// [`error::FullScan::ScanInProgress`] rather than queueing if a scan is
    /// already running.
    pub async fn full_scan(&self) -> miette::Result<BlockHash, error::FullScan> {
        self.inner.try_full_scan().await
    }

    pub async fn status(&self) -> WalletStatus {
        self.inner.status().await
    }

    /// Whether the BDK wallet is loaded, i.e. [`WalletStatus::Unlocked`].
    pub async fn is_initialized(&self) -> bool {
        self.inner.locks.read_slot().await.is_some()
    }

    pub fn validator(&self) -> &Validator {
        self.inner.validator()
    }

    fn create_op_return_output<Msg>(
        msg: Msg,
    ) -> Result<bdk_wallet::bitcoin::TxOut, <bitcoin::script::PushBytesBuf as TryFrom<Msg>>::Error>
    where
        PushBytesBuf: TryFrom<Msg>,
    {
        let op_return_txout = bitcoin::TxOut {
            script_pubkey: bitcoin::ScriptBuf::new_op_return(PushBytesBuf::try_from(msg)?),
            value: bitcoin::Amount::ZERO,
        };
        Ok(bdk_wallet::bitcoin::TxOut {
            script_pubkey: bdk_wallet::bitcoin::ScriptBuf::from_bytes(
                op_return_txout.script_pubkey.to_bytes(),
            ),
            value: op_return_txout.value,
        })
    }

    pub async fn get_wallet_balance(
        &self,
    ) -> Result<(bdk_wallet::Balance, bool), error::GetWalletBalance> {
        let has_synced = self.inner.sync_state.has_synced();

        let balance = self.inner.read_wallet().await?.balance();

        Ok((balance, has_synced))
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "false positive for `bitcoin_wallet`"
    )]
    #[instrument(skip_all)]
    pub async fn list_wallet_transactions(
        &self,
    ) -> Result<Vec<BDKWalletTransaction>, error::ListWalletTransactions> {
        // Massage the wallet data into a format that we can use to calculate fees, etc.
        let wallet_data = {
            let wallet_read = self.inner.read_wallet().await?;
            let transactions = wallet_read.transactions();

            transactions
                .into_iter()
                .map(|tx| {
                    let txid = tx.tx_node.txid;
                    let chain_position = tx.chain_position;
                    let tx = tx.tx_node.tx.clone();

                    let output_ownership: Vec<_> = tx
                        .output
                        .iter()
                        .map(|output| {
                            (
                                output.value,
                                wallet_read.is_mine(output.script_pubkey.clone()),
                            )
                        })
                        .collect();

                    // Just collect the inputs - we'll get their values using getrawtransaction later
                    let inputs = tx.input.clone();

                    (txid, tx, chain_position, output_ownership, inputs)
                })
                .collect::<Vec<_>>()
        };

        // Calculate fees, received, and sent amounts
        let mut txs = Vec::new();
        for (txid, tx, chain_position, output_ownership, inputs) in wallet_data {
            let mut input_value = Amount::ZERO;
            let mut output_value = Amount::ZERO;
            let mut received = Amount::ZERO;
            let mut sent = Amount::ZERO;

            // Calculate output value and received amount
            for (value, is_mine) in output_ownership {
                output_value += value;
                if is_mine {
                    received += value;
                }
            }

            // Get input values using getrawtransaction
            let mut prev_txouts = Vec::new();
            for input in inputs {
                // Coinbase transactions have an empty prev output txid, which we'll be unable to fetch
                if input.previous_output.txid == bitcoin::Txid::all_zeros() {
                    continue;
                }

                let transaction_hex = self
                    .inner
                    .main_client
                    // TODO: get rid of this. It's kind of absurd that we're calling out to getrawtransaction for every input.
                    // Both from a performance point of view, as well as requiring txindex. Would be better to somehow
                    // persist the relevant values in the wallet DB
                    .get_raw_transaction(
                        input.previous_output.txid,
                        GetRawTransactionVerbose::<false>,
                        None,
                    )
                    .await
                    .map_err(|err| error::ListWalletTransactions::FetchTransaction {
                        txid: input.previous_output.txid,
                        source: error::BitcoinCoreRPC {
                            method: "getrawtransaction".to_string(),
                            error: err,
                        },
                    })?;

                let prev_output =
                    bitcoin::consensus::encode::deserialize_hex::<Transaction>(&transaction_hex)?;

                let prev_txout = prev_output.output[input.previous_output.vout as usize].clone();
                input_value += prev_txout.value;
                prev_txouts.push(prev_txout);
            }

            // One wallet read covers every input of this tx, instead of
            // re-acquiring the lock per input.
            {
                let wallet_read = self.inner.read_wallet().await?;
                for prev_txout in prev_txouts {
                    if wallet_read.is_mine(prev_txout.script_pubkey) {
                        sent += prev_txout.value;
                    }
                }
            }

            let fee = input_value
                .checked_sub(output_value)
                .unwrap_or(Amount::ZERO);
            // Calculate net wallet change (excluding fee)
            // We need to handle received and sent separately since Amount can't be negative
            let (final_received, final_sent) = if received >= sent {
                (received - sent, Amount::from_sat(0)) // Net gain to wallet
            } else {
                (Amount::from_sat(0), sent - received - fee) // Net loss from wallet
            };

            txs.push(BDKWalletTransaction {
                txid,
                tx,
                chain_position,
                fee,
                received: final_received,
                sent: final_sent,
            });
        }

        // Make sure that the transaction list is in chronological order.
        txs.sort_by_key(wallet_transaction_sort_key);
        Ok(txs)
    }

    fn build_send_psbt(
        wallet: &mut bdk_wallet::Wallet,
        destinations: HashMap<bitcoin::Address, Amount>,
        params: CreateTransactionParams,
        replay_protection: Option<bitcoin::absolute::LockTime>,
    ) -> Result<bdk_wallet::bitcoin::psbt::Psbt, error::CreateSendPsbt> {
        let mut timestamp = Instant::now();
        let mut builder = wallet.build_tx();
        Self::apply_replay_protection(&mut builder, replay_protection);

        if let Some(op_return_message) = params.op_return_message {
            let op_return_output = Self::create_op_return_output(op_return_message)?;
            // Keep the OP_RETURN at output 0: BDK shuffles outputs by default.
            builder.ordering(bdk_wallet::TxOrdering::Untouched);
            builder.add_recipient(op_return_output.script_pubkey, op_return_output.value);

            tracing::debug!("Added OP_RETURN output in {:?}", timestamp.elapsed());
            timestamp = Instant::now();
        }

        let destinations_len = destinations.len();

        // Add outputs for each destination address
        for (address, value) in destinations {
            builder.add_recipient(address.script_pubkey(), value);
        }

        tracing::debug!(
            "Added {} destinations in {:?}",
            destinations_len,
            timestamp.elapsed()
        );
        timestamp = Instant::now();

        if let Some(drain_wallet_to) = params.drain_wallet_to {
            tracing::debug!("Draining wallet to {}", drain_wallet_to);
            builder
                .drain_to(drain_wallet_to.script_pubkey())
                .drain_wallet();
        }

        if !params.required_utxos.is_empty() {
            builder
                // TODO: this does not work at all for wallets past a certain scale....
                // 25s pr. UTXO for a wallet with 40k UTXOs in total
                .add_utxos(&params.required_utxos)
                .map_err(|err| match err {
                    bdk_wallet::tx_builder::AddUtxoError::UnknownUtxo(outpoint) => {
                        error::CreateSendPsbt::UnknownUTXO(outpoint)
                    }
                })?;

            builder.manually_selected_only();

            tracing::debug!(
                "Added {} required UTXOs in {:?}",
                params.required_utxos.len(),
                timestamp.elapsed()
            );
            timestamp = Instant::now();
        }

        match params.fee_policy {
            Some(crate::types::FeePolicy::Absolute(fee)) => {
                builder.fee_absolute(fee);
            }
            Some(crate::types::FeePolicy::Rate(rate)) => {
                builder.fee_rate(rate);
            }
            None => (),
        }

        tracing::debug!("Set fee policy in {:?}", timestamp.elapsed());
        timestamp = Instant::now();

        builder
            .finish()
            .inspect(|_| {
                tracing::debug!("Finished transaction builder in {:?}", timestamp.elapsed());
            })
            .map_err(error::CreateSendPsbt::CreateTx)
    }

    async fn create_send_psbt(
        &self,
        destinations: HashMap<bitcoin::Address, Amount>,
        params: CreateTransactionParams,
    ) -> Result<bdk_wallet::bitcoin::psbt::Psbt, error::CreateSendPsbt> {
        let replay_protection = self.validator().network_params().replay_protection();
        let mut wallet_write = self.inner.write_wallet().await?;
        tokio::task::block_in_place(|| {
            wallet_write.with_mut(|wallet| {
                Self::build_send_psbt(wallet, destinations, params, replay_protection)
            })
        })
    }

    /// Stamp the replay-protection `nLockTime`, with non-final inputs so it
    /// is enforced. Without one, BDK's default lock time stands.
    pub(crate) fn apply_replay_protection<Cs>(
        builder: &mut bdk_wallet::TxBuilder<'_, Cs>,
        replay_protection: Option<bitcoin::absolute::LockTime>,
    ) {
        let Some(lock_time) = replay_protection else {
            return;
        };
        builder
            .nlocktime(lock_time)
            .set_exact_sequence(crate::types::input_sequence(lock_time));
    }

    /// Creates a transaction, sends it, and returns the TXID.
    pub async fn send_wallet_transaction(
        &self,
        destinations: HashMap<bdk_wallet::bitcoin::Address, Amount>,
        params: CreateTransactionParams,
    ) -> Result<bitcoin::Txid, error::SendWalletTransaction> {
        tracing::debug!(
            destinations = destinations.len(),
            required_utxos = params.required_utxos.len(),
            drain_wallet = params.drain_wallet_to.is_some(),
            "Sending wallet transaction",
        );
        let mut timestamp = Instant::now();
        let psbt = self.create_send_psbt(destinations, params).await?;

        tracing::debug!("Created send PSBT in {:?}", timestamp.elapsed());
        timestamp = Instant::now();

        let tx = self.sign_transaction(psbt).await?;
        let txid = tx.compute_txid();

        tracing::info!(
            %txid,
            "Signed send transaction in {:?}, {} bytes",
            timestamp.elapsed(),
            {
                let tx_bytes = bdk_wallet::bitcoin::consensus::serialize(&tx);
                tx_bytes.len()
            },
        );
        timestamp = Instant::now();

        if crate::rpc_client::broadcast_transaction(&self.inner.main_client, &tx)
            .await
            .map_err(error::SendWalletTransaction::BroadcastTx)?
            .is_none()
        {
            let err = error::SendWalletTransaction::NonstandardTxNotSupported;
            tracing::error!(%txid, "{:#}", ErrorChain::new(&err));
            return Err(err);
        }
        tracing::info!(%txid, "Broadcast send transaction in {:?}", timestamp.elapsed());

        // Apply the unconfirmed transaction to the wallet
        let applied_changes = self.inner.apply_unconfirmed_tx(tx).await?;

        // `applied_changes` is false if the mempool `accept_tx` hook, which runs
        // in a background task once bitcoind accepts the broadcast, got there
        // first.
        if applied_changes {
            tracing::debug!(%txid, "Applied unconfirmed transaction to wallet");
        } else {
            tracing::debug!(
                %txid,
                "Unconfirmed transaction already applied to wallet (likely by mempool accept_tx)"
            );
        }

        Ok(convert::bdk_txid_to_bitcoin_txid(txid))
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "false positive for `bitcoin_wallet`"
    )]
    #[instrument(skip_all)]
    pub async fn get_utxos(&self) -> Result<Vec<bdk_wallet::LocalOutput>, error::NotUnlocked> {
        let wallet_read = self.inner.read_wallet().await?;
        let utxos = wallet_read.list_unspent().collect::<Vec<_>>();

        Ok(utxos)
    }

    async fn sign_transaction(
        &self,
        psbt: bdk_wallet::bitcoin::psbt::Psbt,
    ) -> Result<bdk_wallet::bitcoin::Transaction, error::WalletSignTransaction> {
        self.sign_transaction_inner(psbt, false).await
    }

    async fn sign_transaction_inner(
        &self,
        mut psbt: bdk_wallet::bitcoin::psbt::Psbt,
        skip_fee_rate_check: bool,
    ) -> Result<bdk_wallet::bitcoin::Transaction, error::WalletSignTransaction> {
        let mut timestamp = Instant::now();

        if !self
            .inner
            .read_wallet()
            .await
            .map_err(error::WalletSignTransaction::NotUnlocked)?
            .sign(&mut psbt, bdk_wallet::SignOptions::default())
            .map_err(error::WalletSignTransaction::SignerError)?
        {
            return Err(error::WalletSignTransaction::UnableToSign);
        }

        tracing::debug!("Signed transaction in {:?}", timestamp.elapsed());
        timestamp = Instant::now();

        let tx = if skip_fee_rate_check {
            psbt.extract_tx_unchecked_fee_rate()
        } else {
            psbt.extract_tx()
                .map_err(error::WalletSignTransaction::ExtractTx)?
        };

        tracing::debug!("Extracted transaction in {:?}", timestamp.elapsed());
        Ok(tx)
    }

    pub async fn get_wallet_info(&self) -> Result<WalletInfo, error::NotUnlocked> {
        let sync_state::SyncStateReport {
            connected,
            last_error,
            last_synced_at,
        } = self.inner.sync_state.report();

        let w = self.inner.read_wallet().await?;
        let mut keychain_descriptors = std::collections::HashMap::new();
        for (kind, _) in w.keychains() {
            keychain_descriptors.insert(kind, w.public_descriptor(kind).clone());
        }

        let tip = {
            let tip = w.local_chain().tip();
            (tip.hash(), tip.height())
        };

        let wallet_opts = &self.inner.config.wallet_opts;
        let sync_source = SyncSourceInfo {
            kind: wallet_opts.sync_source,
            endpoint: sync_backend_endpoint(wallet_opts, w.network()),
            connected,
            last_error,
            last_synced_at,
        };

        Ok(WalletInfo {
            keychain_descriptors,
            network: w.network(),
            transaction_count: w.transactions().count(),
            unspent_output_count: w.list_unspent().count(),
            tip,
            sync_source,
        })
    }

    #[expect(clippy::significant_drop_tightening)]
    pub async fn get_new_address(
        &self,
    ) -> Result<bdk_wallet::bitcoin::Address, error::GetNewAddress> {
        // Using next_unused_address here means that we get a new address
        // when funds are received. Without this we'd need to take care not
        // to cross the wallet scan gap.
        let mut wallet_write = self.inner.write_wallet().await?;

        let mut bdk_db_lock = self.inner.locks.db(&wallet_write).await;
        let address = wallet_write
            .with_mut(|wallet| {
                let info = wallet.next_unused_address(bdk_wallet::KeychainKind::External);
                wallet
                    .persist_async(&mut bdk_db_lock)
                    .map_ok(|_: bool| info.address)
            })
            .await?;
        Ok(address)
    }

    pub async fn unlock_existing_wallet(
        &self,
        password: &str,
    ) -> Result<(), error::UnlockExistingWallet> {
        self.inner.unlock_existing_wallet(password).await
    }

    /// Creates a new wallet with a given mnemonic and encryption password.
    /// Note that the password is NOT a BIP39 passphrase, but is only used to
    /// encrypt the mnemonic in storage.
    pub async fn create_wallet(
        &self,
        mnemonic: Option<Mnemonic>,
        password: Option<&str>,
    ) -> Result<(), error::CreateNewWallet> {
        self.inner.create_new_wallet(mnemonic, password).await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use bdk_chain::{BlockId, ConfirmationBlockTime};
    use bdk_wallet::{
        bip39::Language,
        bitcoin::{Amount, ScriptBuf, script::PushBytesBuf},
        test_utils::get_funded_wallet_wpkh,
    };
    use bitcoin::{BlockHash, hashes::Hash as _};

    use super::{
        BDKWalletTransaction, BdkWallet, ChainPosition, CreateTransactionParams, KeychainKind,
        Mnemonic, Network, Persistence, Txid, Wallet, WalletConfig, WalletInner, WalletSyncSource,
        error, slip44_coin_type,
    };
    use crate::errors::ErrorChain;

    /// The BIP 39 test mnemonic that BIP 84's published vectors derive from.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon about";

    /// Every network other than mainnet is a test network, and SLIP-44
    /// reserves coin type `1` for all of them.
    #[test]
    fn coin_type_is_zero_only_on_mainnet() {
        assert_eq!(slip44_coin_type(Network::Bitcoin), 0);
        for network in [
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            assert_eq!(slip44_coin_type(network), 1, "{network}");
        }
    }

    fn test_mnemonic() -> Mnemonic {
        Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap()
    }

    fn descriptors(network: Network) -> (String, String) {
        WalletInner::bip84_descriptors(&test_mnemonic(), network, slip44_coin_type(network))
            .unwrap()
    }

    #[test]
    fn descriptors_carry_the_network_coin_type() {
        let (external, internal) = descriptors(Network::Bitcoin);
        assert!(external.starts_with("wpkh(xprv"), "{external}");
        assert!(external.ends_with("/84'/0'/0'/0/*)"), "{external}");
        assert!(internal.ends_with("/84'/0'/0'/1/*)"), "{internal}");

        for network in [
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            let (external, internal) = descriptors(network);
            assert!(external.starts_with("wpkh(tprv"), "{network}: {external}");
            assert!(
                external.ends_with("/84'/1'/0'/0/*)"),
                "{network}: {external}"
            );
            assert!(
                internal.ends_with("/84'/1'/0'/1/*)"),
                "{network}: {internal}"
            );
        }
    }

    /// First external and internal address for `network`, derived through BDK
    /// rather than from the descriptor string, so the assertions cover the
    /// path the wallet actually takes.
    fn first_addresses(network: Network) -> (String, String) {
        let (external, internal) = descriptors(network);
        let wallet = bdk_wallet::Wallet::create(external, internal)
            .network(network)
            .create_wallet_no_persist()
            .unwrap();
        (
            wallet.peek_address(KeychainKind::External, 0).to_string(),
            wallet.peek_address(KeychainKind::Internal, 0).to_string(),
        )
    }

    /// Pins mainnet against BIP 84's published test vectors.
    #[test]
    fn mainnet_matches_bip84_test_vectors() {
        let (receive, change) = first_addresses(Network::Bitcoin);
        assert_eq!(receive, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(change, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    }

    /// The test networks derive under the test coin type, distinct from
    /// mainnet's.
    #[test]
    fn test_networks_derive_under_the_test_coin_type() {
        let (mainnet, _) = first_addresses(Network::Bitcoin);
        let (signet, _) = first_addresses(Network::Signet);
        let (regtest, _) = first_addresses(Network::Regtest);

        assert!(signet.starts_with("tb1"), "{signet}");
        assert!(regtest.starts_with("bcrt1"), "{regtest}");
        assert_ne!(mainnet, signet);
    }

    /// Open the wallet the way the enforcer does.
    async fn open_wallet(
        database: &mut Persistence,
        network: Network,
    ) -> Result<BdkWallet, error::InitWalletFromMnemonic> {
        WalletInner::initialize_wallet_from_mnemonic(&test_mnemonic(), network, database).await
    }

    async fn empty_database(dir: &temp_dir::TempDir) -> Persistence {
        Persistence::open(dir.path().join("wallet.sqlite.db"))
            .await
            .expect("must open a wallet database")
    }

    /// An empty database gets a wallet under the network's coin type.
    #[tokio::test]
    async fn a_fresh_mainnet_wallet_is_created_under_the_network_coin_type() {
        let dir = temp_dir::TempDir::new().unwrap();
        let mut database = empty_database(&dir).await;

        let wallet = open_wallet(&mut database, Network::Bitcoin)
            .await
            .expect("an empty database must yield a freshly created wallet");

        assert_eq!(
            wallet.peek_address(KeychainKind::External, 0).to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        );
    }

    /// A database holding a wallet under some other derivation is refused as
    /// a data mismatch that names what differs, not as an opaque load
    /// failure.
    #[tokio::test]
    async fn an_unrecognized_descriptor_is_a_data_mismatch() {
        let dir = temp_dir::TempDir::new().unwrap();
        let mut database = empty_database(&dir).await;
        let (external, internal) =
            WalletInner::bip84_descriptors(&test_mnemonic(), Network::Bitcoin, 7).unwrap();
        bdk_wallet::Wallet::create(external, internal)
            .network(Network::Bitcoin)
            .create_wallet_async(&mut database)
            .await
            .expect("must persist a wallet under the foreign coin type");

        let err = open_wallet(&mut database, Network::Bitcoin)
            .await
            .expect_err("a foreign descriptor must not load");

        assert!(
            matches!(err, error::InitWalletFromMnemonic::DataMismatch(_)),
            "expected a data mismatch, got: {err:#}",
        );
        let rendered = format!("{:#}", ErrorChain::new(&err));
        assert!(
            rendered.contains("Descriptor mismatch"),
            "the mismatch BDK reported must survive into the error: {rendered}",
        );
    }

    /// A shuffle lands the OP_RETURN at output 0 half the time, so one build
    /// proves nothing.
    #[test]
    fn op_return_is_always_output_zero() {
        const ROUNDS: usize = 64;

        let message = [&[13][..], &[0x11; 32][..], &[0x22; 32][..]].concat();
        let expected = ScriptBuf::new_op_return(PushBytesBuf::try_from(message.clone()).unwrap());

        for _ in 0..ROUNDS {
            let (mut wallet, _) = get_funded_wallet_wpkh();

            let psbt = Wallet::build_send_psbt(
                &mut wallet,
                HashMap::new(),
                CreateTransactionParams {
                    op_return_message: Some(message.clone()),
                    ..Default::default()
                },
                None,
            )
            .unwrap();

            let outputs = psbt.unsigned_tx.output;
            assert_eq!(outputs.len(), 2, "want an OP_RETURN and change");
            assert_eq!(outputs[0].script_pubkey, expected);
            assert_eq!(outputs[0].value, Amount::ZERO);
        }
    }

    /// On a fork with replay protection, sends carry its `nLockTime` and a
    /// non-final sequence, so the lock time is enforced. Without one, BDK's
    /// default stands.
    #[test]
    fn sends_carry_the_replay_protection_lock_time() {
        const LOCK_TIME: u32 = 499_999_998;
        let message = b"replay".to_vec();
        let build = |lock_time| {
            let (mut wallet, _) = get_funded_wallet_wpkh();
            Wallet::build_send_psbt(
                &mut wallet,
                HashMap::new(),
                CreateTransactionParams {
                    op_return_message: Some(message.clone()),
                    ..Default::default()
                },
                lock_time,
            )
            .unwrap()
            .unsigned_tx
        };

        let protected = build(Some(bitcoin::absolute::LockTime::from_consensus(LOCK_TIME)));
        assert_eq!(protected.lock_time.to_consensus_u32(), LOCK_TIME);
        assert!(
            protected.input.iter().all(
                |input| input.sequence == bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME
            )
        );

        assert_ne!(build(None).lock_time.to_consensus_u32(), LOCK_TIME);
    }

    /// A password embedded in `--wallet-esplora-url` reaches the wallet
    /// config verbatim, and wallet info is served over the API, so the
    /// endpoint reported there must be redacted the same way the startup
    /// config dump redacts it.
    #[test]
    fn reported_esplora_endpoint_redacts_credentials() {
        let config = WalletConfig {
            auto_create: false,
            esplora_url: Some(
                url::Url::parse("https://alice:hunter2@esplora.example/api").unwrap(),
            ),
            electrum_host: None,
            electrum_port: None,
            skip_periodic_sync: false,
            sync_source: WalletSyncSource::Esplora,
            max_block_by_block_replay: 2_000,
            mnemonic_path: None,
        };

        let endpoint = super::sync_backend_endpoint(&config, Network::Regtest)
            .expect("an esplora URL is configured");
        assert!(
            !endpoint.contains("hunter2"),
            "the esplora password must not be reported over the API: {endpoint}"
        );
        assert_eq!(endpoint, "https://alice:redacted@esplora.example/api");
    }

    /// Host and port default independently, so a config that sets only one of
    /// them must still report a complete endpoint.
    #[test]
    fn reported_electrum_endpoint_fills_in_defaults() {
        let config = WalletConfig {
            auto_create: false,
            esplora_url: None,
            electrum_host: None,
            electrum_port: Some(50009),
            skip_periodic_sync: false,
            sync_source: WalletSyncSource::Electrum,
            max_block_by_block_replay: 2_000,
            mnemonic_path: None,
        };

        assert_eq!(
            super::sync_backend_endpoint(&config, Network::Regtest).as_deref(),
            Some("127.0.0.1:50009"),
        );
    }

    /// A disabled sync source has no backend, so there is no endpoint to
    /// report rather than a misleading default one.
    #[test]
    fn disabled_sync_source_reports_no_endpoint() {
        let config = WalletConfig {
            auto_create: false,
            esplora_url: None,
            electrum_host: None,
            electrum_port: None,
            skip_periodic_sync: false,
            sync_source: WalletSyncSource::Disabled,
            max_block_by_block_replay: 2_000,
            mnemonic_path: None,
        };

        assert_eq!(
            super::sync_backend_endpoint(&config, Network::Regtest),
            None
        );
    }

    fn wallet_tx(
        txid_byte: u8,
        chain_position: ChainPosition<ConfirmationBlockTime>,
    ) -> BDKWalletTransaction {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        BDKWalletTransaction {
            txid: Txid::from_byte_array([txid_byte; 32]),
            tx: Arc::new(tx),
            chain_position,
            fee: Amount::ZERO,
            received: Amount::ZERO,
            sent: Amount::ZERO,
        }
    }

    /// A position confirmed at `timestamp`. Only the time matters here, not
    /// the block the transaction is anchored to.
    fn confirmed_at(timestamp: u64) -> ChainPosition<ConfirmationBlockTime> {
        let block_id = BlockId {
            height: 1,
            hash: BlockHash::from_byte_array([0xAA; 32]),
        };
        ChainPosition::Confirmed {
            anchor: ConfirmationBlockTime {
                block_id,
                confirmation_time: timestamp,
            },
            transitively: None,
        }
    }

    /// An unconfirmed position. BDK reports no `last_seen` for a transaction
    /// it has not seen since a reorg orphaned it.
    fn unconfirmed(last_seen: Option<u64>) -> ChainPosition<ConfirmationBlockTime> {
        ChainPosition::Unconfirmed {
            first_seen: last_seen,
            last_seen,
        }
    }

    fn txids(txs: &[BDKWalletTransaction]) -> Vec<Txid> {
        txs.iter().map(|tx| tx.txid).collect()
    }

    /// The three positions `list_wallet_transactions` sees, arranged so that
    /// comparing timestamps for some pairs and TXIDs for the rest is cyclic:
    /// the confirmed transaction precedes the unconfirmed one by time, which
    /// precedes the orphaned one by TXID, which precedes the confirmed one by
    /// TXID.
    fn intransitive_arrangement() -> [BDKWalletTransaction; 3] {
        let confirmed = wallet_tx(0x03, confirmed_at(10));
        let seen = wallet_tx(0x01, unconfirmed(Some(20)));
        let orphaned = wallet_tx(0x02, unconfirmed(None));
        [confirmed, seen, orphaned]
    }

    /// Sorting must be a total order. Switching relation per pair is not one,
    /// so the answer depended on the order the transactions arrived in.
    #[test]
    fn wallet_transactions_sort_in_a_total_order() {
        let [confirmed, seen, orphaned] = intransitive_arrangement();
        // Chronological, with the transaction carrying no timestamp first.
        let expected = [orphaned.txid, confirmed.txid, seen.txid];

        let mut forwards = [confirmed.clone(), seen.clone(), orphaned.clone()];
        forwards.sort_by_key(super::wallet_transaction_sort_key);
        let mut backwards = [orphaned, seen, confirmed];
        backwards.sort_by_key(super::wallet_transaction_sort_key);

        assert_eq!(txids(&forwards), expected);
        assert_eq!(txids(&backwards), expected);
    }

    /// The same mix, at a size where the standard library's sort checks the
    /// comparator it was handed and panics on one that is not a total order.
    #[test]
    fn many_wallet_transactions_sort_without_panicking() {
        const COUNT: u8 = 64;

        // A tiny LCG, so that the timestamps are shuffled with respect to the
        // TXIDs while the case stays reproducible.
        let mut seed = 1u64;
        let mut txs = Vec::with_capacity(COUNT as usize);
        for i in 0..COUNT {
            seed = seed.wrapping_mul(2862933555777941757).wrapping_add(1);
            let chain_position = match i % 3 {
                0 => confirmed_at(seed >> 58),
                1 => unconfirmed(Some(seed >> 58)),
                _ => unconfirmed(None),
            };
            txs.push(wallet_tx(i, chain_position));
        }

        txs.sort_by_key(super::wallet_transaction_sort_key);

        assert!(
            txs.is_sorted_by_key(super::wallet_transaction_sort_key),
            "the sorted list must be ordered by its own sort key"
        );
    }
}
