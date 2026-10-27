//! Types shared across the validator, wallet and RPC layers.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use bdk_wallet::chain::{ChainPosition, ConfirmationBlockTime};
use bitcoin::{Amount, BlockHash, Sequence, Transaction, Txid, Work, absolute::LockTime};
use clap::ValueEnum;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::proto::{StatusBuilder, ToStatus};

/// The build of Bitcoin Core the node runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Fork {
    Bitcoin,
    EcashAlphanet,
    EcashBetanet,
    Ecash,
}

impl Fork {
    /// The fork a node's user agent names. Only eCash renames it, so
    /// alphanet and betanet nodes detect as Bitcoin.
    pub fn detect(subversion: &str) -> Self {
        if subversion.starts_with("/eCash") {
            Self::Ecash
        } else {
            Self::Bitcoin
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin",
            Self::EcashAlphanet => "ecash-alphanet",
            Self::EcashBetanet => "ecash-betanet",
            Self::Ecash => "ecash",
        }
    }
}

impl fmt::Display for Fork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Network parameters, resolved from the node's fork and chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkParams {
    pub fork: Fork,
    /// Blocks strictly below this height are plain Bitcoin history: they are
    /// recorded, but not validated against the enforcer's rules. `0`
    /// enforces from genesis.
    pub activation_height: u32,
    /// P2P message-start bytes. `None` means the stock magic for the
    /// reported network.
    pub network_magic: Option<[u8; 4]>,
    /// The `nLockTime` that marks a transaction as valid on this fork only.
    /// `None` on Bitcoin.
    pub replay_protection_lock_time: Option<u32>,
}

impl NetworkParams {
    /// Bitcoin's parameters, without a signet's magic.
    pub const fn for_network(_network: bitcoin::Network) -> Self {
        Self {
            fork: Fork::Bitcoin,
            activation_height: 0,
            network_magic: None,
            replay_protection_lock_time: None,
        }
    }

    pub fn new(
        fork: Fork,
        network: bitcoin::Network,
        signet_challenge: Option<&bitcoin::Script>,
    ) -> Self {
        let mut params = Self {
            fork,
            network_magic: signet_challenge
                .map(|challenge| crate::p2p::compute_signet_magic(fork, challenge).to_bytes()),
            ..Self::for_network(network)
        };
        // eCash builds rebrand every chain's magic to `eca5 <fork> <chain>`,
        // and keep betanet's fork byte everywhere except mainnet. Each fork
        // activates on mainnet at its fork height, a retarget boundary.
        let (lock_time, fork_byte, mainnet_activation_height, mainnet_magic) = match fork {
            Fork::Bitcoin => return params,
            Fork::EcashAlphanet => (499_999_999, 0xa1, 963_648, [0xec, 0xa5, 0xa1, 0x04]),
            Fork::EcashBetanet => (499_999_999, 0xb1, 967_680, [0xec, 0xa5, 0xb1, 0x04]),
            Fork::Ecash => (499_999_998, 0xb1, 973_728, [0xec, 0xa5, 0xdc, 0xb7]),
        };
        params.replay_protection_lock_time = Some(lock_time);
        params.network_magic = match network {
            bitcoin::Network::Bitcoin => {
                params.activation_height = mainnet_activation_height;
                Some(mainnet_magic)
            }
            bitcoin::Network::Signet => params.network_magic,
            bitcoin::Network::Testnet => Some([0xec, 0xa5, fork_byte, 0x14]),
            bitcoin::Network::Testnet4 => Some([0xec, 0xa5, fork_byte, 0x24]),
            bitcoin::Network::Regtest => Some([0xec, 0xa5, fork_byte, 0x34]),
        };
        params
    }

    /// The fork's replay-protection `nLockTime`, or `None` on Bitcoin.
    pub fn replay_protection(&self) -> Option<LockTime> {
        self.replay_protection_lock_time.map(|height| {
            LockTime::from_height(height).expect("replay-protection nLockTime is a block height")
        })
    }

    /// The `nLockTime` of a transaction the enforcer builds itself: the
    /// fork's replay-protection value, so it never confirms on Bitcoin, or
    /// none on Bitcoin. Pair it with [`input_sequence`] so it is enforced.
    pub fn spend_lock_time(&self) -> LockTime {
        self.replay_protection().unwrap_or(LockTime::ZERO)
    }

    /// Whether `OP_CHECKLOCKTIMEVERIFY` fails, whatever its argument, in a
    /// transaction with this `nLockTime`. The fork's nodes refuse their
    /// replay-protection value there: it sits just below the height/time
    /// threshold, so it would otherwise satisfy every height lock. Rules that
    /// execute scripts must refuse it too.
    pub fn cltv_rejects_lock_time(&self, lock_time: LockTime) -> bool {
        self.replay_protection() == Some(lock_time)
    }

    /// `<fork>/<chain>`. Like Bitcoin Core, a custom signet's directory is
    /// suffixed with its magic.
    pub fn data_dir(
        &self,
        network: bitcoin::Network,
        signet_challenge: Option<&bitcoin::Script>,
    ) -> PathBuf {
        let chain = match network {
            bitcoin::Network::Bitcoin => "mainnet".to_owned(),
            bitcoin::Network::Testnet => "testnet3".to_owned(),
            bitcoin::Network::Testnet4 => "testnet4".to_owned(),
            bitcoin::Network::Signet => match (signet_challenge, self.network_magic) {
                (Some(challenge), Some(magic))
                    if !crate::p2p::is_default_signet_challenge(challenge) =>
                {
                    format!("signet_{}", hex::encode(magic))
                }
                _ => "signet".to_owned(),
            },
            bitcoin::Network::Regtest => "regtest".to_owned(),
        };
        Path::new(self.fork.name()).join(chain)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct HeaderInfo {
    pub block_hash: BlockHash,
    pub prev_block_hash: BlockHash,
    pub height: u32,
    pub work: Work,
    pub timestamp: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockInfo {
    pub coinbase_txid: Txid,
}

#[derive(Clone, Debug)]
pub enum Event {
    ConnectBlock {
        header_info: HeaderInfo,
        block_info: BlockInfo,
    },
    DisconnectBlock {
        block_hash: BlockHash,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BDKWalletTransaction {
    pub txid: bitcoin::Txid,
    pub tx: Arc<Transaction>,
    pub chain_position: ChainPosition<ConfirmationBlockTime>,
    pub fee: Amount,
    pub received: Amount,
    pub sent: Amount,
}

#[derive(Debug)]
pub enum FeePolicy {
    Absolute(Amount),
    Rate(bitcoin::FeeRate),
}

impl From<Amount> for FeePolicy {
    fn from(amount: Amount) -> Self {
        Self::Absolute(amount)
    }
}

impl From<bitcoin::FeeRate> for FeePolicy {
    fn from(fee_rate: bitcoin::FeeRate) -> Self {
        Self::Rate(fee_rate)
    }
}

#[derive(Debug, Diagnostic, Error)]
#[error("Amount overflow")]
pub struct AmountOverflowError;

impl ToStatus for AmountOverflowError {
    fn builder(&self) -> StatusBuilder<'_> {
        StatusBuilder::new(self)
    }
}

#[derive(Debug, Diagnostic, Error)]
#[error("Amount underflow")]
pub struct AmountUnderflowError;

impl ToStatus for AmountUnderflowError {
    fn builder(&self) -> StatusBuilder<'_> {
        StatusBuilder::new(self)
    }
}

/// The `nSequence` of an input with no relative lock in a transaction with
/// nLockTime `lock_time`: non-final when a lock time is set, so it is
/// enforced; final otherwise.
pub fn input_sequence(lock_time: LockTime) -> Sequence {
    if lock_time == LockTime::ZERO {
        Sequence::MAX
    } else {
        Sequence::ENABLE_RBF_NO_LOCKTIME
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On eCash, transactions the enforcer builds carry the replay-protection
    /// lock time with non-final inputs, and CLTV refuses that lock time. On
    /// Bitcoin neither applies.
    #[test]
    fn replay_protection_follows_the_fork() {
        let ecash = NetworkParams::new(Fork::Ecash, bitcoin::Network::Regtest, None);
        let lock_time = ecash.spend_lock_time();
        assert_eq!(lock_time.to_consensus_u32(), 499_999_998);
        assert_eq!(input_sequence(lock_time), Sequence::ENABLE_RBF_NO_LOCKTIME);
        assert!(ecash.cltv_rejects_lock_time(lock_time));
        assert!(!ecash.cltv_rejects_lock_time(LockTime::from_consensus(100)));

        let bitcoin = NetworkParams::for_network(bitcoin::Network::Regtest);
        assert_eq!(bitcoin.spend_lock_time(), LockTime::ZERO);
        assert_eq!(input_sequence(LockTime::ZERO), Sequence::MAX);
        assert!(!bitcoin.cltv_rejects_lock_time(lock_time));
    }

    /// Each eCash fork activates at its mainnet fork height, with its
    /// rebranded magic and replay-protection lock time; Bitcoin enforces
    /// from genesis with the stock magic.
    #[test]
    fn forks_resolve_their_mainnet_parameters() {
        let mainnet = |fork| NetworkParams::new(fork, bitcoin::Network::Bitcoin, None);
        assert_eq!(
            mainnet(Fork::Bitcoin),
            NetworkParams::for_network(bitcoin::Network::Bitcoin)
        );
        for (fork, height, magic, lock_time) in [
            (
                Fork::EcashAlphanet,
                963_648,
                [0xec, 0xa5, 0xa1, 0x04],
                499_999_999,
            ),
            (
                Fork::EcashBetanet,
                967_680,
                [0xec, 0xa5, 0xb1, 0x04],
                499_999_999,
            ),
            (Fork::Ecash, 973_728, [0xec, 0xa5, 0xdc, 0xb7], 499_999_998),
        ] {
            let params = mainnet(fork);
            assert_eq!(params.activation_height, height, "{fork}");
            assert_eq!(params.network_magic, Some(magic), "{fork}");
            assert_eq!(
                params.replay_protection_lock_time,
                Some(lock_time),
                "{fork}"
            );
        }
    }

    /// eCash v1.0.0 keeps betanet's `b1` fork byte on its test chains.
    #[test]
    fn ecash_test_chains_use_the_betanet_fork_byte() {
        let magic = |network| NetworkParams::new(Fork::Ecash, network, None).network_magic;
        assert_eq!(
            magic(bitcoin::Network::Regtest),
            Some([0xec, 0xa5, 0xb1, 0x34])
        );
        assert_eq!(
            magic(bitcoin::Network::Testnet),
            Some([0xec, 0xa5, 0xb1, 0x14])
        );
        assert_eq!(
            magic(bitcoin::Network::Testnet4),
            Some([0xec, 0xa5, 0xb1, 0x24])
        );
        assert_eq!(
            NetworkParams::new(Fork::Ecash, bitcoin::Network::Regtest, None).activation_height,
            0,
            "only mainnet has a fork height"
        );
    }

    #[test]
    fn data_dir_is_fork_then_chain() {
        let dir = |fork, network| NetworkParams::new(fork, network, None).data_dir(network, None);
        assert_eq!(
            dir(Fork::Bitcoin, bitcoin::Network::Bitcoin),
            Path::new("bitcoin/mainnet")
        );
        assert_eq!(
            dir(Fork::Ecash, bitcoin::Network::Regtest),
            Path::new("ecash/regtest")
        );
        let challenge = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        let params = NetworkParams::new(Fork::Ecash, bitcoin::Network::Signet, Some(&challenge));
        assert_eq!(
            params.data_dir(bitcoin::Network::Signet, Some(&challenge)),
            Path::new("ecash/signet_15e00570"),
            "a custom signet's directory carries its magic"
        );
    }

    #[test]
    fn only_ecash_renames_its_user_agent() {
        assert_eq!(Fork::detect("/eCash Satoshi:31.1.0/"), Fork::Ecash);
        assert_eq!(Fork::detect("/Satoshi:31.0.0/"), Fork::Bitcoin);
    }
}
