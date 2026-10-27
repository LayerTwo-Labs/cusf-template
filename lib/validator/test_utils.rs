//! Shared test utilities for `crate::validator` tests.
//! This module is gated behind `#[cfg(test)]` in the parent module.

use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    hashes::Hash as _,
};
use bitcoin_jsonrpsee::jsonrpsee;
use miette::IntoDiagnostic as _;

use super::{Validator, dbs::Dbs, main_rest_client::MainRestClient};
use crate::types::NetworkParams;

pub fn create_test_dbs() -> miette::Result<(temp_dir::TempDir, Dbs)> {
    let dir = temp_dir::TempDir::new().into_diagnostic()?;
    let dbs = Dbs::new(dir.path(), bitcoin::Network::Regtest).into_diagnostic()?;
    Ok((dir, dbs))
}

/// Validator with a fresh DB in `dir`, and mainchain clients that point at
/// nothing. For tests that only exercise DB-backed methods.
pub fn dummy_validator(dir: &std::path::Path) -> Validator {
    let mainchain_client = jsonrpsee::http_client::HttpClientBuilder::default()
        .build("http://127.0.0.1:1")
        .expect("build dummy rpc client");
    let mainchain_rest_client =
        MainRestClient::new(url::Url::parse("http://127.0.0.1:1").expect("valid url"));
    Validator::new(
        mainchain_client,
        Some(mainchain_rest_client),
        None,
        dir,
        bitcoin::Network::Regtest,
        NetworkParams::for_network(bitcoin::Network::Regtest),
    )
    .expect("construct validator")
}

/// Minimal block header for tests — only `prev_blockhash` is meaningful
pub fn test_block_header(prev_blockhash: BlockHash) -> bitcoin::block::Header {
    bitcoin::block::Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash,
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(0x2000_0000),
        nonce: 0,
    }
}

#[derive(Default)]
pub struct TestBlockParts {
    pub extra_coinbase_outputs: Vec<TxOut>,
    pub extra_txs: Vec<Transaction>,
}

pub fn build_test_block(prev_hash: BlockHash, parts: TestBlockParts) -> Block {
    let mut coinbase_outputs = vec![TxOut {
        script_pubkey: ScriptBuf::new(),
        value: Amount::from_sat(50_0000_0000),
    }];
    coinbase_outputs.extend(parts.extra_coinbase_outputs);
    let coinbase_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0xFFFFFFFF,
            },
            ..TxIn::default()
        }],
        output: coinbase_outputs,
    };
    let mut txdata = vec![coinbase_tx];
    txdata.extend(parts.extra_txs);
    Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: prev_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0x2000_0000),
            nonce: 0,
        },
        txdata,
    }
}
