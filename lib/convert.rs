//! Conversions between BDK's and the enforcer's `bitcoin` crate types.

use bdk_wallet::bitcoin::hashes::Hash as _;
use bitcoin::hashes::sha256d::Hash;

pub fn bdk_txid_to_bitcoin_txid(txid: bdk_wallet::bitcoin::Txid) -> bitcoin::Txid {
    let bytes = txid.to_byte_array();

    let hash = Hash::from_byte_array(bytes);

    bitcoin::Txid::from_raw_hash(hash)
}
