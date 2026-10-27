//! P2P network parameters derived from the node's chain.

use bitcoin::{
    consensus::{Encodable as _, encode::VarInt},
    hashes::{Hash as _, HashEngine as _, sha256d},
    p2p::Magic,
};

use crate::types::Fork;

/// The default signet's challenge, a 1-of-2 multisig.
const DEFAULT_SIGNET_CHALLENGE_HEX: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";

/// The message-start bytes of the signet with challenge `signet_challenge`
/// (BIP325). eCash builds hash a `"ecash"` tag ahead of the challenge, so
/// their signets never share a magic with Bitcoin's.
///
/// <https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki#message-start>
pub fn compute_signet_magic(fork: Fork, signet_challenge: &bitcoin::Script) -> Magic {
    let tag = (fork != Fork::Bitcoin).then_some("ecash");
    let mut hasher = sha256d::Hash::engine();
    // Core streams strings and the challenge vector with a CompactSize length
    // prefix, so encode lengths with Bitcoin's CompactSize rather than a raw
    // single byte, which would diverge (and wrap mod 256) for challenges of
    // 253 bytes or more.
    for bytes in tag
        .map(str::as_bytes)
        .into_iter()
        .chain([signet_challenge.as_bytes()])
    {
        VarInt(bytes.len() as u64)
            .consensus_encode(&mut hasher)
            .expect("hash engine writes are infallible");
        hasher.input(bytes);
    }
    let hash = sha256d::Hash::from_engine(hasher);
    Magic::from_bytes(hash[..=3].try_into().unwrap())
}

/// Whether `signet_challenge` is the default signet's.
pub fn is_default_signet_challenge(signet_challenge: &bitcoin::Script) -> bool {
    hex::encode(signet_challenge.as_bytes()) == DEFAULT_SIGNET_CHALLENGE_HEX
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example from BIP325.
    #[test]
    fn bip325_example_challenge() {
        let signet_challenge = bitcoin::ScriptBuf::from_hex(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be43051ae",
        )
        .unwrap();
        let magic = compute_signet_magic(Fork::Bitcoin, signet_challenge.as_script());
        assert_eq!(magic, Magic::from_bytes([0x7e, 0xc6, 0x53, 0xa5]));
    }

    /// A real P2SH signet challenge.
    #[test]
    fn known_challenge() {
        let signet_challenge =
            bitcoin::ScriptBuf::from_hex("a91484fa7c2460891fe5212cb08432e21a4207909aa987").unwrap();
        let magic = compute_signet_magic(Fork::Bitcoin, signet_challenge.as_script());
        assert_eq!(magic, Magic::from_bytes([0xe4, 0x09, 0xe9, 0x68]));
    }

    /// For challenges of 253 bytes or more the length prefix must be a
    /// CompactSize, not a single byte, otherwise the derived magic diverges
    /// from Bitcoin Core. This 253-byte challenge encodes its length as
    /// CompactSize `fd fd 00`; Core logs the derived message-start magic as
    /// `ae285478` for it.
    #[test]
    fn long_challenge_matches_core() {
        let signet_challenge = bitcoin::ScriptBuf::from_bytes(vec![0x51; 253]);
        let magic = compute_signet_magic(Fork::Bitcoin, signet_challenge.as_script());
        assert_eq!(magic, Magic::from_bytes([0xae, 0x28, 0x54, 0x78]));
    }

    /// The magics eCash v1.0.0 logs as `Signet derived magic` for these
    /// challenges.
    #[test]
    fn ecash_signet_magic_matches_the_ecash_node() {
        for (challenge_hex, magic) in [
            ("51", [0x15, 0xe0, 0x05, 0x70]),
            (
                "a91484fa7c2460891fe5212cb08432e21a4207909aa987",
                [0x95, 0x14, 0x9a, 0xa4],
            ),
        ] {
            let challenge = bitcoin::ScriptBuf::from_hex(challenge_hex).unwrap();
            assert_eq!(
                compute_signet_magic(Fork::Ecash, &challenge),
                Magic::from_bytes(magic),
                "{challenge_hex}"
            );
        }
    }

    #[test]
    fn default_signet_challenge_is_recognized() {
        let default = bitcoin::ScriptBuf::from_hex(DEFAULT_SIGNET_CHALLENGE_HEX).unwrap();
        assert!(is_default_signet_challenge(&default));
        assert!(!is_default_signet_challenge(
            &bitcoin::ScriptBuf::from_bytes(vec![0x51])
        ));
    }
}
