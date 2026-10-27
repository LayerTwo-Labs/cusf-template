//! The integration-test harness: processes, setup, mining and the trials.

pub mod block_verdict;
pub mod integration_test;
pub mod mine;
pub mod setup;
pub mod signet_chain_params;
pub mod signet_miner;
mod test_file_based_block_parser;
mod test_gbt_during_initial_sync;
mod test_gbt_rule_ack;
mod test_generate_to_address;
mod test_mempool_dat_sync;
mod test_no_secrets_in_logs;
mod test_node_requirements;
mod test_replay_protection;
mod test_rest_disabled_header_sync;
mod test_testmempoolaccept_no_insert;
mod test_unconfirmed_transactions;
mod test_wallet_encrypted_restart;
mod test_wallet_large_gap_sync;
mod test_wallet_less_block_template;
mod test_wallet_reorg_multi_block;
mod test_zmq_sequence_gap;
pub mod util;
