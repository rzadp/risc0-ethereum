use crate::ethereum_consensus::{
    configs::Config,
    networks::Network,
    primitives::{Epoch, ExecutionAddress, Gwei, Version, FAR_FUTURE_EPOCH, U256},
};

pub const MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: usize = 1300;
pub const MIN_GENESIS_TIME: u64 = 1655647200;
pub const GENESIS_FORK_VERSION: Version = [144, 0, 0, 105];
pub const GENESIS_DELAY: u64 = 86400;
pub const SECONDS_PER_SLOT: u64 = 12;
pub const SECONDS_PER_ETH1_BLOCK: u64 = 14;
pub const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: Epoch = 256;
pub const SHARD_COMMITTEE_PERIOD: Epoch = 256;
pub const ETH1_FOLLOW_DISTANCE: u64 = 2048;
pub const EJECTION_BALANCE: Gwei = 16 * 10u64.pow(9);
pub const MIN_PER_EPOCH_CHURN_LIMIT: u64 = 4;
pub const MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: u64 = 8;
pub const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: u64 = 128 * 10u64.pow(9);
pub const MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT: u64 = 256 * 10u64.pow(9);
pub const CHURN_LIMIT_QUOTIENT: u64 = 65536;
pub const TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: Epoch = FAR_FUTURE_EPOCH;
pub const ALTAIR_FORK_VERSION: Version = [144, 0, 0, 112];
pub const ALTAIR_FORK_EPOCH: Epoch = 50;
pub const BELLATRIX_FORK_VERSION: Version = [144, 0, 0, 113];
pub const BELLATRIX_FORK_EPOCH: Epoch = 100;
pub const CAPELLA_FORK_VERSION: Version = [144, 0, 0, 114];
pub const CAPELLA_FORK_EPOCH: Epoch = 56832;
pub const DENEB_FORK_VERSION: Version = [144, 0, 0, 115];
pub const DENEB_FORK_EPOCH: Epoch = 132608;
pub const ELECTRA_FORK_VERSION: Version = [144, 0, 0, 116];
pub const ELECTRA_FORK_EPOCH: Epoch = FAR_FUTURE_EPOCH;
pub const INACTIVITY_SCORE_BIAS: u64 = 4;
pub const INACTIVITY_SCORE_RECOVERY_RATE: u64 = 16;
pub const PROPOSER_SCORE_BOOST: u64 = 40;
pub const DEPOSIT_CHAIN_ID: usize = 11155111;
pub const DEPOSIT_NETWORK_ID: usize = 11155111;

pub fn config() -> Config {
    // 17000000000000000
    let terminal_total_difficulty = U256::from_le_bytes([
        0, 128, 46, 241, 104, 101, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ]);
    let terminal_block_hash = Default::default();
    let deposit_contract_address =
        ExecutionAddress::try_from(
            [
                // 0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D
                127, 2, 195, 227, 201, 139, 19, 48, 85, 184, 179, 72, 178, 172, 98, 86, 105, 237,
                41, 93,
            ]
            .as_ref(),
        )
        .unwrap();

    Config {
        preset_base: "mainnet".to_string(),
        name: Network::Sepolia,
        terminal_total_difficulty,
        terminal_block_hash,
        terminal_block_hash_activation_epoch: TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH,
        min_genesis_active_validator_count: MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
        min_genesis_time: MIN_GENESIS_TIME,
        genesis_fork_version: GENESIS_FORK_VERSION,
        genesis_delay: GENESIS_DELAY,
        altair_fork_version: ALTAIR_FORK_VERSION,
        altair_fork_epoch: ALTAIR_FORK_EPOCH,
        bellatrix_fork_version: BELLATRIX_FORK_VERSION,
        bellatrix_fork_epoch: BELLATRIX_FORK_EPOCH,
        capella_fork_version: CAPELLA_FORK_VERSION,
        capella_fork_epoch: CAPELLA_FORK_EPOCH,
        deneb_fork_version: DENEB_FORK_VERSION,
        deneb_fork_epoch: DENEB_FORK_EPOCH,
        electra_fork_version: ELECTRA_FORK_VERSION,
        electra_fork_epoch: ELECTRA_FORK_EPOCH,
        seconds_per_slot: SECONDS_PER_SLOT,
        seconds_per_eth1_block: SECONDS_PER_ETH1_BLOCK,
        min_validator_withdrawability_delay: MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
        shard_committee_period: SHARD_COMMITTEE_PERIOD,
        eth1_follow_distance: ETH1_FOLLOW_DISTANCE,
        inactivity_score_bias: INACTIVITY_SCORE_BIAS,
        inactivity_score_recovery_rate: INACTIVITY_SCORE_RECOVERY_RATE,
        ejection_balance: EJECTION_BALANCE,
        min_per_epoch_churn_limit: MIN_PER_EPOCH_CHURN_LIMIT,
        max_per_epoch_activation_churn_limit: MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT,
        min_per_epoch_churn_limit_electra: MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
        max_per_epoch_activation_exit_churn_limit: MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT,
        churn_limit_quotient: CHURN_LIMIT_QUOTIENT,
        proposer_score_boost: PROPOSER_SCORE_BOOST,
        deposit_chain_id: DEPOSIT_CHAIN_ID,
        deposit_network_id: DEPOSIT_NETWORK_ID,
        deposit_contract_address,
    }
}
