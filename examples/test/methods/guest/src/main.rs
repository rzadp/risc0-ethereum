use alloy_primitives::Address;
use alloy_sol_types::{sol, SolValue};
use risc0_steel::ethereum::EthEvmInput;
use risc0_steel::Contract;
use risc0_zkvm::guest::env;

sol!(
    contract SlotsTest {
        function sload() external view returns (uint256 v) {
            for (uint256 i = 0; i < N; i++) {
                assembly { v := add(v, sload(i)) }
            }
        }
    }
);

fn main() {
    env::log("read");
    // Read the input from the guest environment.
    let input: EthEvmInput = env::read();
    let address: Address = env::read();

    env::log("into_env");
    // Converts the input into a `EvmEnv` for execution.
    let env = input.into_env();

    env::log("call");
    // Execute the view call; it returns the result in the type generated by the `sol!` macro.
    let contract = Contract::new(address, &env);
    contract
        .call_builder(&SlotsTest::sloadCall {})
        .gas(u64::MAX)
        .call();

    env::log("commit_slice");
    // Commit the block hash and number used when deriving `EvmEnv` to the journal.
    env::commit_slice(&env.block_commitment().abi_encode());
}