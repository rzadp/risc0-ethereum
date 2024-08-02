// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use alloy_sol_types::SolValue;
use cross_domain_messenger_core::{CrossDomainMessengerInput, IL1CrossDomainMessenger};
use risc0_steel::{ethereum::EthEvmInput, Contract};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read the input from the guest environment.
    let input: EthEvmInput = env::read();
    // Converts the input into a `EvmEnv` for execution.
    let env = input.into_env();

    // Read the remaining input and create the journal from it
    let cross_domain_messenger_input: CrossDomainMessengerInput = env::read();
    let mut journal = cross_domain_messenger_input.into_journal();

    // Execute the view call; it returns the result in the type generated by the `sol!` macro.
    let call = IL1CrossDomainMessenger::containsCall {
        digest: journal.digest,
    };
    let returns = Contract::new(journal.l1CrossDomainMessenger, &env)
        .call_builder(&call)
        .call();

    // Check that the message exists.
    assert!(returns._0, "message does not exist");

    // Commit the block hash and number used when deriving `view_call_env` to the journal.
    journal.commitment = env.into_commitment();
    env::commit_slice(&journal.abi_encode());
}
