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

// This application demonstrates how to send an off-chain proof request
// to the Bonsai proving service and publish the received proofs directly
// to your deployed app contract.

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    providers::ProviderBuilder,
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolEvent},
};
use alloy_primitives::Address;
use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use cross_domain_messenger_core::{CrossDomainMessengerInput, Message};
use cross_domain_messenger_methods::CROSS_DOMAIN_MESSENGER_ELF;
use risc0_ethereum_contracts::groth16::RiscZeroVerifierSeal;
use risc0_steel::{ethereum::EthEvmEnv, Contract};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use tokio::{task, time};
use tracing_subscriber::EnvFilter;
use url::Url;

sol!(
    #[sol(rpc, all_derives)]
    "../contracts/src/IL1CrossDomainMessenger.sol"
);
sol!(
    #[sol(rpc, all_derives)]
    "../contracts/src/IL2CrossDomainMessenger.sol"
);

// Contract to call via L1.
sol!("../contracts/src/ICounter.sol");

// Contract to bookmark L1 blocks for later verification.
sol!(
    #[sol(rpc, all_derives)]
    "../contracts/src/IBookmark.sol"
);

/// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Ethereum Node endpoint.
    #[clap(long, env)]
    eth_wallet_private_key: PrivateKeySigner,

    /// Ethereum Node endpoint.
    #[clap(long, env)]
    l1_rpc_url: Url,

    /// Ethereum Node endpoint.
    #[clap(long, env)]
    l2_rpc_url: Url,

    /// Target's contract address on L2
    #[clap(long, env)]
    target_address: Address,

    /// l1_cross_domain_messenger_address's contract address on L1
    #[clap(long, env)]
    l1_cross_domain_messenger_address: Address,

    /// l2_cross_domain_messenger_address's contract address on L2
    #[clap(long, env)]
    l2_cross_domain_messenger_address: Address,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::parse();

    // Create an alloy provider for that private key and URL.
    let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let l1_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_http(args.l1_rpc_url);

    let l2_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_http(args.l2_rpc_url);

    // Instantiate all the contracts we want to call.
    let l1_messenger_contract =
        IL1CrossDomainMessenger::new(args.l1_cross_domain_messenger_address, l1_provider.clone());
    let l2_messenger_contract =
        IL2CrossDomainMessenger::new(args.l2_cross_domain_messenger_address, l2_provider.clone());
    let bookmark_contract =
        IBookmark::new(args.l2_cross_domain_messenger_address, l2_provider.clone());

    // Prepare the message to be passed from L1 to L2
    let target = args.target_address;
    let data = ICounter::incrementCall {}.abi_encode();

    // Send a transaction calling IL1CrossDomainMessenger.sendMessage
    let send_message_call = l1_messenger_contract.sendMessage(target, data.into());
    let pending_tx = send_message_call.send().await?;
    let receipt = pending_tx
        .with_timeout(Some(Duration::from_secs(60)))
        .get_receipt()
        .await?;

    // Process the transaction result
    ensure!(receipt.status(), "transaction failed");
    let message_block_number = receipt.block_number.unwrap();
    let event: IL1CrossDomainMessenger::SentMessage = into_event(receipt)?;
    println!("Message submitted on L1: {:?}", event);
    let message = Message {
        target: event.target,
        sender: event.sender,
        data: event.data,
        nonce: event.messageNonce,
    };

    // Call IBookmark.bookmarkL1Block until we can bookmark a block that contains the sent message.
    let bookmark_call = bookmark_contract.bookmarkL1Block();
    loop {
        let current_block_number = bookmark_call.call().await?._0;
        if current_block_number >= message_block_number {
            break;
        }
        println!(
            "Waiting for L1 block to catch up: {} < {}",
            current_block_number, message_block_number
        );
        time::sleep(Duration::from_secs(5)).await;
    }

    // Send a transaction calling IBookmark.bookmarkL1Block to create an on-chain bookmark.
    let pending_tx = bookmark_call
        .send()
        .await
        .context("failed to send bookmarkL1Block")?;
    let receipt = pending_tx
        .with_timeout(Some(Duration::from_secs(60)))
        .get_receipt()
        .await
        .context("failed to confirm tx")?;

    // Get the number of the actual bookmarked block.
    let event: IBookmark::BookmarkedL1Block = into_event(receipt)?;
    let bookmark_block_number = event.number;

    // Run Steel:
    // Create an EVM environment from that provider and a block number.
    let mut env =
        EthEvmEnv::from_provider(l1_provider.clone(), bookmark_block_number.into()).await?;
    // Prepare the function call to be called inside steal
    let call = IL1CrossDomainMessenger::containsCall {
        digest: message.digest(),
    };
    // Preflight the call to prepare the input for the guest.
    let mut contract = Contract::preflight(args.l1_cross_domain_messenger_address, &mut env);
    let success = contract.call_builder(&call).call().await?._0;
    ensure!(success, "message {} not found", call.digest);
    // Finally, construct the input for the guest.
    let evm_input = env.into_input().await?;
    let cross_domain_messenger_input = CrossDomainMessengerInput {
        l1_cross_domain_messenger: args.l1_cross_domain_messenger_address,
        message,
    };

    println!("Creating proof for the constructed input...");
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)?
            .write(&cross_domain_messenger_input)?
            .build()
            .unwrap();

        default_prover().prove_with_ctx(
            env,
            &VerifierContext::default(),
            CROSS_DOMAIN_MESSENGER_ELF,
            &ProverOpts::groth16(),
        )
    })
    .await?
    .context("failed to create proof")?;
    println!(
        "Proving finished in {} cycles",
        prove_info.stats.total_cycles
    );
    let receipt = prove_info.receipt;

    // Encode the groth16 seal with the selector.
    let seal = RiscZeroVerifierSeal::try_from(&receipt)?;

    // Call the increment function of the contract and wait for confirmation.
    let call_builder =
        l2_messenger_contract.relayMessage(receipt.journal.bytes.into(), seal.into());
    let pending_tx = call_builder.send().await?;
    let receipt = pending_tx
        .with_timeout(Some(Duration::from_secs(60)))
        .get_receipt()
        .await?;
    let event = into_event::<IL2CrossDomainMessenger::RelayedMessage>(receipt)?;
    println!("Message relayed {:?}", event);

    Ok(())
}

fn into_event<E: SolEvent>(receipt: TransactionReceipt) -> Result<E> {
    ensure!(receipt.status(), "transaction failed");
    for log in receipt.inner.logs() {
        match log.log_decode::<E>() {
            Ok(decoded_log) => return Ok(decoded_log.inner.data),
            Err(_) => {}
        }
    }
    bail!("invalid events emitted")
}
