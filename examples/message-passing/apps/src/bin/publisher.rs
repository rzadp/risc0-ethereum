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
    providers::{ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolEvent},
};
use alloy_primitives::{Address, U256};
use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use cross_domain_messenger_methods::CROSS_DOMAIN_MESSENGER_ELF;
use risc0_ethereum_contracts::groth16::RiscZeroVerifierSeal;
use risc0_steel::{ethereum::EthEvmEnv, Contract};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use serde::{Deserialize, Serialize};
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

sol!(
    #[sol(rpc)]
    "../contracts/src/IL1CrossDomainMessenger.sol"
);
sol!(
    #[sol(rpc)]
    "../contracts/src/IL2CrossDomainMessenger.sol"
);

// Contract to call via L1.
sol!("../contracts/src/ICounter.sol");

// Contract to bookmark L1 blocks for later verification.
sol!(
    #[sol(rpc)]
    "../contracts/src/IBookmark.sol"
);

#[derive(Serialize, Deserialize)]
pub struct CrossDomainMessengerInput {
    pub l1_cross_domain_messenger: Address,
    pub sender: Address,
    pub target: Address,
    pub nonce: U256,
    pub data: Vec<u8>,
}

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
    #[clap(long)]
    target_address: Address,

    /// l1_cross_domain_messenger_address's contract address on L1
    #[clap(long)]
    l1_cross_domain_messenger_address: Address,

    /// l2_cross_domain_messenger_address's contract address on L2
    #[clap(long)]
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

    let counter = ICounter::incrementCall {};
    let data = counter.abi_encode();

    // Create an alloy instance of the Counter contract.
    let l1_cross_domain_messenger =
        IL1CrossDomainMessenger::new(args.l1_cross_domain_messenger_address, l1_provider.clone());
    let call_builder =
        l1_cross_domain_messenger.sendMessage(args.target_address, data.clone().into());
    let pending_tx = call_builder.send().await?;
    let receipt = pending_tx
        .with_timeout(Some(Duration::from_secs(60)))
        .get_receipt()
        .await?;
    ensure!(receipt.status(), "transaction failed");
    let [log] = receipt.inner.logs() else {
        bail!("call must emit exactly one event")
    };
    let log = log
        .log_decode::<IL1CrossDomainMessenger::SentMessage>()
        .with_context(|| {
            format!(
                "call did not emit {}",
                IL1CrossDomainMessenger::SentMessage::SIGNATURE
            )
        })?;

    let digest = log.inner.data.digest;
    let nonce = log.inner.data.nonce;
    let sender = l1_provider.default_signer_address();
    println!(
        "Sent message from {} to {} with nonce {} and digest {}",
        sender, args.target_address, nonce, digest
    );
    let target = args.target_address;

    // Bookmark block
    let target_block_number = receipt.block_number.context("block_number missing")?;

    let bookmark_contract =
        IBookmark::new(args.l2_cross_domain_messenger_address, l2_provider.clone());
    let bookmark_call = bookmark_contract.bookmarkL1Block();

    loop {
        let current_block_number = bookmark_call
            .call()
            .await
            .context("failed to call bookmarkL1Block")?
            ._0;
        if current_block_number >= target_block_number {
            break;
        }
        println!(
            "Waiting for L1 block to catch up: {} < {}",
            current_block_number, target_block_number
        );
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }

    println!(
        "Sending Tx calling {} Function of {:#}...",
        IBookmark::bookmarkL1BlockCall::SIGNATURE,
        bookmark_contract.address()
    );
    let pending_tx = bookmark_call
        .send()
        .await
        .context("failed to send bookmarkL1Block")?;
    let receipt = pending_tx
        .with_timeout(Some(Duration::from_secs(60)))
        .get_receipt()
        .await
        .context("failed to confirm tx")?;
    let [log] = receipt.inner.logs() else {
        bail!("call must emit exactly one event")
    };
    let log = log
        .log_decode::<IBookmark::BookmarkedL1Block>()
        .with_context(|| {
            format!(
                "call did not emit {}",
                IBookmark::BookmarkedL1Block::SIGNATURE
            )
        })?;

    let block_number = log.inner.data.number;

    let cross_domain_messenger_input = CrossDomainMessengerInput {
        l1_cross_domain_messenger: args.l1_cross_domain_messenger_address,
        sender,
        target,
        nonce,
        data,
    };

    // Create an EVM environment from that provider and a block number.
    let mut env = EthEvmEnv::from_provider(l1_provider.clone(), block_number.into()).await?;

    // Prepare the function call
    let call = IL1CrossDomainMessenger::containsCall { digest };

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(args.l1_cross_domain_messenger_address, &mut env);
    let returns = contract.call_builder(&call).call().await?;
    println!(
        "Call {} Function on {:#} returns: {}",
        IL1CrossDomainMessenger::containsCall::SIGNATURE,
        args.l1_cross_domain_messenger_address,
        returns._0
    );

    // Finally, construct the input from the environment.
    let view_call_input = env.into_input().await?;

    println!("Creating proof for the constructed input...");
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&view_call_input)?
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
    let receipt = prove_info.receipt;

    // Encode the groth16 seal with the selector.
    let seal = RiscZeroVerifierSeal::try_from(&receipt)?;

    // Create an alloy instance of the L2CrossDomainMessenger contract.
    let l2_messenger_contract =
        IL2CrossDomainMessenger::new(args.l2_cross_domain_messenger_address, l2_provider);

    // Call the increment function of the contract and wait for confirmation.
    println!(
        "Sending Tx calling {} Function of {:#}...",
        IL2CrossDomainMessenger::relayMessageCall::SIGNATURE,
        l2_messenger_contract.address()
    );
    let call_builder =
        l2_messenger_contract.relayMessage(receipt.journal.bytes.into(), seal.into());
    let pending_tx = call_builder.send().await?;
    let receipt = pending_tx
        .with_timeout(Some(Duration::from_secs(60)))
        .get_receipt()
        .await?;
    ensure!(receipt.status(), "transaction failed");

    Ok(())
}
