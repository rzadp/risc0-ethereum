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

use alloy_primitives::{Address, Bytes, Keccak256, B256, U256};
use alloy_sol_types::sol;
use risc0_steel::SolCommitment;
use serde::{Deserialize, Serialize};

sol! {
    /// IL1CrossDomainMessenger contains function signature.
    interface IL1CrossDomainMessenger {
        function contains(bytes32 digest) external view returns (bool);
    }
}

sol! {
    struct Journal {
        SolCommitment commitment;
        address l1CrossDomainMessenger;
        address target;
        address sender;
        bytes data;
        uint256 nonce;
        bytes32 digest;
    }
}

#[derive(Serialize, Deserialize)]
pub struct CrossDomainMessengerInput {
    pub l1_cross_domain_messenger: Address,
    pub target: Address,
    pub sender: Address,
    pub data: Bytes,
    pub nonce: U256,
}

impl CrossDomainMessengerInput {
    #[inline]
    pub fn into_journal(self) -> Journal {
        let digest = message_hash(&self.target, &self.sender, &self.data, &self.nonce);
        Journal {
            commitment: SolCommitment::default(),
            l1CrossDomainMessenger: self.l1_cross_domain_messenger,
            target: self.target,
            sender: self.sender,
            data: self.data,
            nonce: self.nonce,
            digest,
        }
    }
}

/// Computes the hash of the message that was relayed.
#[inline]
pub fn message_hash(target: &Address, sender: &Address, data: &Bytes, nonce: &U256) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update("relayMessage(address,address,bytes,uint256)");
    hasher.update(target);
    hasher.update(sender);
    hasher.update(data);
    hasher.update(nonce.to_be_bytes::<32>());
    hasher.finalize()
}
