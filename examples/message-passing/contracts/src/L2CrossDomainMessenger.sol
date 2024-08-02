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
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.13;

import {MerkleProof} from "openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import "./IL1Block.sol";
import "./IL2CrossDomainMessenger.sol";
import {Steel} from "risc0/steel/Steel.sol";

/// @notice Journal that is committed to by the guest.
struct Journal {
    Steel.Commitment commitment;
    address l1CrossDomainMessenger;
    address sender;
    address target;
    uint256 nonce;
    bytes data;
    bytes32 digest;
}

/// @notice L1Bridging verifier contract for RISC Zero receipts of execution.
contract L2CrossDomainMessenger is IL2CrossDomainMessenger {
    bytes32 private immutable IMAGE_ID;
    string private imageUrl;
    IRiscZeroVerifier public immutable VERIFIER;
    IL1Block private immutable L1_BLOCK;
    address private immutable L1_CROSS_DOMAIN_MESSENGER;
    address private xDomainMessageSender;
    mapping(bytes32 => bool) private relayedMessages;
    mapping(uint256 blockNumber => bytes32 blockHash) private bookmarkedBlocks;

    constructor(
        IRiscZeroVerifier verifier,
        bytes32 imageId,
        string memory _imageUrl,
        IL1Block l1Block,
        address l1CrossDomainMessenger
    ) {
        VERIFIER = verifier;
        IMAGE_ID = imageId;
        imageUrl = _imageUrl;
        L1_BLOCK = l1Block;
        L1_CROSS_DOMAIN_MESSENGER = l1CrossDomainMessenger;
        xDomainMessageSender = address(0);
    }

    function number() external view returns (uint64) {
        return L1_BLOCK.number();
    }

    function hash() external view returns (bytes32) {
        return L1_BLOCK.hash();
    }

    function bookmarkL1Block() external returns (uint64) {
        uint64 blockNumber = this.number();
        bookmarkedBlocks[uint256(blockNumber)] = this.hash();

        emit BookmarkedL1Block(blockNumber, bookmarkedBlocks[uint256(blockNumber)]);

        return blockNumber;
    }

    function relayMessage(
        address target,
        address sender,
        uint256 nonce,
        bytes calldata data,
        Steel.Commitment calldata commitment,
        bytes calldata seal
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(sender, target, nonce, data));
        Journal memory journal = Journal({
            commitment: commitment,
            l1CrossDomainMessenger: L1_CROSS_DOMAIN_MESSENGER,
            sender: sender,
            target: target,
            data: data,
            nonce: nonce,
            digest: digest
        });
        VERIFIER.verify(seal, IMAGE_ID, sha256(abi.encode(journal)));

        require(validateCommitment(commitment), "commitment verification failed");
        require(!relayedMessages[digest], "message already relayed");

        xDomainMessageSender = sender;

        (bool success,) = target.call(data);
        require(success, "call failed");

        relayedMessages[digest] = true;
        xDomainMessageSender = address(0);

        emit MessageRelayed(digest);
    }

    function relayMessage(bytes calldata journal, bytes calldata seal) external {
        VERIFIER.verify(seal, IMAGE_ID, sha256(journal));

        Journal memory decodedJournal = abi.decode(journal, (Journal));

        require(decodedJournal.l1CrossDomainMessenger == L1_CROSS_DOMAIN_MESSENGER, "invalid l1CrossDomainMessenger");
        require(validateCommitment(decodedJournal.commitment), "commitment verification failed");
        require(!relayedMessages[decodedJournal.digest], "message already relayed");

        xDomainMessageSender = decodedJournal.sender;

        (bool success,) = decodedJournal.target.call(decodedJournal.data);
        require(success, "call failed");

        relayedMessages[decodedJournal.digest] = true;
        xDomainMessageSender = address(0);

        emit MessageRelayed(decodedJournal.digest);
    }

    function xDomainMessenger() external view returns (address) {
        return xDomainMessageSender;
    }

    function imageInfo() external view returns (bytes32, string memory) {
        return (IMAGE_ID, imageUrl);
    }

    function validateCommitment(Steel.Commitment memory commitment) internal view returns (bool isValid) {
        return commitment.blockHash == bookmarkedBlocks[commitment.blockNumber];
    }
}
