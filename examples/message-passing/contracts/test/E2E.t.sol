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

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {Receipt as RiscZeroReceipt} from "risc0/IRiscZeroVerifier.sol";
import {RiscZeroMockVerifier} from "risc0/test/RiscZeroMockVerifier.sol";
import "../src/IL1CrossDomainMessenger.sol";
import "../src/L1CrossDomainMessenger.sol";
import "../src/IL1Block.sol";
import "../src/IL2CrossDomainMessenger.sol";
import "../src/L2CrossDomainMessenger.sol";
import "./L1BlockMock.sol";
import "../src/Counter.sol";
import {Steel} from "risc0/steel/Steel.sol";

contract E2ETest is Test {
    RiscZeroMockVerifier private verifier;
    IL1CrossDomainMessenger private l1CrossDomainMessenger;
    IL2CrossDomainMessenger private l2CrossDomainMessenger;
    IL1Block private l1Block;
    Counter private counter;
    address private sender;
    address private evilSender;

    bytes32 internal CROSS_DOMAIN_MESSENGER_IMAGE_ID =
        0x0000000000000000000000000000000000000000000000000000000000000003;

    bytes4 MOCK_SELECTOR = bytes4(0);

    function setUp() public {
        sender = address(1);
        evilSender = address(2);

        l1CrossDomainMessenger = new L1CrossDomainMessenger();
        verifier = new RiscZeroMockVerifier(MOCK_SELECTOR);
        l1Block = new L1BlockMock();
        l2CrossDomainMessenger = new L2CrossDomainMessenger(
            verifier,
            CROSS_DOMAIN_MESSENGER_IMAGE_ID,
            "https://contains-message.com",
            address(l1CrossDomainMessenger),
            l1Block
        );
        counter = new Counter(l2CrossDomainMessenger, address(sender));
    }

    function testE2E() public {
        vm.startPrank(sender);

        // define the message
        bytes memory data = abi.encodeCall(Counter.increment, ());

        // define the target
        address target = address(counter);

        // send a message
        (bytes32 digest, uint256 nonce) = l1CrossDomainMessenger.sendMessage(target, data);

        // bookmark the block

        vm.roll(1);
        uint256 blockNumber = l2CrossDomainMessenger.bookmarkL1Block();
        bytes32 blockHash = l1Block.hash();

        // Mock the Journal
        Steel.Commitment memory commitment = Steel.Commitment({blockNumber: blockNumber, blockHash: blockHash});

        Journal memory journal = Journal({
            commitment: commitment,
            l1CrossDomainMessenger: address(l1CrossDomainMessenger),
            sender: sender,
            target: target,
            nonce: nonce,
            data: data,
            digest: digest
        });

        // create a mock proof
        RiscZeroReceipt memory receipt =
            verifier.mockProve(CROSS_DOMAIN_MESSENGER_IMAGE_ID, sha256(abi.encode(journal)));

        l2CrossDomainMessenger.relayMessage(abi.encode(journal), receipt.seal);

        assert(counter.get() == 1);
    }
}
