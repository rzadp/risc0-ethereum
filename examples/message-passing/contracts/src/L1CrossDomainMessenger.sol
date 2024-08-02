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

pragma solidity ^0.8.20;

import {Hasher} from "./Hasher.sol";
import {IL1CrossDomainMessenger} from "./IL1CrossDomainMessenger.sol";

contract L1CrossDomainMessenger is IL1CrossDomainMessenger {
    mapping(bytes32 => bool) private messages;
    uint256 private msgNonce;

    constructor() {
        msgNonce = 0;
    }

    /// Returns whether the digest of the message has been published.
    function contains(bytes32 digest) external view returns (bool) {
        return messages[digest];
    }

    /// Sends a new message by commiting to its digest.
    function sendMessage(address target, bytes calldata data) external {
        address sender = msg.sender;
        uint256 nonce = messageNonce();
        bytes32 digest = Hasher.hashCrossDomainMessage(target, sender, data, nonce);
        messages[digest] = true;

        emit SentMessage(target, sender, data, nonce);

        unchecked {
            ++msgNonce;
        }
    }

    function messageNonce() public view returns (uint256) {
        return msgNonce;
    }

    function encodeMessage(address target, address sender, bytes memory data, uint256 nonce)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature("relayMessage(address,address,bytes,uint256)", target, sender, data, nonce);
    }
}
