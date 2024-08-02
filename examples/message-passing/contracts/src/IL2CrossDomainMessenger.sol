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

pragma solidity >0.5.0 <0.9.0;

import {IL1Block} from "./IL1Block.sol";
import {Steel} from "risc0/steel/Steel.sol";

interface IL2CrossDomainMessenger is IL1Block {
    error VerificationFailed();

    /// A new L1 block has been bookmarked.
    event BookmarkedL1Block(uint64 number, bytes32 hash);

    /// A new message has been bridged.
    event MessageRelayed(bytes32 digest);

    // /// relay the message from L1.
    // function relayMessage(
    //     address target,
    //     address sender,
    //     uint256 nonce,
    //     bytes calldata data,
    //     Steel.Commitment calldata commitment,
    //     bytes calldata seal
    // ) external;

    /// relay the message from L1.
    function relayMessage(bytes calldata journal, bytes calldata seal) external;

    /// returns the cross domain messenger address, i.e., the sender of the message.
    function xDomainMessenger() external view returns (address);

    /// Bookmarks the current L1 block.
    function bookmarkL1Block() external returns (uint64 number);

    /// Returns the L1 block number.
    function number() external view returns (uint64);

    /// Returns the L1 block hash.
    function hash() external view returns (bytes32);

    /// Returns the imageId and its url.
    function imageInfo() external view returns (bytes32, string memory);
}
