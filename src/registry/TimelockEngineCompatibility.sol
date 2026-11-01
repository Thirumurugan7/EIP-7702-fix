// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ProtocolCodehashes} from "../ProtocolCodehashes.sol";

/// @notice Engine releases accepted specifically for timelock policy governance.
/// @dev Retain the reviewed predecessor while installing a new facet and replacing its
///      runner in separate governed actions. Otherwise the old runner cannot authorize
///      either its own replacement or a facet rollback. This does not broaden engine
///      admission for execution hosts or accounts. Future releases must explicitly
///      review and preserve the predecessors needed by their supported migration paths.
library TimelockEngineCompatibility {
    // Frozen deployment triplets from 4cdc7f0e9b866af988c3ad004e233ff20fc0cd44.
    // These are historical release commitments, not constants to refresh on rebuild.
    bytes32 private constant PREVIOUS_ENGINE_DEFAULT =
        0x889052c1fd1d359590eb9a5aa7b725d4fe273b297673c8b4d65c1b05fe51c11e;
    bytes32 private constant PREVIOUS_ANALYZER_DEFAULT =
        0x680f1594e973cd3043f9bf6f08234e58e68949c81cf45b6bafe19b6dea9aab41;
    bytes32 private constant PREVIOUS_ENCODER_DEFAULT =
        0x3136565577e30e8ea04447a8ac066d0399837687a5436a61f49285b1c5fe00f1;

    bytes32 private constant PREVIOUS_ENGINE_PRODUCTION =
        0x240dfd00ebdfffbae04a054907a5e49055151520d5714b2a420f6184905744fd;
    bytes32 private constant PREVIOUS_ANALYZER_PRODUCTION =
        0x0acb1a5d79faaeed4336aab76bbcc77057610c1efbc3ab18e162e9aeb2faa6a1;
    bytes32 private constant PREVIOUS_ENCODER_PRODUCTION =
        0xfdee783e333775ee2c19dfb54e581aca9a5d5702898f0f41beb05ac9550647ad;

    /// @dev Both current and historical engines require their exact profile-matched
    ///      analyzer and encoder at CREATE nonces 1 and 2; runtime authentication alone
    ///      cannot rule out substituted constructor children.
    function isAcceptedDeployment(address engine) internal view returns (bool) {
        if (ProtocolCodehashes.isAcceptedMiniScriptDeployment(engine)) return true;

        bytes32 engineCodehash = engine.codehash;
        if (engineCodehash == PREVIOUS_ENGINE_DEFAULT) {
            return _child(engine, 1).codehash == PREVIOUS_ANALYZER_DEFAULT
                && _child(engine, 2).codehash == PREVIOUS_ENCODER_DEFAULT;
        }
        if (engineCodehash == PREVIOUS_ENGINE_PRODUCTION) {
            return _child(engine, 1).codehash == PREVIOUS_ANALYZER_PRODUCTION
                && _child(engine, 2).codehash == PREVIOUS_ENCODER_PRODUCTION;
        }
        return false;
    }

    function _child(address engine, uint8 nonce) private pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", engine, bytes1(nonce))))));
    }
}
