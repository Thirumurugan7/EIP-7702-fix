// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
/// @title WebAuthnEntryPoint
/// @notice Canonical ERC-4337 deployment supported by Chainwall AuthAccounts.
library WebAuthnEntryPoint {
    address internal constant ENTRY_POINT_V0_8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    uint256 internal constant ETHEREUM_CHAIN_ID = 1;
    uint256 internal constant OPTIMISM_CHAIN_ID = 10;
    uint256 internal constant BASE_CHAIN_ID = 8453;
    uint256 internal constant ARBITRUM_CHAIN_ID = 42161;
    uint256 internal constant SEPOLIA_CHAIN_ID = 11155111;
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
    uint256 internal constant CHAINWALL_ETHEREUM_DEMO_CHAIN_ID = 4409431;
    uint256 internal constant CHAINWALL_BASE_DEMO_CHAIN_ID = 4409432;
    uint256 internal constant CHAINWALL_ARBITRUM_DEMO_CHAIN_ID = 4409433;

    bytes32 internal constant ETHEREUM_ENTRY_POINT_V0_8_CODEHASH =
        0x44e632a24c6f2600cbd5b5b8b4c2d372359112c8b5774297f5fd0a9e64f11f86;
    bytes32 internal constant OPTIMISM_ENTRY_POINT_V0_8_CODEHASH =
        0x49ff5c033c81f4ebe0467c1127c9a6c6f3ad1837405c199bea9b494fee621c04;
    bytes32 internal constant BASE_ENTRY_POINT_V0_8_CODEHASH =
        0x28f989233f4ffb52e4b168fb74df5dfa52fe0f846141774f5abc56c5604d8e46;
    bytes32 internal constant ARBITRUM_ENTRY_POINT_V0_8_CODEHASH =
        0x49684f00c804420e129bac03ca503baa5312db5c36f68767d393bc36dd58c4c9;
    bytes32 internal constant SEPOLIA_ENTRY_POINT_V0_8_CODEHASH =
        0xe07af503ad1c64355b712a3fba2341cb6cf83a62fa80b23469c2a283c12dd7d5;
    bytes32 internal constant BASE_SEPOLIA_ENTRY_POINT_V0_8_CODEHASH =
        0xa06a3208a3f27999ffae96d26acf86a40a16e582c5467513cbf2c7e96e68029c;

    /// @notice An address is not the canonical EntryPoint v0.8 deployment supported by Chainwall.
    /// @param entryPoint Unsupported address.
    error EntryPointUnsupported(address entryPoint);

    /// @notice Chainwall has no pinned EntryPoint runtime for the requested chain.
    /// @param chainId Unsupported chain identifier.
    error EntryPointChainUnsupported(uint256 chainId);

    /// @notice The canonical EntryPoint address has no deployed code on the active chain.
    /// @param entryPoint Canonical address expected to contain the EntryPoint runtime.
    error EntryPointNotDeployed(address entryPoint);

    /// @notice The canonical EntryPoint address has an unexpected runtime.
    /// @param entryPoint Canonical EntryPoint address inspected on the active chain.
    /// @param expectedCodehash Pinned runtime hash for the active chain.
    /// @param actualCodehash Runtime hash found at `entryPoint`.
    error EntryPointCodehashMismatch(address entryPoint, bytes32 expectedCodehash, bytes32 actualCodehash);

    /// @dev EntryPoint-only account methods are privileged. Pinning the public
    ///      v0.8 deployment and its chain-specific runtime prevents a configuration
    ///      typo or EOA from becoming an alternate credential and protocol-call
    ///      authority. The runtime differs by chain because EntryPoint embeds
    ///      chain-dependent EIP-712 cache values.
    /// @param entryPoint Candidate address to authenticate against the active chain's canonical deployment.
    function requireCanonical(address entryPoint) internal view {
        requireAddress(entryPoint);
        bytes32 expected = expectedCodehash(block.chainid);
        if (!Delegation7702.hasContractCode(entryPoint)) revert EntryPointNotDeployed(entryPoint);
        bytes32 actualCodehash = entryPoint.codehash;
        if (actualCodehash != expected) {
            revert EntryPointCodehashMismatch(entryPoint, expected, actualCodehash);
        }
    }

    /// @dev Address-only form for account initialization during ERC-4337 sender
    ///      creation, where touching EntryPoint code would violate ERC-7562.
    /// @param entryPoint Candidate address that must equal the canonical EntryPoint v0.8 address.
    function requireAddress(address entryPoint) internal pure {
        if (entryPoint != ENTRY_POINT_V0_8) revert EntryPointUnsupported(entryPoint);
    }

    /// @notice Return the audited EntryPoint v0.8 runtime hash for a supported release chain.
    /// @param chainId Chain whose canonical runtime hash should be returned.
    /// @return Expected runtime hash for `chainId`.
    function expectedCodehash(uint256 chainId) internal pure returns (bytes32) {
        if (chainId == ETHEREUM_CHAIN_ID) return ETHEREUM_ENTRY_POINT_V0_8_CODEHASH;
        if (chainId == OPTIMISM_CHAIN_ID) return OPTIMISM_ENTRY_POINT_V0_8_CODEHASH;
        if (chainId == BASE_CHAIN_ID) return BASE_ENTRY_POINT_V0_8_CODEHASH;
        if (chainId == ARBITRUM_CHAIN_ID) return ARBITRUM_ENTRY_POINT_V0_8_CODEHASH;
        if (chainId == SEPOLIA_CHAIN_ID) return SEPOLIA_ENTRY_POINT_V0_8_CODEHASH;
        if (chainId == BASE_SEPOLIA_CHAIN_ID) return BASE_SEPOLIA_ENTRY_POINT_V0_8_CODEHASH;
        // Local fork demos retain the source chain's canonical EntryPoint
        // runtime under isolated chain IDs used by browser wallets.
        if (chainId == CHAINWALL_ETHEREUM_DEMO_CHAIN_ID) return ETHEREUM_ENTRY_POINT_V0_8_CODEHASH;
        if (chainId == CHAINWALL_BASE_DEMO_CHAIN_ID) return BASE_ENTRY_POINT_V0_8_CODEHASH;
        if (chainId == CHAINWALL_ARBITRUM_DEMO_CHAIN_ID) return ARBITRUM_ENTRY_POINT_V0_8_CODEHASH;
        revert EntryPointChainUnsupported(chainId);
    }
}
