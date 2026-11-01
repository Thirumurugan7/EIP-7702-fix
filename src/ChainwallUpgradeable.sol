// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {IChainwallUpgradeable} from "@chainwall/interfaces/IChainwallUpgradeable.sol";

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC1822Proxiable} from "@openzeppelin/contracts/interfaces/draft-IERC1822.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

library ChainwallUpgradeHash {
    function hash(bytes memory encoded) internal pure returns (bytes32 value) {
        assembly ("memory-safe") {
            value := keccak256(add(encoded, 0x20), mload(encoded))
        }
    }
}

/// @notice Shared inspection for implementations selected before an ERC-1967 proxy exists.
/// @dev ERC-1967 constructors do not exercise the UUPS upgrade path. Factories therefore use this
///      helper to reject an initial implementation that cannot participate in the same Registry-
///      governed protocol as later upgrades. The reported component, protocol, and bindings are
///      self-attestation; governance still commits the implementation runtime codehash separately.
library ChainwallInitialImplementationValidation {
    uint256 internal constant UPGRADE_PROTOCOL_VERSION = 1;
    bytes32 internal constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    enum Issue {
        None,
        NotContract,
        Component,
        Protocol,
        Uups,
        SecurityBindings
    }

    /// @notice Inspect an implementation without mutating it.
    /// @param implementation Candidate runtime selected for a new proxy or dispatcher.
    /// @param expectedComponentId Stable logical component identifier required from the candidate.
    /// @param requireUups Whether the persistent address itself uses an ERC-1967/UUPS proxy.
    /// @return issue First compatibility failure, or `None` when every required surface is present.
    /// @return codehash_ Candidate runtime codehash when valid, otherwise zero.
    function inspect(address implementation, bytes32 expectedComponentId, bool requireUups)
        internal
        view
        returns (Issue issue, bytes32 codehash_)
    {
        if (implementation.code.length == 0) return (Issue.NotContract, bytes32(0));

        try IChainwallUpgradeable(implementation).chainwallComponentId() returns (bytes32 componentId) {
            if (componentId != expectedComponentId) return (Issue.Component, bytes32(0));
        } catch {
            return (Issue.Component, bytes32(0));
        }

        try IChainwallUpgradeable(implementation).chainwallUpgradeProtocolVersion() returns (uint256 version) {
            if (version != UPGRADE_PROTOCOL_VERSION) return (Issue.Protocol, bytes32(0));
        } catch {
            return (Issue.Protocol, bytes32(0));
        }

        if (requireUups) {
            try IERC1822Proxiable(implementation).proxiableUUID() returns (bytes32 slot) {
                if (slot != ERC1967_IMPLEMENTATION_SLOT) return (Issue.Uups, bytes32(0));
            } catch {
                return (Issue.Uups, bytes32(0));
            }
        }

        (bool ok, bytes memory result) =
            implementation.staticcall(abi.encodeCall(IChainwallUpgradeable.chainwallSecurityBindingsHash, ()));
        if (!ok || result.length != 32) return (Issue.SecurityBindings, bytes32(0));

        return (Issue.None, implementation.codehash);
    }
}

/// @notice Storage-free base for components upgraded through the Chainwall Registry timelock.
/// @dev Introspection reads the proxy's real ERC-1967 slot. Keeping this base storage-free preserves
///      the existing layouts of Interact, MiniScript, and WebAuthnAuthAccountFactory.
abstract contract ChainwallUUPSUpgradeable is UUPSUpgradeable {
    uint256 public constant CHAINWALL_UPGRADE_PROTOCOL_VERSION = 1;

    error ChainwallUpgradeBindingsChanged(bytes32 expected, bytes32 actual);
    error ChainwallUpgradeImplementationChanged(address expected, address actual);

    /// @notice Stable logical component type used to reject cross-component implementation mistakes.
    function chainwallComponentId() external pure virtual returns (bytes32);

    /// @notice Return the implementation currently selected by this ERC-1967 proxy.
    function chainwallImplementation() external view onlyProxy returns (address) {
        return ERC1967Utils.getImplementation();
    }

    /// @notice Return the runtime codehash of the implementation selected by this proxy.
    function chainwallImplementationCodehash() external view onlyProxy returns (bytes32) {
        return ERC1967Utils.getImplementation().codehash;
    }

    function chainwallUpgradeProtocolVersion() external pure returns (uint256) {
        return CHAINWALL_UPGRADE_PROTOCOL_VERSION;
    }

    /// @notice Hash the authority and dependency pointers that a code-only upgrade must preserve.
    /// @dev Intentional binding changes use a separately scoped Registry release action. Implementations must keep
    ///      this protocol-v1 schema stable so the Registry can reject a candidate that cannot support later upgrades.
    function chainwallSecurityBindingsHash() external view returns (bytes32) {
        return _chainwallSecurityBindingsHash();
    }

    /// @dev Install a candidate, run its migration, and then inspect storage through the old implementation frame.
    ///      The candidate cannot redefine this postcondition: internal dispatch remains in the implementation that
    ///      entered the upgrade even though the ERC-1967 slot now points at the candidate.
    function _upgradePreservingBindings(address newImplementation, bytes memory data) internal {
        bytes32 expected = _chainwallSecurityBindingsHash();
        super.upgradeToAndCall(newImplementation, data);
        address actualImplementation = ERC1967Utils.getImplementation();
        if (actualImplementation != newImplementation) {
            revert ChainwallUpgradeImplementationChanged(newImplementation, actualImplementation);
        }
        bytes32 actual = _chainwallSecurityBindingsHash();
        if (actual != expected) revert ChainwallUpgradeBindingsChanged(expected, actual);
    }

    function _hashSecurityBindings(bytes memory encoded) internal pure returns (bytes32) {
        return ChainwallUpgradeHash.hash(encoded);
    }

    function _chainwallSecurityBindingsHash() internal view virtual returns (bytes32);
}
