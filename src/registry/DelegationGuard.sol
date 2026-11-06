// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "../Delegation7702.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title DelegateAllowlistStorage
/// @notice Registry storage for the EIP-7702 delegates this tenant accepts behind its actors.
/// @dev Empty by default: an actor that carries any delegation has no authority. Each entry pins the
///      delegate's runtime codehash at approval time, so an approved address whose code later differs
///      stops being accepted without a second governance action.
library DelegateAllowlistStorage {
    using EnumerableSet for EnumerableSet.AddressSet;

    bytes32 internal constant SLOT = keccak256("okc.storage.delegate_allowlist");

    struct Layout {
        EnumerableSet.AddressSet delegates;
        mapping(address delegate => bytes32 codehash) codehashOf;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

/// @title DelegationRules
/// @notice The complete EIP-7702 actor rule: a delegated EOA holds no authority unless its delegate is approved.
/// @dev Compiled only into the facet that owns the allowlist (RegistryUsersFacet), which exposes it through
///      `isActorUsable` and `requireActorUsable`. Every other Registry component reaches it through the
///      thin {DelegationGuard}, which keeps their bytecode growth to a few dozen bytes.
library DelegationRules {
    /// @notice `actor` carries an EIP-7702 delegation to a delegate this Registry has not approved.
    error ActorDelegated(address actor, address delegate);

    /// @notice Return whether `delegate` is approved and still has the code that was approved.
    function isDelegateAllowed(address delegate) internal view returns (bool) {
        bytes32 approved = DelegateAllowlistStorage.getLayout().codehashOf[delegate];
        return approved != bytes32(0) && delegate.codehash == approved;
    }

    /// @notice Return whether `actor` may hold or exercise authority.
    /// @dev True for accounts without a delegation (plain EOAs and contracts) and for EOAs whose
    ///      delegate is approved.
    function isActorUsable(address actor) internal view returns (bool) {
        address delegate = Delegation7702.delegateOf(actor);
        return delegate == address(0) || isDelegateAllowed(delegate);
    }

    /// @notice Revert unless `actor` may hold or exercise authority.
    function requireActorUsable(address actor) internal view {
        address delegate = Delegation7702.delegateOf(actor);
        if (delegate != address(0) && !isDelegateAllowed(delegate)) revert ActorDelegated(actor, delegate);
    }
}

/// @title DelegationGuard
/// @notice Thin entry to the EIP-7702 actor rule for code that runs in the Registry diamond's context.
/// @dev An EIP-7702 designator is exactly 23 bytes of code. Any other account passes after a single
///      EXTCODESIZE, with no call and no storage read. Only a 23-byte account is referred to the Registry's
///      own `isActorUsable` / `requireActorUsable` (a self STATICCALL routed to RegistryUsersFacet), where
///      {DelegationRules} decides. If that call cannot be answered (for example its selector is contained
///      by a pause), the account is treated as not usable: the guard fails closed.
library DelegationGuard {
    /// @dev uint32(bytes4(keccak256("isActorUsable(address)")))
    uint256 private constant IS_ACTOR_USABLE = 0x813d2582;
    /// @dev uint32(bytes4(keccak256("requireActorUsable(address)")))
    uint256 private constant REQUIRE_ACTOR_USABLE = 0x8044a2d5;

    // Calldata is built in scratch space as a right-aligned selector word followed by the address word,
    // and sent from offset 0x1c. This keeps the guard to a few dozen bytes in every facet that inlines it.

    function isActorUsable(address actor) internal view returns (bool usable) {
        assembly ("memory-safe") {
            usable := 1
            if eq(extcodesize(actor), 23) {
                mstore(0x00, IS_ACTOR_USABLE)
                mstore(0x20, actor)
                let answered := staticcall(gas(), address(), 0x1c, 0x24, 0x00, 0x20)
                usable := and(and(answered, gt(returndatasize(), 0x1f)), iszero(iszero(mload(0x00))))
            }
        }
    }

    function requireActorUsable(address actor) internal view {
        assembly ("memory-safe") {
            if eq(extcodesize(actor), 23) {
                mstore(0x00, REQUIRE_ACTOR_USABLE)
                mstore(0x20, actor)
                if iszero(staticcall(gas(), address(), 0x1c, 0x24, 0x00, 0x00)) {
                    let ptr := mload(0x40)
                    returndatacopy(ptr, 0x00, returndatasize())
                    revert(ptr, returndatasize())
                }
            }
        }
    }
}
