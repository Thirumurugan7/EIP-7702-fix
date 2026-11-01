// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {RegistryTransitionGuard} from "../RegistryTransitionGuard.sol";
import {DiamondAdminStorage} from "../diamond/DiamondAdminStorage.sol";
import {DiamondCutStorage} from "../diamond/DiamondCutStorage.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {DiamondLoupeStorage} from "../diamond/DiamondLoupeStorage.sol";
import {DiamondSelectors} from "../diamond/DiamondSelectors.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title IDiamondCut (ERC-2535)
/// @notice Standard diamond-cut surface exposed by the registry dispatcher.
interface IDiamondCut {
    /// @notice Action applied to a selector set during a cut.
    enum FacetCutAction {
        Add,
        Replace,
        Remove
    }

    /// @notice One facet operation in a diamond cut batch.
    struct FacetCut {
        /// @notice Facet implementation address used by the cut.
        address facetAddress;
        /// @notice Whether selectors are added, replaced, or removed.
        FacetCutAction action;
        /// @notice Function selectors affected by the cut.
        bytes4[] functionSelectors;
    }

    /// @notice Add, replace, or remove facet functions. Production v1 requires zero `init` and empty `calldata`.
    function diamondCut(FacetCut[] calldata _diamondCut, address _init, bytes calldata _calldata) external;

    /// @dev MUST be emitted on any successful diamondCut.
    event DiamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata);
}

/// @title DiamondCutFacet
/// @notice Admin-only facet to manage selectors according to ERC-2535.
/// @dev This facet is the timelocked, ERC-2535-compatible way to evolve a live registry.
///      It ultimately forwards to the dispatcher's selector-management helpers so
///      the selector map and loupe metadata stay in sync.
///
///      Example:
///      1. governance queues a cut through the timelock
///      2. the action becomes ready after delay and approvals
///      3. `diamondCut` adds, replaces, or removes selectors
///      4. state migrations use separate typed actions with explicit postconditions
contract DiamondCutFacet is IDiamondCut, FacetGuard {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    uint256 public constant VERSION = 2;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    error CutsFrozenError();
    error CoreSelectorProtected(bytes4 selector);
    error DirectSelectorProtected(bytes4 selector);
    error DiamondCutCallFailed();
    error DuplicateSelector(bytes4 selector);
    error EmptyDiamondCut();
    error EmptySelectorSet();
    error FacetAddressIsDiamond();
    error FacetAddressMustBeZero();
    error FacetAddressZero();
    error FacetHasNoCode(address facet);
    error DiamondCutInitUnsupported();
    error MissingCodeCommitment(bytes32 actionId);
    error SelectorAlreadyExists(bytes4 selector);
    error SelectorDoesNotExist(bytes4 selector);
    error SelectorMapsToSameFacet(bytes4 selector, address facet);
    error TimelockedCodeChanged(bytes32 actionId, bytes32 expected, bytes32 actual);

    /// @notice Perform a standard diamond cut.
    /// @dev Add, Replace, and Remove retain their exact ERC-2535 meaning at both
    ///      proposal and execution. Runtime code hashes are committed when an
    ///      action queues so an approved address cannot change code before replay.
    function diamondCut(FacetCut[] calldata _diamondCut, address _init, bytes calldata _calldata) external {
        address actor = _msgSenderD();
        if (msg.sender == address(this) && actor == address(this)) {
            require(DiamondAdminStorage.state().selfCallDepth > 0, "SelfCallBlocked");
        } else {
            require(IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor), "NotAuthorized");
        }
        if (DiamondAdminStorage.state().cutsFrozen) {
            revert CutsFrozenError();
        }
        _validateCut(_diamondCut);
        _requireCodeOnlyCut(_init, _calldata);
        if (_diamondCut.length == 0) revert EmptyDiamondCut();

        bytes32 codeCommitment = _codeCommitment(_diamondCut);
        (bool executing, bytes32 actionId) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryDiamond(),
                scope: keccak256("diamond.cut"),
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.diamondCut.selector, _diamondCut, _init, _calldata)
        );
        if (!executing) {
            DiamondCutStorage.getLayout().queuedCodeCommitment[actionId] = codeCommitment;
            return;
        }
        if (actionId != bytes32(0)) {
            DiamondCutStorage.Layout storage cutStorage = DiamondCutStorage.getLayout();
            bytes32 expected = cutStorage.queuedCodeCommitment[actionId];
            if (expected == bytes32(0)) revert MissingCodeCommitment(actionId);
            if (expected != codeCommitment) {
                revert TimelockedCodeChanged(actionId, expected, codeCommitment);
            }
            delete cutStorage.queuedCodeCommitment[actionId];
        }

        RegistryTransitionGuard.Snapshot memory transitionBefore = RegistryTransitionGuard.snapshot();

        for (uint256 i = 0; i < _diamondCut.length;) {
            FacetCut calldata c = _diamondCut[i];
            if (c.action == FacetCutAction.Add || c.action == FacetCutAction.Replace) {
                _setSelectors(c.functionSelectors, c.facetAddress);
            } else if (c.action == FacetCutAction.Remove) {
                for (uint256 j = 0; j < c.functionSelectors.length;) {
                    _removeSelector(c.functionSelectors[j]);
                    unchecked {
                        ++j;
                    }
                }
            }
            unchecked {
                ++i;
            }
        }

        // Cut helpers only call this Registry to change routing; arbitrary init calls are rejected and no user
        // callback runs.
        // forge-lint: disable-next-line(reentrancy-events)
        emit DiamondCut(_diamondCut, _init, _calldata);

        // A cut may change resolution or policy semantics without touching a
        // catalog record directly. Invalidate pinned intents.
        RegistryTransitionGuard.advanceFrom(transitionBefore);
    }

    /// @notice Reject a selector that bootstrap attempted to route through fallback.
    /// @dev Called by RegistryDiamond before core installation. Once core exists,
    ///      strict diamondCut validation enforces the same boundary.
    function validateBootstrapSelector(bytes4 selector) external pure {
        if (DiamondSelectors.isDirect(selector)) revert DirectSelectorProtected(selector);
        if (DiamondSelectors.isCore(selector)) revert CoreSelectorProtected(selector);
    }

    /// @notice Emit the complete initial routing table after core installation.
    /// @dev RegistryDiamond invokes this function by delegatecall during its
    ///      one-time bootstrap. Direct selectors are represented in the event but
    ///      are never inserted into fallback routing storage.
    function emitInitialDiamondCut() external {
        DiamondLoupeStorage.Layout storage loupe = DiamondLoupeStorage.getLayout();
        uint256 facetCount = loupe.facetAddrs.length();
        FacetCut[] memory cuts = new FacetCut[](facetCount + 1);
        for (uint256 i = 0; i < facetCount;) {
            address facet = loupe.facetAddrs.at(i);
            uint256 selectorCount = loupe.selectorsOf[facet].length();
            bytes4[] memory selectors = new bytes4[](selectorCount);
            for (uint256 j = 0; j < selectorCount;) {
                selectors[j] = DiamondLoupeStorage._b4(loupe.selectorsOf[facet].at(j));
                unchecked {
                    ++j;
                }
            }
            cuts[i] = FacetCut({facetAddress: facet, action: FacetCutAction.Add, functionSelectors: selectors});
            unchecked {
                ++i;
            }
        }
        cuts[facetCount] = FacetCut({
            facetAddress: address(this),
            action: FacetCutAction.Add,
            functionSelectors: DiamondSelectors.directSelectors()
        });
        // Cut helpers only call this Registry to change routing; arbitrary init calls are rejected and no user
        // callback runs.
        // forge-lint: disable-next-line(reentrancy-events)
        emit DiamondCut(cuts, address(0), "");
    }

    function _validateCut(FacetCut[] calldata cuts) private view {
        DiamondLoupeStorage.Layout storage loupe = DiamondLoupeStorage.getLayout();
        uint256 total = 0;
        for (uint256 i = 0; i < cuts.length;) {
            // A diamond cut is atomic; every selector transition must be valid and every routing update must
            // succeed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (cuts[i].functionSelectors.length == 0) revert EmptySelectorSet();
            total += cuts[i].functionSelectors.length;
            unchecked {
                ++i;
            }
        }

        bytes4[] memory seen = new bytes4[](total);
        uint256 seenCount = 0;
        for (uint256 i = 0; i < cuts.length;) {
            FacetCut calldata cut = cuts[i];
            if (cut.action == FacetCutAction.Remove) {
                // A diamond cut is atomic; every selector transition must be valid and every routing update must
                // succeed.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (cut.facetAddress != address(0)) revert FacetAddressMustBeZero();
            } else {
                // A diamond cut is atomic; every selector transition must be valid and every routing update must
                // succeed.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (cut.facetAddress == address(0)) revert FacetAddressZero();
                // A diamond cut is atomic; every selector transition must be valid and every routing update must
                // succeed.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (cut.facetAddress == address(this)) revert FacetAddressIsDiamond();
                // A diamond cut is atomic; every selector transition must be valid and every routing update must
                // succeed.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (cut.facetAddress.code.length == 0) revert FacetHasNoCode(cut.facetAddress);
            }

            for (uint256 j = 0; j < cut.functionSelectors.length;) {
                bytes4 selector = cut.functionSelectors[j];
                for (uint256 k = 0; k < seenCount;) {
                    // A diamond cut is atomic; every selector transition must be valid and every routing update
                    // must succeed.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    if (seen[k] == selector) revert DuplicateSelector(selector);
                    unchecked {
                        ++k;
                    }
                }
                seen[seenCount++] = selector;

                // A diamond cut is atomic; every selector transition must be valid and every routing update must
                // succeed.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (DiamondSelectors.isDirect(selector)) revert DirectSelectorProtected(selector);
                if (cut.action == FacetCutAction.Remove && DiamondSelectors.isCore(selector)) {
                    // A diamond cut is atomic; every selector transition must be valid and every routing update
                    // must succeed.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert CoreSelectorProtected(selector);
                }

                address current = loupe.selectorToFacet[selector];
                if (cut.action == FacetCutAction.Add) {
                    // A diamond cut is atomic; every selector transition must be valid and every routing update
                    // must succeed.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    if (current != address(0)) revert SelectorAlreadyExists(selector);
                } else if (cut.action == FacetCutAction.Replace) {
                    // A diamond cut is atomic; every selector transition must be valid and every routing update
                    // must succeed.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    if (current == address(0)) revert SelectorDoesNotExist(selector);
                    // A diamond cut is atomic; every selector transition must be valid and every routing update
                    // must succeed.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    if (current == cut.facetAddress) revert SelectorMapsToSameFacet(selector, current);
                } else if (current == address(0)) {
                    // A diamond cut is atomic; every selector transition must be valid and every routing update
                    // must succeed.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert SelectorDoesNotExist(selector);
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Arbitrary init delegatecalls can mutate governance or business state outside the enumerable routing
    ///      commitment. Production v1 accepts only selector changes; state migrations require dedicated actions.
    function _requireCodeOnlyCut(address init, bytes calldata data) private pure {
        if (init != address(0) || data.length != 0) revert DiamondCutInitUnsupported();
    }

    function _codeCommitment(FacetCut[] calldata cuts) private view returns (bytes32 commitment) {
        // Preserve the historical no-init commitment seed so already queued code-only cuts remain reproducible.
        commitment = keccak256(abi.encode(address(0), bytes32(0)));
        for (uint256 i = 0; i < cuts.length;) {
            FacetCut calldata cut = cuts[i];
            if (cut.action != FacetCutAction.Remove) {
                commitment = keccak256(abi.encode(commitment, cut.facetAddress, cut.facetAddress.codehash));
            }
            unchecked {
                ++i;
            }
        }
    }

    function _setSelectors(bytes4[] calldata selectors, address facet) private {
        DiamondAdminStorage.Layout storage admin = DiamondAdminStorage.state();
        admin.selfCallDepth += 1;
        // An authorized cut uses Registry self-calls to update each route under selfCallDepth; any failure
        // rolls back the cut.
        // forge-lint: disable-start(calls-loop)
        (bool ok, bytes memory err) =
            address(this).call(abi.encodeWithSignature("setFacets(bytes4[],address)", selectors, facet));
        // forge-lint: disable-end(calls-loop)
        admin.selfCallDepth -= 1;
        _revertIfFailed(ok, err);
    }

    function _removeSelector(bytes4 selector) private {
        DiamondAdminStorage.Layout storage admin = DiamondAdminStorage.state();
        admin.selfCallDepth += 1;
        // An authorized cut uses Registry self-calls to update each route under selfCallDepth; any failure rolls
        // back the cut.
        // forge-lint: disable-next-line(calls-loop)
        (bool ok, bytes memory err) = address(this).call(abi.encodeWithSignature("removeFacet(bytes4)", selector));
        admin.selfCallDepth -= 1;
        _revertIfFailed(ok, err);
    }

    function _revertIfFailed(bool ok, bytes memory err) private pure {
        if (ok) return;
        if (err.length != 0) {
            assembly {
                // A diamond cut is atomic; every selector transition must be valid and every routing update must
                // succeed.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert(add(err, 0x20), mload(err))
            }
        }
        // A diamond cut is atomic; every selector transition must be valid and every routing update must succeed.
        // forge-lint: disable-next-line(require-revert-in-loop)
        revert DiamondCutCallFailed();
    }
}
