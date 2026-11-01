// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {PagedIndex} from "../../PagedIndex.sol";
import {ContractImportProvenance, InteractionImportProvenance, TokenImportProvenance} from "../../RegistryTypes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {
    AccountAddrsStorage,
    ContractsStorage,
    GroupsStorage,
    InteractionsStorage,
    PoliciesStorage,
    SafeAddrsStorage,
    SyncStorage,
    TokensStorage
} from "../../registry/RegistryShared.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title RegistrySyncQueryFacet
/// @notice Sync source and import provenance queries plus bounded index maintenance.
contract RegistrySyncQueryFacet is FacetGuard {
    using PagedIndex for PagedIndex.Index;

    uint256 public constant VERSION = 2;
    bytes32 private constant _ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 private constant _MIN_EPOCH_ROLL_PAGES = 16;
    uint256 private constant _GROUP_INDEX = 1 << 0;
    uint256 private constant _POLICY_INDEX = 1 << 1;
    uint256 private constant _CONTRACT_INDEX = 1 << 2;
    uint256 private constant _INTERACTION_INDEX = 1 << 3;
    uint256 private constant _TOKEN_INDEX = 1 << 4;
    uint256 private constant _SAFE_INDEX = 1 << 5;
    uint256 private constant _ACCOUNT_INDEX = 1 << 6;
    uint256 private constant _SUPPORTED_INDEXES = (1 << 7) - 1;

    /// @notice Thrown when the actor cannot perform Registry index maintenance.
    error IndexEpochRollNotAuthorized();
    /// @notice Thrown when the mask is zero or contains an unsupported index bit.
    error InvalidIndexEpochRollMask(uint256 indexMask);
    /// @notice Thrown when a selected index has not accumulated enough touched pages.
    error IndexEpochRollThresholdNotMet(uint256 indexMask, uint256 touchedPages, uint256 minimumTouchedPages);

    /// @notice Emitted when one Registry index seals its current journal epoch.
    event IndexEpochRolled(
        uint256 indexed indexMask, uint64 indexed sealedEpoch, uint256 touchedPages, address indexed operator
    );

    /// @notice Return the hard roll floor and the supported Registry index mask.
    /// @dev Organization ids are intentionally absent because their index is append-only.
    function getIndexEpochRollConfig() external pure returns (uint256 minimumTouchedPages, uint256 supportedMask) {
        return (_MIN_EPOCH_ROLL_PAGES, _SUPPORTED_INDEXES);
    }

    /// @notice Seal the current epochs of selected Registry indexes atomically.
    /// @dev Every selected index must meet the hard touched-page floor. This prevents
    ///      maintenance callers from creating empty epoch gaps that stale SDK cursors
    ///      would otherwise traverse one RPC request at a time. Inserts do not use the
    ///      epoch journal, so append-only organization ids are not selectable.
    function rollIndexEpochs(uint256 indexMask) external whenNotPausedD nonReentrantD {
        if (indexMask == 0 || indexMask & ~_SUPPORTED_INDEXES != 0) {
            revert InvalidIndexEpochRollMask(indexMask);
        }

        address actor = _msgSenderD();
        if (!_canMaintainIndexes(actor)) revert IndexEpochRollNotAuthorized();

        if (indexMask & _GROUP_INDEX != 0) {
            _rollIndexEpoch(GroupsStorage.getLayout().groupIds, _GROUP_INDEX, actor);
        }
        if (indexMask & _POLICY_INDEX != 0) {
            _rollIndexEpoch(PoliciesStorage.getLayout().policyIds, _POLICY_INDEX, actor);
        }
        if (indexMask & _CONTRACT_INDEX != 0) {
            _rollIndexEpoch(ContractsStorage.getLayout().contractKeys, _CONTRACT_INDEX, actor);
        }
        if (indexMask & _INTERACTION_INDEX != 0) {
            _rollIndexEpoch(InteractionsStorage.getLayout().interactionIds, _INTERACTION_INDEX, actor);
        }
        if (indexMask & _TOKEN_INDEX != 0) {
            _rollIndexEpoch(TokensStorage.getLayout().tokenKeys, _TOKEN_INDEX, actor);
        }
        if (indexMask & _SAFE_INDEX != 0) {
            _rollIndexEpoch(SafeAddrsStorage.getLayout().safeAddrs, _SAFE_INDEX, actor);
        }
        if (indexMask & _ACCOUNT_INDEX != 0) {
            _rollIndexEpoch(AccountAddrsStorage.getLayout().accountAddrs, _ACCOUNT_INDEX, actor);
        }
    }

    function isSyncSourceAllowed(address sourceRegistry) external view returns (bool) {
        return SyncStorage.getLayout().isSyncSourceAllowed[sourceRegistry];
    }

    function getSyncSourceCount() external view returns (uint256) {
        return SyncStorage.getLayout().syncSources.length();
    }

    function getSyncSourceAt(uint256 index) external view returns (address) {
        return _addressFromKey(SyncStorage.getLayout().syncSources.valueAt(index));
    }

    function getSyncSourcesPage(uint256 start, uint256 count) external view returns (address[] memory out) {
        bytes32[] memory page = SyncStorage.getLayout().syncSources.page(start, count);
        out = new address[](page.length);
        for (uint256 i = 0; i < page.length; ++i) {
            out[i] = _addressFromKey(page[i]);
        }
    }

    function getActiveContractImport(bytes32 key)
        external
        view
        returns (bool active, ContractImportProvenance memory provenance)
    {
        SyncStorage.Layout storage sl = SyncStorage.getLayout();
        active = SyncStorage.hasActiveContractImport(sl, key);
        provenance = sl.activeContractImports[key];
    }

    function getContractImportHistoryCount(bytes32 key) external view returns (uint256) {
        return SyncStorage.getLayout().contractImportHistory[key].length;
    }

    function getContractImportHistoryAt(bytes32 key, uint256 index)
        external
        view
        returns (ContractImportProvenance memory)
    {
        return SyncStorage.getLayout().contractImportHistory[key][index];
    }

    function getActiveTokenImport(bytes32 key)
        external
        view
        returns (bool active, TokenImportProvenance memory provenance)
    {
        SyncStorage.Layout storage sl = SyncStorage.getLayout();
        active = SyncStorage.hasActiveTokenImport(sl, key);
        provenance = sl.activeTokenImports[key];
    }

    function getTokenImportHistoryCount(bytes32 key) external view returns (uint256) {
        return SyncStorage.getLayout().tokenImportHistory[key].length;
    }

    function getTokenImportHistoryAt(bytes32 key, uint256 index) external view returns (TokenImportProvenance memory) {
        return SyncStorage.getLayout().tokenImportHistory[key][index];
    }

    function getActiveInteractionImport(bytes32 key)
        external
        view
        returns (bool active, InteractionImportProvenance memory provenance)
    {
        SyncStorage.Layout storage sl = SyncStorage.getLayout();
        active = SyncStorage.hasActiveInteractionImport(sl, key);
        provenance = sl.activeInteractionImports[key];
    }

    function getInteractionImportHistoryCount(bytes32 key) external view returns (uint256) {
        return SyncStorage.getLayout().interactionImportHistory[key].length;
    }

    function getInteractionImportHistoryAt(bytes32 key, uint256 index)
        external
        view
        returns (InteractionImportProvenance memory)
    {
        return SyncStorage.getLayout().interactionImportHistory[key][index];
    }

    /// @dev Return whether `actor` can seal Registry index epochs without changing their contents.
    function _canMaintainIndexes(address actor) private view returns (bool) {
        if (IAccessControl(address(this)).hasRole(_ADMIN_ROLE, actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.REGISTRY_MANAGER)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.INDEX_MAINTAINER)) return true;
        return false;
    }

    /// @dev Seal one eligible index. A later failure reverts every earlier roll in the mask.
    function _rollIndexEpoch(PagedIndex.Index storage index, uint256 indexMask, address actor) private {
        uint64 sealedEpoch = index.currentEpoch;
        uint256 touchedPages = index.epochPageCount(sealedEpoch);
        if (touchedPages < _MIN_EPOCH_ROLL_PAGES) {
            revert IndexEpochRollThresholdNotMet(indexMask, touchedPages, _MIN_EPOCH_ROLL_PAGES);
        }
        index.rollEpoch();
        // Epoch reads and rollEpoch are internal PagedIndex operations; no external call occurs before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit IndexEpochRolled(indexMask, sealedEpoch, touchedPages, actor);
    }

    function _addressFromKey(bytes32 key) private pure returns (address) {
        return address(uint160(uint256(key)));
    }
}
