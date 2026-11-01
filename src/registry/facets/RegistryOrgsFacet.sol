// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {PagedIndex} from "../../PagedIndex.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {KeccakHelpers as KH} from "../../registry/Hashing.sol";
import {Authority, OrgsStorage} from "../../registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/**
 * @title RegistryOrgsFacet
 * @notice Organization CRUD and membership management for the modular Registry.
 * @dev Organization metadata is historical and grants no contract/token authority
 *      unless governance explicitly enables catalog delegation. Delegated authority
 *      also requires an existing, unsuspended organization.
 */
contract RegistryOrgsFacet is FacetGuard {
    using EnumerableSet for EnumerableSet.AddressSet;
    using PagedIndex for PagedIndex.Index;

    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant CATALOG_DELEGATION_SCOPE = keccak256("org.catalog.delegation");

    error NotAuthorized();
    error AlreadyMember();
    error NotMember();
    error EmptyId();
    error TooManyItems();
    error OrgNotFound();
    error AddressZero();
    error PendingOwnerOnly();
    error OwnerUnchanged();
    error OwnerChangeRequiresProposal();
    error InitialMembersOnlyOnCreate();

    event OrgUpsert(string id, address indexed operator);
    event OrgMemberAdded(string indexed orgId, address indexed member);
    event OrgMemberRemoved(string indexed orgId, address indexed member);
    event OrgCatalogDelegationSet(bool enabled, address indexed operator);
    event OrgSuspensionSet(string indexed orgId, bool suspended, address indexed operator);
    event OrgOwnerProposed(string indexed orgId, address indexed currentOwner, address indexed pendingOwner);
    event OrgOwnerTransferred(string indexed orgId, address indexed previousOwner, address indexed newOwner);

    /**
     * @notice Creates or updates an organization.
     * @param id Organization identifier (lowercase enforced).
     * @param owner_ Owner to set on create. On update, zero or the current owner.
     * @param rugged Rugged flag persisted on the record.
     * @param initialMembers Optional initial members (capped for gas safety).
     * @dev Registry governance creates organizations. Existing organization owners
     *      may update their own record, and that live ownership is checked again
     *      when a queued update executes. Ownership changes use proposeOrgOwner;
     *      silently ignoring a different owner here would make a successful update
     *      appear to have transferred authority when it did not.
     */
    function upsertOrg(string calldata id, address owner_, bool rugged, address[] calldata initialMembers)
        external
        whenNotPausedD
        nonReentrantD
    {
        if (bytes(id).length == 0) revert EmptyId();
        _requireLowercase(id);
        bytes32 h = _orgHash(id);
        address caller = _msgSenderD();

        // Timelock replay exposes the stored actor through `_msgSenderD`. Re-run
        // the original authorization so revoking that actor before ETA cancels
        // their practical authority without requiring queue-wide cleanup.
        OrgsStorage.Layout storage ol = OrgsStorage.getLayout();
        bool exists = OrgsStorage.exists(ol, h);
        if (!(_isBootstrapOwnerD(caller) || _isAdmin(caller) || _hasOrgWriteCapability(caller)
                    || (exists && Authority._getOwner(h) == caller))) {
            revert NotAuthorized();
        }
        if (initialMembers.length > 100) revert TooManyItems();
        if (exists && initialMembers.length != 0) revert InitialMembersOnlyOnCreate();
        if (exists && owner_ != address(0) && owner_ != Authority._getOwner(h)) {
            revert OwnerChangeRequiresProposal();
        }
        for (uint256 i; i < initialMembers.length; ++i) {
            // Org creation commits the complete member list and canonical identifier; invalid entries cannot be
            // skipped.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (initialMembers[i] == address(0)) revert AddressZero();
        }

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryOrg(), scope: h, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.upsertOrg.selector, id, owner_, rugged, initialMembers)
        );
        if (!executing) {
            return;
        }

        address actor = _msgSenderD();
        bool fresh = bytes(ol.orgs[h].id).length == 0;

        if (fresh) {
            ol.orgs[h].id = id;
            Authority._setOwner(h, owner_ == address(0) ? actor : owner_);
            ol.orgIds.insert(h);

            for (uint256 i = 0; i < initialMembers.length;) {
                if (ol.orgs[h].members.add(initialMembers[i])) {
                    // Org entrypoints hold nonReentrantD; membership and ownership helpers update local storage
                    // without callbacks.
                    // forge-lint: disable-next-line(reentrancy-events)
                    emit OrgMemberAdded(id, initialMembers[i]);
                }
                unchecked {
                    ++i;
                }
            }
        } else {
            // Keep execution-time authority identical to the pre-queue check.
            // Otherwise the bootstrap owner can successfully submit an immediate
            // or delayed update and then be rejected by its self-call replay.
            if (!(_isBootstrapOwnerD(actor) || Authority._getOwner(h) == actor || _isAdmin(actor)
                        || _hasOrgWriteCapability(actor))) {
                revert NotAuthorized();
            }
            if (initialMembers.length != 0) revert InitialMembersOnlyOnCreate();
        }

        ol.orgs[h].rugged = rugged;
        // Org entrypoints hold nonReentrantD; membership and ownership helpers update local storage without
        // callbacks.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OrgUpsert(id, actor);
    }

    /**
     * @notice Adds a member to an organization.
     * @param id Organization identifier.
     * @param member Address to add as member.
     */
    function addOrgMember(string calldata id, address member) external whenNotPausedD nonReentrantD {
        if (bytes(id).length == 0) revert EmptyId();
        _requireLowercase(id);
        if (member == address(0)) revert AddressZero();
        bytes32 h = _orgHash(id);
        OrgsStorage.Layout storage ol = OrgsStorage.getLayout();
        if (!OrgsStorage.exists(ol, h)) revert OrgNotFound();
        address caller = _msgSenderD();

        if (!(Authority._getOwner(h) == caller || _isAdmin(caller) || _hasOrgWriteCapability(caller))) {
            revert NotAuthorized();
        }
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryOrg(), scope: h, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.addOrgMember.selector, id, member)
        );
        if (!executing) {
            return;
        }

        if (!OrgsStorage.exists(ol, h)) revert OrgNotFound();
        if (!ol.orgs[h].members.add(member)) revert AlreadyMember();
        // Org entrypoints hold nonReentrantD; membership and ownership helpers update local storage without
        // callbacks.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OrgMemberAdded(id, member);
    }

    /**
     * @notice Removes a member from an organization.
     * @param id Organization identifier.
     * @param member Address to remove.
     */
    function removeOrgMember(string calldata id, address member) external whenNotPausedD nonReentrantD {
        if (bytes(id).length == 0) revert EmptyId();
        _requireLowercase(id);
        if (member == address(0)) revert AddressZero();
        bytes32 h = _orgHash(id);
        OrgsStorage.Layout storage ol = OrgsStorage.getLayout();
        if (!OrgsStorage.exists(ol, h)) revert OrgNotFound();
        address caller = _msgSenderD();

        if (!(Authority._getOwner(h) == caller || _isAdmin(caller) || _hasOrgWriteCapability(caller))) {
            revert NotAuthorized();
        }
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryOrg(), scope: h, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.removeOrgMember.selector, id, member)
        );
        if (!executing) {
            return;
        }

        if (!OrgsStorage.exists(ol, h)) revert OrgNotFound();
        if (!ol.orgs[h].members.remove(member)) revert NotMember();
        // Org entrypoints hold nonReentrantD; membership and ownership helpers update local storage without
        // callbacks.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OrgMemberRemoved(id, member);
    }

    /// @notice Enable or disable org owner/member authority over contract and token records.
    /// @dev Defaults to disabled. Only Registry-level governance can opt in.
    function setOrgCatalogDelegationEnabled(bool enabled) external whenNotPausedD nonReentrantD {
        address actor = _msgSenderD();
        if (!_isOrgGovernance(actor)) revert NotAuthorized();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryOrg(),
                scope: CATALOG_DELEGATION_SCOPE,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setOrgCatalogDelegationEnabled.selector, enabled)
        );
        if (!executing) return;
        OrgsStorage.getLayout().catalogDelegationEnabled = enabled;
        // Org entrypoints hold nonReentrantD; membership and ownership helpers update local storage without
        // callbacks.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OrgCatalogDelegationSet(enabled, actor);
    }

    function isOrgCatalogDelegationEnabled() external view returns (bool) {
        return OrgsStorage.getLayout().catalogDelegationEnabled;
    }

    /// @notice Suspend or restore one org's delegated catalog authority.
    /// @dev Registry-level authorities retain recovery access while suspended.
    function setOrgSuspended(string calldata id, bool suspended) external whenNotPausedD nonReentrantD {
        bytes32 h = _requireOrg(id);
        address actor = _msgSenderD();
        if (!_isOrgGovernance(actor)) revert NotAuthorized();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryOrg(), scope: h, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setOrgSuspended.selector, id, suspended)
        );
        if (!executing) return;
        if (!OrgsStorage.exists(OrgsStorage.getLayout(), h)) revert OrgNotFound();
        OrgsStorage.getLayout().suspended[h] = suspended;
        // Org entrypoints hold nonReentrantD; membership and ownership helpers update local storage without
        // callbacks.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OrgSuspensionSet(id, suspended, actor);
    }

    function isOrgSuspended(string calldata id) external view returns (bool) {
        bytes32 h = _requireOrg(id);
        return OrgsStorage.getLayout().suspended[h];
    }

    /// @notice Propose a new organization owner through the org timelock category.
    function proposeOrgOwner(string calldata id, address newOwner) external whenNotPausedD nonReentrantD {
        bytes32 h = _requireOrg(id);
        if (newOwner == address(0)) revert AddressZero();
        address actor = _msgSenderD();
        address currentOwner = Authority._getOwner(h);
        if (!(actor == currentOwner || _isOrgGovernance(actor))) revert NotAuthorized();
        if (newOwner == currentOwner) revert OwnerUnchanged();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryOrg(), scope: h, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.proposeOrgOwner.selector, id, newOwner)
        );
        if (!executing) return;
        if (!OrgsStorage.exists(OrgsStorage.getLayout(), h)) revert OrgNotFound();
        OrgsStorage.getLayout().pendingOwner[h] = newOwner;
        // Org entrypoints hold nonReentrantD; membership and ownership helpers update local storage without
        // callbacks.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OrgOwnerProposed(id, currentOwner, newOwner);
    }

    /// @notice Accept organization ownership after a successful proposal.
    function acceptOrgOwner(string calldata id) external whenNotPausedD nonReentrantD {
        bytes32 h = _requireOrg(id);
        address actor = _msgSenderD();
        OrgsStorage.Layout storage ol = OrgsStorage.getLayout();
        if (ol.pendingOwner[h] != actor) revert PendingOwnerOnly();
        address previousOwner = Authority._getOwner(h);
        delete ol.pendingOwner[h];
        Authority._setOwner(h, actor);
        // Org entrypoints hold nonReentrantD; membership and ownership helpers update local storage without
        // callbacks.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OrgOwnerTransferred(id, previousOwner, actor);
    }

    function getPendingOrgOwner(string calldata id) external view returns (address) {
        return OrgsStorage.getLayout().pendingOwner[_requireOrg(id)];
    }

    /**
     * @notice Gets organization metadata (id/rugged/owner).
     */
    function getOrg(string calldata id) external view returns (string memory, bool, address) {
        bytes32 h = _orgHash(id);
        OrgsStorage.Layout storage ol = OrgsStorage.getLayout();
        return (ol.orgs[h].id, ol.orgs[h].rugged, Authority._getOwner(h));
    }

    /// @notice Gets organization metadata by its precomputed hash (keccak256 of id).
    function getOrgByHash(bytes32 h) external view returns (string memory, bool, address) {
        OrgsStorage.Layout storage ol = OrgsStorage.getLayout();
        return (ol.orgs[h].id, ol.orgs[h].rugged, Authority._getOwner(h));
    }

    /**
     * @notice Gets a page of members for an organization.
     * @param id Organization identifier.
     * @param start Start index.
     * @param count Number of members to return.
     * @return Array of member addresses in the requested window.
     */
    function getOrgMembers(string calldata id, uint256 start, uint256 count) external view returns (address[] memory) {
        bytes32 h = _orgHash(id);
        OrgsStorage.Layout storage ol = OrgsStorage.getLayout();
        uint256 len = ol.orgs[h].members.length();
        if (start >= len) return new address[](0);
        uint256 available = len - start;
        uint256 n = count > available ? available : count;
        address[] memory out = new address[](n);
        for (uint256 i = 0; i < n;) {
            out[i] = ol.orgs[h].members.at(start + i);
            unchecked {
                ++i;
            }
        }
        return out;
    }

    // Index views
    /// @notice Returns number of organizations
    function getOrgCount() external view returns (uint256) {
        return OrgsStorage.getLayout().orgIds.length();
    }

    /// @notice Returns org key at index
    function getOrgKeyAt(uint256 index) external view returns (bytes32) {
        return OrgsStorage.getLayout().orgIds.valueAt(index);
    }

    /// @notice Returns a page of org keys
    function getOrgKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return OrgsStorage.getLayout().orgIds.page(start, count);
    }

    function getOrgIndexNextId() external view returns (uint256) {
        return OrgsStorage.getLayout().orgIds.nextId();
    }

    function getOrgIndexCurrentEpoch() external view returns (uint64) {
        return OrgsStorage.getLayout().orgIds.currentEpoch;
    }

    function getOrgIndexAlivePage(uint256 pageIndex) external view returns (uint256) {
        return OrgsStorage.getLayout().orgIds.alivePage(pageIndex);
    }

    function getOrgIndexValues(uint256[] calldata ids) external view returns (bytes32[] memory) {
        return OrgsStorage.getLayout().orgIds.getValues(ids);
    }

    function getOrgIndexEpochPageCount(uint64 epoch) external view returns (uint256) {
        return OrgsStorage.getLayout().orgIds.epochPageCount(epoch);
    }

    function getOrgIndexEpochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return OrgsStorage.getLayout().orgIds.epochPageAt(epoch, i);
    }

    function getOrgIndexJournal(uint64 epoch, uint128 pageIndex)
        external
        view
        returns (uint256 updates, uint256 deletes)
    {
        return OrgsStorage.getLayout().orgIds.journal(epoch, pageIndex);
    }

    // Helpers
    function _isAdmin(address actor) private view returns (bool) {
        return IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor);
    }

    function _hasOrgWriteCapability(address actor) private view returns (bool) {
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.REGISTRY_MANAGER)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.ORG_MANAGER)) return true;
        return false;
    }

    function _isOrgGovernance(address actor) private view returns (bool) {
        if (_isBootstrapOwnerD(actor) || _isAdmin(actor)) return true;
        return CapabilitiesLib.hasCapability(actor, CapabilityIds.REGISTRY_MANAGER);
    }

    function _requireLowercase(string memory s) private pure {
        bytes memory b = bytes(s);
        for (uint256 i = 0; i < b.length;) {
            bytes1 c = b[i];
            // Org creation commits the complete member list and canonical identifier; invalid entries cannot be
            // skipped.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (c >= 0x41 && c <= 0x5A) revert("Identifier must be lowercase");
            unchecked {
                ++i;
            }
        }
    }

    function _orgHash(string memory id) private pure returns (bytes32 h) {
        KH.requireNoSlash(id);
        assembly ("memory-safe") {
            h := keccak256(add(id, 0x20), mload(id))
        }
    }

    function _requireOrg(string calldata id) private view returns (bytes32 h) {
        if (bytes(id).length == 0) revert EmptyId();
        _requireLowercase(id);
        h = _orgHash(id);
        if (!OrgsStorage.exists(OrgsStorage.getLayout(), h)) revert OrgNotFound();
    }
}
