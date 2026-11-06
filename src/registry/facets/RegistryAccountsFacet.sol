// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "../../Delegation7702.sol";
import {PagedIndex} from "../../PagedIndex.sol";
import {ProtocolCodehashes} from "../../ProtocolCodehashes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {AccountAddrsStorage, SafeAddrsStorage} from "../../registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

interface IManagedOKAccount {
    function INTERACT() external view returns (address);
    function REGISTRY() external view returns (address);
    function ENGINE() external view returns (address);
}

interface IManagedAccountFactory {
    function interact() external view returns (address);
    function isAccount(address account) external view returns (bool);
}

interface IManagedSafeFactory {
    function GUARD_CONTRACT() external view returns (address);
    function MODULE_CONTRACT() external view returns (address);
    function executionModule() external view returns (address);
    function isSafe(address safe) external view returns (bool);
    function validateManagedSafe(address safe) external view;
}

interface IManagedSafe {
    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory, address);
    function isModuleEnabled(address module) external view returns (bool);
}

interface IManagedSafeModuleValidator {
    function validateSafeExtensions(address safe) external view;
}

/**
 * @title RegistryAccountsFacet
 * @notice Allowlist management for Safe and native account types.
 * @dev Writes are admin/capability-gated and timelocked by category/scope.
 *      Factory-created tenant runtimes use this facet so `Interact` can distinguish approved vault types from
 *      arbitrary contracts. A Safe or account must be allowlisted here before account-mode execution can target it.
 */
contract RegistryAccountsFacet is FacetGuard {
    using PagedIndex for PagedIndex.Index;

    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant SAFE_ADD_SCOPE_DOMAIN = keccak256("registry.safe.add");
    bytes32 private constant SAFE_REMOVE_SCOPE_DOMAIN = keccak256("registry.safe.remove");
    bytes32 private constant ACCOUNT_ADD_SCOPE_DOMAIN = keccak256("registry.account.add");
    bytes32 private constant ACCOUNT_REMOVE_SCOPE_DOMAIN = keccak256("registry.account.remove");

    /// @notice Emitted when a Safe is allowlisted.
    event SafeAdded(address indexed safe);
    /// @notice Emitted when a Safe is removed from the allowlist.
    event SafeRemoved(address indexed safe);
    /// @notice Emitted when an account vault is allowlisted.
    event AccountAdded(address indexed account);
    /// @notice Emitted when an account vault is removed from the allowlist.
    event AccountRemoved(address indexed account);

    error SafeExists();
    error SafeMissing();
    error SafeInvalid();
    error SafeNotFactoryManaged(address safe);
    error SafeGuardMismatch(address safe, address expectedGuard, address actualGuard);
    error SafeModuleNotAllowed(address safe, address module);
    error SafeFallbackHandlerNotAllowed(address safe, address handler);
    error SafeModulePaginationLimit(address safe);
    error AccountExists();
    error AccountMissing();
    error AccountInvalid();
    error AccountNotFactoryManaged(address account);
    error AccountInteractMismatch(address account, address expectedInteract, address actualInteract);
    error AccountRegistryMismatch(address account, address expectedRegistry, address actualRegistry);
    error AccountEngineNotCanonical(address account, address engine);

    address private constant SENTINEL_MODULES = address(0x1);
    uint256 private constant SENTINEL_MODULES_WORD = 1;
    uint256 private constant PROVENANCE_QUERY_GAS = 100_000;
    // OKModule supports up to 16 pages of 16 modules. Keep enough gas for that
    // documented scan while preventing a hostile validator from consuming the
    // caller's entire transaction and shadowing a later canonical factory.
    uint256 private constant MODULE_VALIDATION_GAS = 2_000_000;
    bytes32 private constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 private constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    enum AccountFailureKind {
        None,
        Interact,
        Registry,
        EngineCode
    }

    struct AccountFactoryCheck {
        bool valid;
        AccountFailureKind failure;
        address expected;
        address actual;
    }

    enum SafeFailureKind {
        None,
        Guard,
        Module,
        Fallback
    }

    struct SafeFactoryCheck {
        bool valid;
        SafeFailureKind failure;
        address expected;
        address actual;
    }

    /// @notice Adds a Safe address to the allowlist.
    /// @param safe Safe proxy address to allowlist.
    function addSafe(address safe) external whenNotPausedD nonReentrantD {
        _requireSafeWriteRole();
        if (safe == address(0) || !Delegation7702.hasContractCode(safe)) revert SafeInvalid();
        bytes32 scope = _safeScope(safe, true);
        SafeAddrsStorage.Layout storage sl = SafeAddrsStorage.getLayout();
        if (SafeAddrsStorage.contains(sl, safe)) revert SafeExists();
        _requireManagedSafe(safe);

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categorySafe(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.addSafe.selector, safe)
        );
        if (!executing) {
            return;
        }

        if (SafeAddrsStorage.contains(sl, safe)) revert SafeExists();
        _requireManagedSafe(safe);
        SafeAddrsStorage.add(sl, safe);
        // Membership changes hold nonReentrantD; factory/account validation uses STATICCALL before the local write
        // and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeAdded(safe);
    }

    /// @notice Removes a Safe address from the allowlist.
    /// @param safe Safe proxy address to remove.
    function removeSafe(address safe) external whenNotPausedD nonReentrantD {
        _requireSafeWriteRole();
        bytes32 scope = _safeScope(safe, false);
        SafeAddrsStorage.Layout storage sl = SafeAddrsStorage.getLayout();
        if (!SafeAddrsStorage.contains(sl, safe)) revert SafeMissing();

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categorySafe(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.removeSafe.selector, safe)
        );
        if (!executing) {
            return;
        }

        if (!SafeAddrsStorage.contains(sl, safe)) revert SafeMissing();
        SafeAddrsStorage.remove(sl, safe);
        // Membership changes hold nonReentrantD; factory/account validation uses STATICCALL before the local write
        // and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeRemoved(safe);
    }

    /// @notice Checks if a Safe is allowlisted and has deployed code.
    function isSafeAllowed(address safe) external view returns (bool) {
        if (safe == address(0) || !Delegation7702.hasContractCode(safe)) {
            return false;
        }
        SafeAddrsStorage.Layout storage sl = SafeAddrsStorage.getLayout();
        return SafeAddrsStorage.contains(sl, safe);
    }

    /// @notice Return whether `authority` is the exact execution module of a currently valid managed Safe.
    /// @dev MiniScriptEngine uses this stronger check before executing in Safe storage. It prevents another
    ///      enabled module from impersonating the tenant Interact contract even if it exposes matching getters.
    function isSafeExecutionAuthorityAllowed(address safe, address authority) external view returns (bool) {
        if (safe == address(0) || authority == address(0) || !Delegation7702.hasContractCode(safe)) return false;
        if (!SafeAddrsStorage.contains(SafeAddrsStorage.getLayout(), safe)) return false;

        address[] memory factories = CapabilitiesLib.capabilityActors(CapabilityIds.ACCOUNT_MANAGER);
        for (uint256 i; i < factories.length; ++i) {
            (bool ok, address configuredModule) =
                _readAddress(factories[i], abi.encodeWithSelector(IManagedSafeFactory.executionModule.selector));
            if (!ok || configuredModule != authority) continue;
            if (_checkSafeFactory(factories[i], safe).valid) return true;
        }
        return false;
    }

    /// @notice Returns the number of allowlisted Safes.
    function getSafeCount() external view returns (uint256) {
        SafeAddrsStorage.Layout storage sl = SafeAddrsStorage.getLayout();
        return SafeAddrsStorage.length(sl);
    }

    /// @notice Returns the allowlisted Safe at index.
    function getSafeAt(uint256 index) external view returns (address) {
        SafeAddrsStorage.Layout storage sl = SafeAddrsStorage.getLayout();
        return SafeAddrsStorage.valueAt(sl, index);
    }

    /// @notice Returns a page of allowlisted Safes.
    function getSafePage(uint256 start, uint256 count) external view returns (address[] memory) {
        SafeAddrsStorage.Layout storage sl = SafeAddrsStorage.getLayout();
        return SafeAddrsStorage.page(sl, start, count);
    }

    function getSafeIndexNextId() external view returns (uint256) {
        return SafeAddrsStorage.getLayout().safeAddrs.nextId();
    }

    function getSafeIndexCurrentEpoch() external view returns (uint64) {
        return SafeAddrsStorage.getLayout().safeAddrs.currentEpoch;
    }

    function getSafeIndexAlivePage(uint256 pageIndex) external view returns (uint256) {
        return SafeAddrsStorage.getLayout().safeAddrs.alivePage(pageIndex);
    }

    function getSafeIndexValues(uint256[] calldata ids) external view returns (address[] memory out) {
        bytes32[] memory values = SafeAddrsStorage.getLayout().safeAddrs.getValues(ids);
        out = new address[](values.length);
        for (uint256 i = 0; i < values.length;) {
            out[i] = address(uint160(uint256(values[i])));
            unchecked {
                ++i;
            }
        }
    }

    function getSafeIndexEpochPageCount(uint64 epoch) external view returns (uint256) {
        return SafeAddrsStorage.getLayout().safeAddrs.epochPageCount(epoch);
    }

    function getSafeIndexEpochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return SafeAddrsStorage.getLayout().safeAddrs.epochPageAt(epoch, i);
    }

    function getSafeIndexJournal(uint64 epoch, uint128 pageIndex)
        external
        view
        returns (uint256 updates, uint256 deletes)
    {
        return SafeAddrsStorage.getLayout().safeAddrs.journal(epoch, pageIndex);
    }

    /// @notice Adds an Account address to the allowlist.
    /// @param account Account address to allowlist.
    function addAccount(address account) external whenNotPausedD nonReentrantD {
        _requireAccountWriteRole();
        if (account == address(0) || !Delegation7702.hasContractCode(account)) revert AccountInvalid();
        bytes32 scope = _accountScope(account, true);
        AccountAddrsStorage.Layout storage al = AccountAddrsStorage.getLayout();
        if (AccountAddrsStorage.contains(al, account)) revert AccountExists();
        _requireManagedAccount(account);

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryAccount(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.addAccount.selector, account)
        );
        if (!executing) {
            return;
        }

        if (AccountAddrsStorage.contains(al, account)) revert AccountExists();
        _requireManagedAccount(account);
        AccountAddrsStorage.add(al, account);
        // Membership changes hold nonReentrantD; factory/account validation uses STATICCALL before the local write
        // and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit AccountAdded(account);
    }

    /// @notice Removes an Account address from the allowlist.
    /// @param account Account address to remove.
    function removeAccount(address account) external whenNotPausedD nonReentrantD {
        _requireAccountWriteRole();
        bytes32 scope = _accountScope(account, false);
        AccountAddrsStorage.Layout storage al = AccountAddrsStorage.getLayout();
        if (!AccountAddrsStorage.contains(al, account)) revert AccountMissing();

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryAccount(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.removeAccount.selector, account)
        );
        if (!executing) {
            return;
        }

        if (!AccountAddrsStorage.contains(al, account)) revert AccountMissing();
        AccountAddrsStorage.remove(al, account);
        // Membership changes hold nonReentrantD; factory/account validation uses STATICCALL before the local write
        // and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit AccountRemoved(account);
    }

    /// @notice Checks if an Account is allowlisted and has deployed code.
    function isAccountAllowed(address account) external view returns (bool) {
        if (account == address(0) || !Delegation7702.hasContractCode(account)) {
            return false;
        }
        AccountAddrsStorage.Layout storage al = AccountAddrsStorage.getLayout();
        return AccountAddrsStorage.contains(al, account);
    }

    /// @notice Returns the number of allowlisted Accounts.
    function getAccountCount() external view returns (uint256) {
        return AccountAddrsStorage.length(AccountAddrsStorage.getLayout());
    }

    /// @notice Returns the allowlisted Account at index.
    function getAccountAt(uint256 index) external view returns (address) {
        return AccountAddrsStorage.valueAt(AccountAddrsStorage.getLayout(), index);
    }

    /// @notice Returns a page of allowlisted Accounts.
    function getAccountPage(uint256 start, uint256 count) external view returns (address[] memory) {
        return AccountAddrsStorage.page(AccountAddrsStorage.getLayout(), start, count);
    }

    function getAccountIndexNextId() external view returns (uint256) {
        return AccountAddrsStorage.getLayout().accountAddrs.nextId();
    }

    function getAccountIndexCurrentEpoch() external view returns (uint64) {
        return AccountAddrsStorage.getLayout().accountAddrs.currentEpoch;
    }

    function getAccountIndexAlivePage(uint256 pageIndex) external view returns (uint256) {
        return AccountAddrsStorage.getLayout().accountAddrs.alivePage(pageIndex);
    }

    function getAccountIndexValues(uint256[] calldata ids) external view returns (address[] memory out) {
        bytes32[] memory values = AccountAddrsStorage.getLayout().accountAddrs.getValues(ids);
        out = new address[](values.length);
        for (uint256 i = 0; i < values.length;) {
            out[i] = address(uint160(uint256(values[i])));
            unchecked {
                ++i;
            }
        }
    }

    function getAccountIndexEpochPageCount(uint64 epoch) external view returns (uint256) {
        return AccountAddrsStorage.getLayout().accountAddrs.epochPageCount(epoch);
    }

    function getAccountIndexEpochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return AccountAddrsStorage.getLayout().accountAddrs.epochPageAt(epoch, i);
    }

    function getAccountIndexJournal(uint64 epoch, uint128 pageIndex)
        external
        view
        returns (uint256 updates, uint256 deletes)
    {
        return AccountAddrsStorage.getLayout().accountAddrs.journal(epoch, pageIndex);
    }

    function _safeScope(address safe, bool addOperation) private pure returns (bytes32) {
        return keccak256(abi.encode(addOperation ? SAFE_ADD_SCOPE_DOMAIN : SAFE_REMOVE_SCOPE_DOMAIN, safe));
    }

    function _accountScope(address account, bool addOperation) private pure returns (bytes32) {
        return keccak256(abi.encode(addOperation ? ACCOUNT_ADD_SCOPE_DOMAIN : ACCOUNT_REMOVE_SCOPE_DOMAIN, account));
    }

    function _requireSafeWriteRole() private view {
        address actor = _msgSenderD();
        if (_isAdmin(actor) || CapabilitiesLib.hasCapability(actor, CapabilityIds.ACCOUNT_MANAGER)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, ADMIN_ROLE);
    }

    function _requireAccountWriteRole() private view {
        address actor = _msgSenderD();
        if (_isAdmin(actor) || CapabilitiesLib.hasCapability(actor, CapabilityIds.ACCOUNT_MANAGER)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, ADMIN_ROLE);
    }

    function _isAdmin(address actor) private view returns (bool) {
        return IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor);
    }

    function _requireManagedAccount(address account) private view {
        address[] memory factories = CapabilitiesLib.capabilityActors(CapabilityIds.ACCOUNT_MANAGER);
        AccountFactoryCheck memory recordedFailure;
        for (uint256 i; i < factories.length; ++i) {
            AccountFactoryCheck memory result = _checkAccountFactory(factories[i], account);
            if (result.valid) return;
            if (recordedFailure.failure == AccountFailureKind.None && result.failure != AccountFailureKind.None) {
                recordedFailure = result;
            }
        }
        if (recordedFailure.failure == AccountFailureKind.Interact) {
            revert AccountInteractMismatch(account, recordedFailure.expected, recordedFailure.actual);
        }
        if (recordedFailure.failure == AccountFailureKind.Registry) {
            revert AccountRegistryMismatch(account, recordedFailure.expected, recordedFailure.actual);
        }
        if (recordedFailure.failure == AccountFailureKind.EngineCode) {
            revert AccountEngineNotCanonical(account, recordedFailure.actual);
        }
        revert AccountNotFactoryManaged(account);
    }

    /// @dev Every external provenance probe is gas-bounded and accepts only its
    ///      exact static ABI size. A factory that claims an account but then
    ///      reverts, returns malformed/oversized data, or has stale bindings is
    ///      skipped so it cannot shadow a later canonical manager.
    function _checkAccountFactory(address factory, address account)
        private
        view
        returns (AccountFactoryCheck memory result)
    {
        if (!Delegation7702.hasContractCode(factory)) return result;
        (bool ok, bool managed) =
            _readBool(factory, abi.encodeWithSelector(IManagedAccountFactory.isAccount.selector, account));
        if (!ok || !managed) return result;

        address expectedInteract;
        (ok, expectedInteract) = _readAddress(factory, abi.encodeWithSelector(IManagedAccountFactory.interact.selector));
        if (!ok) return result;
        address actualInteract;
        (ok, actualInteract) = _readAddress(account, abi.encodeWithSelector(IManagedOKAccount.INTERACT.selector));
        if (!ok) return result;
        address actualRegistry;
        (ok, actualRegistry) = _readAddress(account, abi.encodeWithSelector(IManagedOKAccount.REGISTRY.selector));
        if (!ok) return result;
        address actualEngine;
        (ok, actualEngine) = _readAddress(account, abi.encodeWithSelector(IManagedOKAccount.ENGINE.selector));
        if (!ok) return result;

        if (actualInteract != expectedInteract) {
            return AccountFactoryCheck({
                valid: false, failure: AccountFailureKind.Interact, expected: expectedInteract, actual: actualInteract
            });
        }
        if (actualRegistry != address(this)) {
            return AccountFactoryCheck({
                valid: false, failure: AccountFailureKind.Registry, expected: address(this), actual: actualRegistry
            });
        }
        // The factory engine is only the default for future accounts. Existing
        // accounts adopt engines independently through Registry governance, so
        // provenance must not depend on which side was upgraded first.
        if (!Delegation7702.hasContractCode(actualEngine) || !ProtocolCodehashes.isAcceptedMiniScriptDeployment(actualEngine)) {
            return AccountFactoryCheck({
                valid: false, failure: AccountFailureKind.EngineCode, expected: address(0), actual: actualEngine
            });
        }
        result.valid = true;
    }

    function _requireManagedSafe(address safe) private view {
        address[] memory factories = CapabilitiesLib.capabilityActors(CapabilityIds.ACCOUNT_MANAGER);
        SafeFactoryCheck memory recordedFailure;
        for (uint256 i; i < factories.length; ++i) {
            SafeFactoryCheck memory result = _checkSafeFactory(factories[i], safe);
            if (result.valid) return;
            if (recordedFailure.failure == SafeFailureKind.None && result.failure != SafeFailureKind.None) {
                recordedFailure = result;
            }
        }
        if (recordedFailure.failure == SafeFailureKind.Guard) {
            revert SafeGuardMismatch(safe, recordedFailure.expected, recordedFailure.actual);
        }
        if (recordedFailure.failure == SafeFailureKind.Module) {
            revert SafeModuleNotAllowed(safe, recordedFailure.actual);
        }
        if (recordedFailure.failure == SafeFailureKind.Fallback) {
            revert SafeFallbackHandlerNotAllowed(safe, recordedFailure.actual);
        }
        revert SafeNotFactoryManaged(safe);
    }

    function _checkSafeFactory(address factory, address safe) private view returns (SafeFactoryCheck memory result) {
        if (!Delegation7702.hasContractCode(factory)) return result;
        (bool ok, bool managed) = _readBool(factory, abi.encodeWithSelector(IManagedSafeFactory.isSafe.selector, safe));
        if (!ok || !managed) return result;

        address expectedGuard;
        (ok, expectedGuard) = _readAddress(factory, abi.encodeWithSelector(IManagedSafeFactory.GUARD_CONTRACT.selector));
        if (!ok) return result;
        address expectedModule;
        (ok, expectedModule) =
            _readAddress(factory, abi.encodeWithSelector(IManagedSafeFactory.MODULE_CONTRACT.selector));
        if (!ok) return result;
        address expectedExecutionModule;
        (ok, expectedExecutionModule) =
            _readAddress(factory, abi.encodeWithSelector(IManagedSafeFactory.executionModule.selector));
        if (!ok || expectedExecutionModule == address(0)) return result;
        address actualGuard;
        (ok, actualGuard) = _safeStorageAddress(safe, GUARD_STORAGE_SLOT);
        if (!ok) return result;
        if (expectedGuard == address(0) || actualGuard != expectedGuard) {
            return SafeFactoryCheck({
                valid: false, failure: SafeFailureKind.Guard, expected: expectedGuard, actual: actualGuard
            });
        }

        bool executionModuleEnabled;
        (ok, executionModuleEnabled) =
            _readBool(safe, abi.encodeWithSelector(IManagedSafe.isModuleEnabled.selector, expectedExecutionModule));
        if (!ok) return result;
        if (!executionModuleEnabled) {
            return SafeFactoryCheck({
                valid: false, failure: SafeFailureKind.Module, expected: expectedExecutionModule, actual: address(0)
            });
        }

        if (expectedModule != address(0)) {
            bool enabled;
            (ok, enabled) =
                _readBool(safe, abi.encodeWithSelector(IManagedSafe.isModuleEnabled.selector, expectedModule));
            if (!ok) return result;
            if (enabled) {
                if (!_validateSafeExtensions(expectedModule, safe) || !_validateManagedSafe(factory, safe)) {
                    return SafeFactoryCheck({
                        valid: false, failure: SafeFailureKind.Module, expected: expectedModule, actual: expectedModule
                    });
                }
                result.valid = true;
                return result;
            }
        }

        if (!_validateManagedSafe(factory, safe)) {
            address firstModule;
            (ok, firstModule) = _firstSafeModule(safe);
            if (!ok) return result;
            return SafeFactoryCheck({
                valid: false, failure: SafeFailureKind.Module, expected: expectedExecutionModule, actual: firstModule
            });
        }
        result.valid = true;
    }

    function _staticcallWord(address target, bytes memory callData) private view returns (bool ok, uint256 word) {
        uint256 gasLimit = PROVENANCE_QUERY_GAS;
        assembly ("memory-safe") {
            let out := mload(0x40)
            mstore(out, 0)
            ok := staticcall(gasLimit, target, add(callData, 0x20), mload(callData), out, 0x20)
            if iszero(eq(returndatasize(), 0x20)) { ok := 0 }
            word := mload(out)
        }
    }

    function _readAddress(address target, bytes memory callData) private view returns (bool ok, address value) {
        uint256 word;
        (ok, word) = _staticcallWord(target, callData);
        if (!ok || word > type(uint160).max) return (false, address(0));
        assembly ("memory-safe") {
            value := word
        }
    }

    function _readBool(address target, bytes memory callData) private view returns (bool ok, bool value) {
        uint256 word;
        (ok, word) = _staticcallWord(target, callData);
        if (!ok || word > 1) return (false, false);
        value = word == 1;
    }

    function _safeStorageAddress(address safe, bytes32 slot) private view returns (bool ok, address value) {
        bytes memory callData = abi.encodeWithSelector(IManagedSafe.getStorageAt.selector, uint256(slot), 1);
        uint256 gasLimit = PROVENANCE_QUERY_GAS;
        uint256 word;
        assembly ("memory-safe") {
            let out := mload(0x40)
            mstore(out, 0)
            mstore(add(out, 0x20), 0)
            mstore(add(out, 0x40), 0)
            ok := staticcall(gasLimit, safe, add(callData, 0x20), mload(callData), out, 0x60)
            if iszero(eq(returndatasize(), 0x60)) { ok := 0 }
            if iszero(eq(mload(out), 0x20)) { ok := 0 }
            if iszero(eq(mload(add(out, 0x20)), 0x20)) { ok := 0 }
            word := mload(add(out, 0x40))
        }
        if (!ok || word > type(uint160).max) return (false, address(0));
        assembly ("memory-safe") {
            value := word
        }
    }

    /// @dev A one-entry page proves whether any module exists; no unbounded
    ///      array allocation or multi-page traversal is needed for the strict
    ///      zero-module fallback policy.
    function _firstSafeModule(address safe) private view returns (bool ok, address module) {
        bytes memory callData = abi.encodeWithSelector(IManagedSafe.getModulesPaginated.selector, SENTINEL_MODULES, 1);
        uint256 gasLimit = PROVENANCE_QUERY_GAS;
        uint256 size;
        uint256 offset;
        uint256 nextWord;
        uint256 length;
        uint256 moduleWord;
        assembly ("memory-safe") {
            let out := mload(0x40)
            mstore(out, 0)
            mstore(add(out, 0x20), 0)
            mstore(add(out, 0x40), 0)
            mstore(add(out, 0x60), 0)
            ok := staticcall(gasLimit, safe, add(callData, 0x20), mload(callData), out, 0x80)
            size := returndatasize()
            offset := mload(out)
            nextWord := mload(add(out, 0x20))
            length := mload(add(out, 0x40))
            moduleWord := mload(add(out, 0x60))
        }
        if (!ok || offset != 0x40 || nextWord > type(uint160).max) return (false, address(0));
        if (length == 0) {
            if (size != 0x60 || nextWord != SENTINEL_MODULES_WORD) return (false, address(0));
            return (true, address(0));
        }
        if (length != 1 || size != 0x80 || moduleWord == 0 || moduleWord > type(uint160).max) {
            return (false, address(0));
        }
        assembly ("memory-safe") {
            module := moduleWord
        }
        return (true, module);
    }

    function _validateSafeExtensions(address module, address safe) private view returns (bool ok) {
        if (!Delegation7702.hasContractCode(module)) return false;
        bytes memory callData =
            abi.encodeWithSelector(IManagedSafeModuleValidator.validateSafeExtensions.selector, safe);
        uint256 gasLimit = MODULE_VALIDATION_GAS;
        assembly ("memory-safe") {
            ok := staticcall(gasLimit, module, add(callData, 0x20), mload(callData), 0, 0)
            if returndatasize() { ok := 0 }
        }
    }

    function _validateManagedSafe(address factory, address safe) private view returns (bool ok) {
        bytes memory callData = abi.encodeWithSelector(IManagedSafeFactory.validateManagedSafe.selector, safe);
        uint256 gasLimit = MODULE_VALIDATION_GAS;
        assembly ("memory-safe") {
            ok := staticcall(gasLimit, factory, add(callData, 0x20), mload(callData), 0, 0)
            if returndatasize() { ok := 0 }
        }
    }
}
