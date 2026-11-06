// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "../../Delegation7702.sol";
import {AuthCredentialLink} from "../../RegistryTypes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {AuthLinksStorage} from "../../registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

struct WebAuthnCredentialView {
    bytes32 credHash;
    bytes32 qx;
    bytes32 qy;
    uint32 signCount;
    bool active;
    bool exists;
}

interface IWebAuthnAuthAccountView {
    function factory() external view returns (address);
    function registry() external view returns (address);
    function interact() external view returns (address);
    function entryPoint() external view returns (address);
    function getCredential(bytes32 credHash) external view returns (WebAuthnCredentialView memory);
}

interface IWebAuthnAuthAccountFactoryView {
    function REGISTRY() external view returns (address);
    function INTERACT() external view returns (address);
    function ENTRY_POINT() external view returns (address);
    function isAuthAccount(address account) external view returns (bool);
}

/**
 * @title RegistryAuthFacet
 * @notice Registry-side links from WebAuthn credential id keys to deployed protocol-user AuthAccounts.
 * @dev The registry does not verify WebAuthn assertions or store credential public keys. It only records
 *      lookup/indexing links to accounts attested by an admin-approved AuthAccount factory.
 */
contract RegistryAuthFacet is FacetGuard {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    uint256 public constant VERSION = 4;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    event AuthCredentialLinked(
        bytes32 indexed idKey, address indexed account, bytes32 indexed credHash, address operator
    );
    event AuthCredentialRevoked(bytes32 indexed idKey, address indexed account, address operator);
    event AuthAccountFactorySet(address indexed factory, bool allowed, address operator);

    error AuthIdKeyZero();
    error AuthAccountZero();
    error AuthAccountNotDeployed(address account);
    error AuthAccountFactoryZero();
    error AuthAccountFactoryNotDeployed(address factory);
    error AuthAccountFactoryNotAllowed(address factory);
    error AuthAccountFactoryInvalid(address factory);
    error AuthAccountFactoryRegistryMismatch(address factory, address expectedRegistry, address actualRegistry);
    error AuthAccountNotFromAllowedFactory(address account, address factory);
    error AuthAccountRegistryMismatch(address account, address expectedRegistry, address actualRegistry);
    error AuthAccountInteractMismatch(address account, address expectedInteract, address actualInteract);
    error AuthAccountEntryPointMismatch(address account, address expectedEntryPoint, address actualEntryPoint);
    error AuthCredHashZero();
    error AuthCredentialMissing(address account, bytes32 credHash);
    error AuthCredentialInactive(address account, bytes32 credHash);
    error AuthLinkMissing(bytes32 idKey);
    error AuthLinkAccountMismatch(bytes32 idKey, address existing, address requested);
    error AuthLinkCredentialMismatch(bytes32 idKey, bytes32 existing, bytes32 requested);

    /// @notice Allow or remove a WebAuthn AuthAccount factory trusted for registry auth links.
    function setAuthAccountFactory(address factory, bool allowed) external whenNotPausedD nonReentrantD {
        _requireAdminRole();
        if (factory == address(0)) revert AuthAccountFactoryZero();
        if (allowed && !Delegation7702.hasContractCode(factory)) revert AuthAccountFactoryNotDeployed(factory);
        if (allowed) _requireFactoryRegistry(factory);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryAuth(),
                scope: bytes32(uint256(uint160(factory))),
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setAuthAccountFactory.selector, factory, allowed)
        );
        if (!executing) {
            return;
        }

        if (allowed) _requireFactoryRegistry(factory);
        AuthLinksStorage.getLayout().authAccountFactories[factory] = allowed;
        // Auth-link changes hold nonReentrantD; factory and credential checks use STATICCALL before the local write
        // and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit AuthAccountFactorySet(factory, allowed, _msgSenderD());
    }

    /// @notice Return whether a factory is currently trusted for AuthAccount links.
    function isAuthAccountFactoryAllowed(address factory) external view returns (bool) {
        return AuthLinksStorage.getLayout().authAccountFactories[factory];
    }

    /// @notice Link a WebAuthn credential id key to a deployed AuthAccount.
    /// @dev Existing links may only be reactivated for the same account and credential hash.
    ///      Credential public keys and verifier policy must already be installed in the AuthAccount.
    function linkAuthCredential(bytes32 idKey, address account, bytes32 credHash)
        external
        whenNotPausedD
        nonReentrantD
    {
        _requireAuthManagerRole();
        _validateLinkInput(idKey, account, credHash);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryAuth(), scope: idKey, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.linkAuthCredential.selector, idKey, account, credHash)
        );
        if (!executing) {
            return;
        }

        _validateLinkInput(idKey, account, credHash);
        AuthLinksStorage.Layout storage L = AuthLinksStorage.getLayout();
        AuthCredentialLink storage link = L.links[idKey];
        if (link.account != address(0) && link.account != account) {
            revert AuthLinkAccountMismatch(idKey, link.account, account);
        }
        if (link.credHash != bytes32(0) && link.credHash != credHash) {
            revert AuthLinkCredentialMismatch(idKey, link.credHash, credHash);
        }

        link.account = account;
        link.credHash = credHash;
        link.active = true;
        L.accountAuthIds[account].add(idKey);

        // Auth-link changes hold nonReentrantD; factory and credential checks use STATICCALL before the local write
        // and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit AuthCredentialLinked(idKey, account, credHash, _msgSenderD());
    }

    /// @notice Revoke a registry-side credential link without modifying the AuthAccount credential store.
    function revokeAuthCredential(bytes32 idKey) external whenNotPausedD nonReentrantD {
        _requireAuthManagerRole();
        if (idKey == bytes32(0)) revert AuthIdKeyZero();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryAuth(), scope: idKey, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.revokeAuthCredential.selector, idKey)
        );
        if (!executing) {
            return;
        }

        AuthCredentialLink storage link = AuthLinksStorage.getLayout().links[idKey];
        address account = link.account;
        if (account == address(0)) revert AuthLinkMissing(idKey);
        link.active = false;

        // Auth-link changes hold nonReentrantD; factory and credential checks use STATICCALL before the local write
        // and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit AuthCredentialRevoked(idKey, account, _msgSenderD());
    }

    /// @notice Return the linked account only when the link is active.
    function getAuthAccount(bytes32 idKey) external view returns (address account) {
        AuthCredentialLink storage link = AuthLinksStorage.getLayout().links[idKey];
        if (link.active) {
            account = link.account;
        }
    }

    /// @notice Fetch the full registry-side credential link.
    function getAuthCredentialLink(bytes32 idKey)
        external
        view
        returns (address account, bytes32 credHash, bool active)
    {
        AuthCredentialLink storage link = AuthLinksStorage.getLayout().links[idKey];
        return (link.account, link.credHash, link.active);
    }

    /// @notice Return the number of idKeys ever linked to `account`.
    function getAuthCredentialCount(address account) external view returns (uint256) {
        return AuthLinksStorage.getLayout().accountAuthIds[account].length();
    }

    /// @notice Return one idKey linked to `account` by index.
    function getAuthCredentialAt(address account, uint256 index) external view returns (bytes32) {
        return AuthLinksStorage.getLayout().accountAuthIds[account].at(index);
    }

    /// @notice Return a page of idKeys linked to `account`.
    function getAuthCredentialPage(address account, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory out)
    {
        AuthLinksStorage.Layout storage L = AuthLinksStorage.getLayout();
        uint256 len = L.accountAuthIds[account].length();
        if (start >= len || count == 0) {
            return new bytes32[](0);
        }
        uint256 remaining = len - start;
        uint256 pageSize = count < remaining ? count : remaining;
        out = new bytes32[](pageSize);
        for (uint256 i; i < out.length; i++) {
            out[i] = L.accountAuthIds[account].at(start + i);
        }
    }

    function _validateLinkInput(bytes32 idKey, address account, bytes32 credHash) private view {
        if (idKey == bytes32(0)) revert AuthIdKeyZero();
        if (account == address(0)) revert AuthAccountZero();
        if (!Delegation7702.hasContractCode(account)) revert AuthAccountNotDeployed(account);
        if (credHash == bytes32(0)) revert AuthCredHashZero();
        _requireAuthAccountFromAllowedFactory(account, credHash);
    }

    function _requireAuthAccountFromAllowedFactory(address account, bytes32 credHash) private view {
        address factory = address(0);
        try IWebAuthnAuthAccountView(account).factory() returns (address factory_) {
            factory = factory_;
        } catch {
            revert AuthAccountNotFromAllowedFactory(account, address(0));
        }
        if (!AuthLinksStorage.getLayout().authAccountFactories[factory]) {
            revert AuthAccountFactoryNotAllowed(factory);
        }
        _requireFactoryAndAccountTenant(factory, account);
        bool isAuthAccount = false;
        try IWebAuthnAuthAccountFactoryView(factory).isAuthAccount(account) returns (bool isAuthAccount_) {
            isAuthAccount = isAuthAccount_;
        } catch {
            revert AuthAccountNotFromAllowedFactory(account, factory);
        }
        if (!isAuthAccount) {
            revert AuthAccountNotFromAllowedFactory(account, factory);
        }
        _requireActiveCredential(account, factory, credHash);
    }

    function _requireFactoryAndAccountTenant(address factory, address account) private view {
        address expectedRegistry = _requireFactoryRegistry(factory);
        address actualRegistry = _accountRegistry(account, factory);
        if (actualRegistry != expectedRegistry) {
            revert AuthAccountRegistryMismatch(account, expectedRegistry, actualRegistry);
        }

        address expectedInteract = _factoryInteract(factory);
        address actualInteract = _accountInteract(account, factory);
        if (actualInteract != expectedInteract) {
            revert AuthAccountInteractMismatch(account, expectedInteract, actualInteract);
        }

        address expectedEntryPoint = _factoryEntryPoint(factory);
        address actualEntryPoint = _accountEntryPoint(account, factory);
        if (actualEntryPoint != expectedEntryPoint) {
            revert AuthAccountEntryPointMismatch(account, expectedEntryPoint, actualEntryPoint);
        }
    }

    function _requireActiveCredential(address account, address factory, bytes32 credHash) private view {
        WebAuthnCredentialView memory credential;
        try IWebAuthnAuthAccountView(account).getCredential(credHash) returns (WebAuthnCredentialView memory value) {
            credential = value;
        } catch {
            revert AuthAccountNotFromAllowedFactory(account, factory);
        }
        if (!credential.exists) revert AuthCredentialMissing(account, credHash);
        if (!credential.active) revert AuthCredentialInactive(account, credHash);
    }

    function _requireFactoryRegistry(address factory) private view returns (address registry_) {
        try IWebAuthnAuthAccountFactoryView(factory).REGISTRY() returns (address value) {
            registry_ = value;
        } catch {
            revert AuthAccountFactoryInvalid(factory);
        }
        if (registry_ != address(this)) {
            revert AuthAccountFactoryRegistryMismatch(factory, address(this), registry_);
        }
    }

    function _factoryInteract(address factory) private view returns (address interact_) {
        try IWebAuthnAuthAccountFactoryView(factory).INTERACT() returns (address value) {
            return value;
        } catch {
            revert AuthAccountFactoryInvalid(factory);
        }
    }

    function _factoryEntryPoint(address factory) private view returns (address entryPoint_) {
        try IWebAuthnAuthAccountFactoryView(factory).ENTRY_POINT() returns (address value) {
            return value;
        } catch {
            revert AuthAccountFactoryInvalid(factory);
        }
    }

    function _accountRegistry(address account, address factory) private view returns (address registry_) {
        try IWebAuthnAuthAccountView(account).registry() returns (address value) {
            return value;
        } catch {
            revert AuthAccountNotFromAllowedFactory(account, factory);
        }
    }

    function _accountInteract(address account, address factory) private view returns (address interact_) {
        try IWebAuthnAuthAccountView(account).interact() returns (address value) {
            return value;
        } catch {
            revert AuthAccountNotFromAllowedFactory(account, factory);
        }
    }

    function _accountEntryPoint(address account, address factory) private view returns (address entryPoint_) {
        try IWebAuthnAuthAccountView(account).entryPoint() returns (address value) {
            return value;
        } catch {
            revert AuthAccountNotFromAllowedFactory(account, factory);
        }
    }

    function _requireAuthManagerRole() private view {
        address actor = _msgSenderD();
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) {
            return;
        }
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.AUTH_MANAGER)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, ADMIN_ROLE);
    }

    function _requireAdminRole() private view {
        address actor = _msgSenderD();
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, ADMIN_ROLE);
    }
}
