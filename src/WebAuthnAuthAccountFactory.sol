// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IEntryPointStake} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {ChainwallUUPSUpgradeable} from "./ChainwallUpgradeable.sol";
import {PagedIndex} from "./PagedIndex.sol";
import {WebAuthnAuthAccount} from "./WebAuthnAuthAccount.sol";
import {WebAuthnAuthAccountProxy} from "./WebAuthnAuthAccountProxy.sol";
import {WebAuthnEntryPoint} from "./WebAuthnEntryPoint.sol";
import {CapabilityIds} from "./registry/Capabilities.sol";

interface IWebAuthnAuthFactoryRegistry {
    function hasRole(bytes32 role, address account) external view returns (bool);
    function hasCapability(bytes32 capability, address actor) external view returns (bool);
}

interface IWebAuthnEntryPointV08 {
    function senderCreator() external view returns (address);
}

interface IWebAuthnFactoryAccount {
    function chainwallFactory() external view returns (address);
    function chainwallImplementation() external view returns (address);
    function chainwallImplementationCodehash() external view returns (bytes32);
    function factory() external view returns (address);
    function registry() external view returns (address);
    function interact() external view returns (address);
    function entryPoint() external view returns (address);
}

/// @title WebAuthnAuthAccountFactory
/// @notice Deploys deterministic WebAuthn protocol-user accounts for one tenant registry.
/// @dev Account addresses bind both the caller-supplied account salt and the complete initial account authority.
///      An authorized factory caller can deploy an exact account on the user's behalf, but cannot consume the
///      expected address with a different credential key or initial execution scope.
contract WebAuthnAuthAccountFactory is Initializable, ChainwallUUPSUpgradeable {
    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.WebAuthnAuthAccountFactory");
    using PagedIndex for PagedIndex.Index;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant AUTH_ACCOUNT_SALT_TYPEHASH = keccak256(
        "ChainwallWebAuthnAuthAccountDeployment(address registry,bytes32 accountSalt,bytes32 initialCredHash,bytes32 initialQx,bytes32 initialQy,bytes32 initialScopesHash)"
    );
    bytes32 private constant _EMPTY_SCOPES_HASH = 0x569e75fc77c1a856f6daaf9e69d8a9566ca34aa47f9133711ce065a571af0cfd;
    bytes32 private constant _ACCOUNT_PROXY_IMPLEMENTATION_SALT = keccak256("Chainwall.WebAuthnAuthAccountProxy.v1");

    address private _implementation;
    address private _registry;
    address private _interact;
    address private _entryPoint;
    bytes32 private _rpIdHash;
    bool private _requireUserVerification;

    string private _origin;
    PagedIndex.Index private _authAccounts;
    address private _entryPointSenderCreator;
    // Tenant SafeFactory predicted during stage 1 and deployed during stage 2.
    address private _safeFactory;
    mapping(address => bytes32) private _approvedAuthAccountImplementationCodehash;
    // Accounts are EIP-1167 clones of this immutable Registry upgrade dispatcher.
    address private _accountProxyImplementation;

    event AuthAccountDeployed(
        address indexed account,
        bytes32 indexed accountSalt,
        bytes32 indexed initialCredHash,
        address implementation,
        bytes32 implementationCodehash
    );
    event AuthAccountImplementationChanged(
        address indexed previousImplementation, address indexed newImplementation, bytes32 newImplementationCodehash
    );

    error RegistryZero();
    error InteractZero();
    error RegistryInteractSame();
    error RegistryNotContract(address registry);
    error EntryPointZero();
    error SafeFactoryZero();
    error ImplementationZero();
    error ImplementationNotContract(address implementation);
    error RpIdHashZero();
    error OriginEmpty();
    error UserVerificationRequired();
    error NotAuthManager(address actor);
    error NotStakeManager(address actor);
    error OnlyEntryPointSenderCreator(address actor);
    error EntryPointSenderCreatorZero();
    error AuthAccountAddressOccupied(address account);
    error AuthAccountImplementationMismatch(address expected, address actual);
    error AuthAccountImplementationCodehashMismatch(address implementation, bytes32 expected, bytes32 actual);
    error AuthAccountImplementationComponentInvalid(address implementation, bytes32 componentId);
    error AuthAccountImplementationProtocolInvalid(address implementation, uint256 protocolVersion);
    error StakeRecipientZero();
    error OnlyRegistry();

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address registry_,
        address interact_,
        address safeFactory_,
        address entryPoint_,
        address implementation_,
        bytes32 rpIdHash_,
        string memory origin_,
        bool requireUv_
    ) external initializer {
        if (registry_ == address(0)) revert RegistryZero();
        if (interact_ == address(0)) revert InteractZero();
        if (safeFactory_ == address(0)) revert SafeFactoryZero();
        if (entryPoint_ == address(0)) revert EntryPointZero();
        WebAuthnEntryPoint.requireCanonical(entryPoint_);
        if (implementation_ == address(0)) revert ImplementationZero();
        if (registry_ == interact_) revert RegistryInteractSame();
        if (!Delegation7702.hasContractCode(registry_)) revert RegistryNotContract(registry_);
        bytes32 implementationCodehash = _requireAuthAccountImplementation(implementation_);
        if (rpIdHash_ == bytes32(0)) revert RpIdHashZero();
        if (bytes(origin_).length == 0) revert OriginEmpty();
        if (!requireUv_) revert UserVerificationRequired();
        _registry = registry_;
        _interact = interact_;
        _safeFactory = safeFactory_;
        _entryPoint = entryPoint_;
        _rpIdHash = rpIdHash_;
        _origin = origin_;
        _requireUserVerification = requireUv_;
        _implementation = implementation_;
        _approvedAuthAccountImplementationCodehash[implementation_] = implementationCodehash;
        _accountProxyImplementation = address(new WebAuthnAuthAccountProxy{salt: _ACCOUNT_PROXY_IMPLEMENTATION_SALT}());
        _entryPointSenderCreator = IWebAuthnEntryPointV08(entryPoint_).senderCreator();
        if (_entryPointSenderCreator == address(0)) revert EntryPointSenderCreatorZero();
        __UUPSUpgradeable_init();
    }

    function IMPLEMENTATION() external view returns (address) {
        return _implementation;
    }

    /// @notice Immutable dispatcher cloned by every account created by this tenant factory.
    function ACCOUNT_PROXY_IMPLEMENTATION() external view returns (address) {
        return _accountProxyImplementation;
    }

    function chainwallComponentId() external pure override returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    function chainwallAuthAccountImplementation() external view returns (address) {
        return _implementation;
    }

    /// @notice Code hash pinned for the implementation selected for future accounts.
    /// @dev Release transitions must reject implementation code drift rather than
    ///      recording the code found at the address after approval.
    function CHAINWALL_AUTH_ACCOUNT_IMPLEMENTATION_CODEHASH() external view returns (bytes32) {
        return _approvedAuthAccountImplementationCodehash[_implementation];
    }

    /// @notice Select the implementation loaded by newly deployed stable account proxies.
    /// @dev Existing accounts retain their own implementation pointer and remain recognized by provenance checks.
    // _requireAuthAccountImplementation rejects empty code before updating the implementation.
    // forge-lint: disable-next-line(missing-zero-check)
    function setChainwallAuthAccountImplementation(address newImplementation) external {
        if (msg.sender != _registry) revert OnlyRegistry();
        bytes32 codehash_ = _requireAuthAccountImplementation(newImplementation);
        address previous = _implementation;
        bytes32 expectedPreviousCodehash = _approvedAuthAccountImplementationCodehash[previous];
        bytes32 actualPreviousCodehash = previous.codehash;
        if (expectedPreviousCodehash == bytes32(0) || actualPreviousCodehash != expectedPreviousCodehash) {
            revert AuthAccountImplementationCodehashMismatch(previous, expectedPreviousCodehash, actualPreviousCodehash);
        }
        _approvedAuthAccountImplementationCodehash[newImplementation] = codehash_;
        _implementation = newImplementation;
        emit AuthAccountImplementationChanged(previous, newImplementation, codehash_);
    }

    function isAuthAccountImplementationApproved(address implementation) external view returns (bool) {
        bytes32 expected = _approvedAuthAccountImplementationCodehash[implementation];
        return expected != bytes32(0) && implementation.codehash == expected;
    }

    function REGISTRY() external view returns (address) {
        return _registry;
    }

    function INTERACT() external view returns (address) {
        return _interact;
    }

    function ENTRY_POINT() external view returns (address) {
        return _entryPoint;
    }

    /// @notice Tenant SafeFactory that owns the only OKModule accepted by AuthAccounts.
    /// @dev Stage 1 stores the already-predicted address before stage 2 deploys its code.
    function SAFE_FACTORY() external view returns (address) {
        return _safeFactory;
    }

    function ENTRY_POINT_SENDER_CREATOR() external view returns (address) {
        return _entryPointSenderCreator;
    }

    function RP_ID_HASH() external view returns (bytes32) {
        return _rpIdHash;
    }

    function REQUIRE_USER_VERIFICATION() external view returns (bool) {
        return _requireUserVerification;
    }

    function origin() external view returns (string memory) {
        return _origin;
    }

    /// @notice Stake this factory in its canonical EntryPoint.
    /// @dev Counterfactual deployment reads this proxy's implementation and tenant
    ///      configuration slots. ERC-7562 permits a factory to read its own storage
    ///      during validation only while it is staked. Governance must fund enough
    ///      stake for the target chain's bundlers before submitting undeployed users.
    function addEntryPointStake(uint32 unstakeDelaySec) external payable {
        _requireStakeManager();
        // Only a Registry stake manager can send this call msg.value to the canonical EntryPoint fixed at
        // initialization.
        // forge-lint: disable-next-line(arbitrary-send-eth)
        IEntryPointStake(_entryPoint).addStake{value: msg.value}(unstakeDelaySec);
    }

    /// @notice Start the canonical EntryPoint's delayed factory-stake withdrawal.
    function unlockEntryPointStake() external {
        _requireStakeManager();
        IEntryPointStake(_entryPoint).unlockStake();
    }

    /// @notice Withdraw an unlocked factory stake after the EntryPoint delay.
    function withdrawEntryPointStake(address payable recipient) external {
        _requireStakeManager();
        if (recipient == address(0)) revert StakeRecipientZero();
        IEntryPointStake(_entryPoint).withdrawStake(recipient);
    }

    /// @notice Upgrade entry point reserved for the tenant registry timelock.
    function timelockUpgrade(address newImplementation, bytes calldata data) external {
        if (msg.sender != _registry) revert OnlyRegistry();
        _performUpgrade(newImplementation, data);
    }

    /// @notice Disabled default UUPS entrypoint.
    function upgradeToAndCall(address, bytes memory) public payable override {
        revert("WebAuthnAuthAccountFactory: use timelockUpgrade");
    }

    function _performUpgrade(address newImplementation, bytes calldata data) internal {
        require(newImplementation != address(0), "upgrade:impl=0");
        _upgradePreservingBindings(newImplementation, data);
    }

    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != _registry) revert OnlyRegistry();
    }

    /// @dev Factory code upgrades preserve the tenant, EntryPoint, WebAuthn domain, stable dispatcher, and future
    ///      account implementation default. Defaults change only through the separately reviewed release action.
    function _chainwallSecurityBindingsHash() internal view override returns (bytes32) {
        return _hashSecurityBindings(
            abi.encode(
                _implementation,
                _approvedAuthAccountImplementationCodehash[_implementation],
                _registry,
                _interact,
                _entryPoint,
                _entryPointSenderCreator,
                _safeFactory,
                _rpIdHash,
                _requireUserVerification,
                keccak256(bytes(_origin)),
                _accountProxyImplementation
            )
        );
    }

    function newAuthAccount(
        bytes32 accountSalt,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        address expectedImplementation,
        bytes32 expectedImplementationCodehash,
        WebAuthnAuthAccount.DirectExecuteScope[] calldata initialScopes
    ) external returns (address account) {
        _requireAuthManager();
        account = _createAuthAccount(
            accountSalt,
            initialCredHash,
            initialQx,
            initialQy,
            expectedImplementation,
            expectedImplementationCodehash,
            initialScopes
        );
    }

    /// @notice Deploy an account through EntryPoint v0.8 sender creation.
    /// @dev This path deliberately does not mutate the factory's global index.
    ///      EntryPoint calls SenderCreator only when the sender has no code and
    ///      verifies that this function returns the requested sender, so this path
    ///      can deploy directly while the governed path remains idempotent.
    ///      The factory must nevertheless be staked because its proxy and tenant
    ///      configuration are read during the ERC-7562 deployment frame. The account
    ///      remains discoverable from the deployment event and `isAuthAccount`; an
    ///      AUTH_MANAGER can index it later by calling `newAuthAccount` with the same
    ///      complete initializer.
    function createAuthAccount(
        bytes32 accountSalt,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        address expectedImplementation,
        bytes32 expectedImplementationCodehash
    ) external returns (address account) {
        if (msg.sender != _entryPointSenderCreator) {
            revert OnlyEntryPointSenderCreator(msg.sender);
        }
        _requireSelectedImplementation(expectedImplementation, expectedImplementationCodehash);
        bytes32 salt =
            _deploymentSaltFromScopesHash(accountSalt, initialCredHash, initialQx, initialQy, _EMPTY_SCOPES_HASH);
        account = Clones.predictDeterministicAddress(_accountProxyImplementation, salt, address(this));
        if (account.code.length != 0) revert AuthAccountAddressOccupied(account);
        account = Clones.cloneDeterministic(_accountProxyImplementation, salt);
        WebAuthnAuthAccountProxy(payable(account))
            .initializeProxy(expectedImplementation, expectedImplementationCodehash);
        _requireAccountImplementation(account, expectedImplementation, expectedImplementationCodehash);
        WebAuthnAuthAccount.DirectExecuteScope[] memory noScopes = new WebAuthnAuthAccount.DirectExecuteScope[](0);
        _initializeAuthAccount(account, initialCredHash, initialQx, initialQy, noScopes);
        // CREATE2 fixes the account before initialization; the selected implementation and tenant bindings are
        // checked before this deployment event.
        // forge-lint: disable-start(reentrancy-events)
        emit AuthAccountDeployed(
            account, accountSalt, initialCredHash, expectedImplementation, expectedImplementationCodehash
        );
        // forge-lint: disable-end(reentrancy-events)
    }

    function isAuthAccount(address account) public view returns (bool) {
        return _authAccounts.contains(_addressKey(account)) || _isCanonicalAuthAccount(account);
    }

    function getAuthAccountCount() external view returns (uint256) {
        return _authAccounts.length();
    }

    function getAuthAccountAt(uint256 index) external view returns (address) {
        return _addressFromKey(_authAccounts.valueAt(index));
    }

    function getAuthAccountPage(uint256 start, uint256 count) external view returns (address[] memory out) {
        bytes32[] memory values = _authAccounts.page(start, count);
        out = new address[](values.length);
        for (uint256 i = 0; i < values.length;) {
            out[i] = _addressFromKey(values[i]);
            unchecked {
                ++i;
            }
        }
    }

    function getAuthAccountIndexNextId() external view returns (uint256) {
        return _authAccounts.nextId();
    }

    function getAuthAccountIndexCurrentEpoch() external view returns (uint64) {
        return _authAccounts.currentEpoch;
    }

    function getAuthAccountIndexAlivePage(uint256 pageIndex) external view returns (uint256) {
        return _authAccounts.alivePage(pageIndex);
    }

    function getAuthAccountIndexValues(uint256[] calldata ids) external view returns (address[] memory out) {
        bytes32[] memory values = _authAccounts.getValues(ids);
        out = new address[](values.length);
        for (uint256 i = 0; i < values.length;) {
            out[i] = _addressFromKey(values[i]);
            unchecked {
                ++i;
            }
        }
    }

    function getAuthAccountIndexEpochPageCount(uint64 epoch) external view returns (uint256) {
        return _authAccounts.epochPageCount(epoch);
    }

    function getAuthAccountIndexEpochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return _authAccounts.epochPageAt(epoch, i);
    }

    function getAuthAccountIndexJournal(uint64 epoch, uint128 pageIndex)
        external
        view
        returns (uint256 updates, uint256 deletes)
    {
        return _authAccounts.journal(epoch, pageIndex);
    }

    function computeAuthAccountAddress(
        bytes32 accountSalt,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        WebAuthnAuthAccount.DirectExecuteScope[] calldata initialScopes
    ) external view returns (address) {
        return Clones.predictDeterministicAddress(
            _accountProxyImplementation,
            _deploymentSalt(accountSalt, initialCredHash, initialQx, initialQy, initialScopes),
            address(this)
        );
    }

    function deploymentSalt(
        bytes32 accountSalt,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        WebAuthnAuthAccount.DirectExecuteScope[] calldata initialScopes
    ) external view returns (bytes32) {
        return _deploymentSalt(accountSalt, initialCredHash, initialQx, initialQy, initialScopes);
    }

    function _deploymentSalt(
        bytes32 accountSalt,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        WebAuthnAuthAccount.DirectExecuteScope[] calldata initialScopes
    ) private view returns (bytes32) {
        // Account identity is intentionally chain-independent, while the complete
        // initial authority is address-bound. This prevents another AUTH_MANAGER
        // from consuming a predicted address with attacker-selected credentials.
        bytes32 initialScopesHash = _hashEncoded(abi.encode(initialScopes));
        return _deploymentSaltFromScopesHash(accountSalt, initialCredHash, initialQx, initialQy, initialScopesHash);
    }

    function _deploymentSaltFromScopesHash(
        bytes32 accountSalt,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        bytes32 initialScopesHash
    ) private view returns (bytes32) {
        return _hashEncoded(
            abi.encode(
                AUTH_ACCOUNT_SALT_TYPEHASH,
                _registry,
                accountSalt,
                initialCredHash,
                initialQx,
                initialQy,
                initialScopesHash
            )
        );
    }

    function _createAuthAccount(
        bytes32 accountSalt,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        address expectedImplementation,
        bytes32 expectedImplementationCodehash,
        WebAuthnAuthAccount.DirectExecuteScope[] calldata initialScopes
    ) private returns (address account) {
        bytes32 salt = _deploymentSalt(accountSalt, initialCredHash, initialQx, initialQy, initialScopes);
        account = Clones.predictDeterministicAddress(_accountProxyImplementation, salt, address(this));
        if (account.code.length == 0) {
            _requireSelectedImplementation(expectedImplementation, expectedImplementationCodehash);
            account = Clones.cloneDeterministic(_accountProxyImplementation, salt);
            WebAuthnAuthAccountProxy(payable(account))
                .initializeProxy(expectedImplementation, expectedImplementationCodehash);
            _requireAccountImplementation(account, expectedImplementation, expectedImplementationCodehash);
            _initializeAuthAccount(account, initialCredHash, initialQx, initialQy, initialScopes);
            // CREATE2 fixes the account before initialization; the selected implementation and tenant bindings are
            // checked before this deployment event.
            // forge-lint: disable-start(reentrancy-events)
            emit AuthAccountDeployed(
                account, accountSalt, initialCredHash, expectedImplementation, expectedImplementationCodehash
            );
            // forge-lint: disable-end(reentrancy-events)
        } else if (!_isCanonicalAuthAccount(account)) {
            revert AuthAccountAddressOccupied(account);
        } else {
            _requireAccountImplementation(account, expectedImplementation, expectedImplementationCodehash);
        }

        bytes32 accountKey = _addressKey(account);
        if (!_authAccounts.contains(accountKey)) _authAccounts.insert(accountKey);
    }

    function _initializeAuthAccount(
        address account,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        WebAuthnAuthAccount.DirectExecuteScope[] memory initialScopes
    ) private {
        // initialize rejects UV=false, so avoid a cold config SLOAD in the
        // ERC-4337 counterfactual deployment budget.
        WebAuthnAuthAccount(payable(account))
            .initialize(
                _registry,
                _interact,
                _entryPoint,
                _rpIdHash,
                _origin,
                true,
                initialCredHash,
                initialQx,
                initialQy,
                initialScopes
            );
    }

    function _isCanonicalAuthAccount(address account) private view returns (bool) {
        if (account.codehash != _authAccountRuntimeCodehash()) return false;
        IWebAuthnFactoryAccount account_ = IWebAuthnFactoryAccount(account);
        try account_.chainwallFactory() returns (address value) {
            if (value != address(this)) return false;
        } catch {
            return false;
        }
        address accountImplementation = address(0);
        try account_.chainwallImplementation() returns (address value) {
            accountImplementation = value;
        } catch {
            return false;
        }
        bytes32 expectedImplementationCodehash = _approvedAuthAccountImplementationCodehash[accountImplementation];
        if (expectedImplementationCodehash == bytes32(0)) return false;
        try account_.chainwallImplementationCodehash() returns (bytes32 value) {
            if (value != expectedImplementationCodehash || accountImplementation.codehash != value) return false;
        } catch {
            return false;
        }
        try account_.factory() returns (address value) {
            if (value != address(this)) return false;
        } catch {
            return false;
        }
        try account_.registry() returns (address value) {
            if (value != _registry) return false;
        } catch {
            return false;
        }
        try account_.interact() returns (address value) {
            if (value != _interact) return false;
        } catch {
            return false;
        }
        try account_.entryPoint() returns (address value) {
            return value == _entryPoint;
        } catch {
            return false;
        }
    }

    function _authAccountRuntimeCodehash() private view returns (bytes32) {
        address implementation = _accountProxyImplementation;
        return
            keccak256(abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3"));
    }

    function _requireSelectedImplementation(address expectedImplementation, bytes32 expectedCodehash) private view {
        address selected = _implementation;
        if (selected != expectedImplementation) {
            revert AuthAccountImplementationMismatch(expectedImplementation, selected);
        }
        bytes32 actualCodehash = selected.codehash;
        if (actualCodehash != expectedCodehash) {
            revert AuthAccountImplementationCodehashMismatch(selected, expectedCodehash, actualCodehash);
        }
        bytes32 approvedCodehash = _approvedAuthAccountImplementationCodehash[selected];
        if (approvedCodehash == bytes32(0) || actualCodehash != approvedCodehash) {
            revert AuthAccountImplementationCodehashMismatch(selected, approvedCodehash, actualCodehash);
        }
        _requireAuthAccountImplementation(selected);
    }

    function _requireAccountImplementation(address account, address expectedImplementation, bytes32 expectedCodehash)
        private
        view
    {
        IWebAuthnFactoryAccount account_ = IWebAuthnFactoryAccount(account);
        address actualImplementation = address(0);
        try account_.chainwallImplementation() returns (address value) {
            actualImplementation = value;
        } catch {
            revert AuthAccountAddressOccupied(account);
        }
        if (actualImplementation != expectedImplementation) {
            revert AuthAccountImplementationMismatch(expectedImplementation, actualImplementation);
        }
        bytes32 actualCodehash = actualImplementation.codehash;
        if (actualCodehash != expectedCodehash) {
            revert AuthAccountImplementationCodehashMismatch(actualImplementation, expectedCodehash, actualCodehash);
        }
    }

    function _requireAuthAccountImplementation(address implementation) private view returns (bytes32 codehash_) {
        if (!Delegation7702.hasContractCode(implementation)) revert ImplementationNotContract(implementation);
        bytes32 componentId = bytes32(0);
        try WebAuthnAuthAccount(payable(implementation)).chainwallComponentId() returns (bytes32 value) {
            componentId = value;
        } catch {
            revert AuthAccountImplementationComponentInvalid(implementation, bytes32(0));
        }
        if (componentId != keccak256("Chainwall.WebAuthnAuthAccount")) {
            revert AuthAccountImplementationComponentInvalid(implementation, componentId);
        }
        uint256 protocolVersion = 0;
        try WebAuthnAuthAccount(payable(implementation)).chainwallUpgradeProtocolVersion() returns (uint256 value) {
            protocolVersion = value;
        } catch {
            revert AuthAccountImplementationProtocolInvalid(implementation, 0);
        }
        if (protocolVersion != 1) {
            revert AuthAccountImplementationProtocolInvalid(implementation, protocolVersion);
        }
        codehash_ = implementation.codehash;
    }

    function _addressKey(address account) private pure returns (bytes32) {
        return bytes32(uint256(uint160(account)));
    }

    function _addressFromKey(bytes32 key) private pure returns (address) {
        return address(uint160(uint256(key)));
    }

    function _requireAuthManager() private view {
        IWebAuthnAuthFactoryRegistry registry = IWebAuthnAuthFactoryRegistry(_registry);
        if (registry.hasRole(ADMIN_ROLE, msg.sender)) {
            return;
        }
        if (registry.hasCapability(CapabilityIds.AUTH_MANAGER, msg.sender)) {
            return;
        }
        revert NotAuthManager(msg.sender);
    }

    function _requireStakeManager() private view {
        IWebAuthnAuthFactoryRegistry registry = IWebAuthnAuthFactoryRegistry(_registry);
        if (registry.hasRole(ADMIN_ROLE, msg.sender)) {
            return;
        }
        if (registry.hasCapability(CapabilityIds.TIMELOCK_GOVERNOR, msg.sender)) {
            return;
        }
        revert NotStakeManager(msg.sender);
    }

    function _hashEncoded(bytes memory data) private pure returns (bytes32 h) {
        assembly ("memory-safe") {
            h := keccak256(add(data, 0x20), mload(data))
        }
    }
}
