// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {ChainwallInitialImplementationValidation, ChainwallUUPSUpgradeable} from "./ChainwallUpgradeable.sol";
import {Interact} from "./Interact.sol";
import {OKAccount} from "./OKAccount.sol";
import {PagedIndex} from "./PagedIndex.sol";
import {ProtocolCodehashes} from "./ProtocolCodehashes.sol";

/// @title IRegistryUsers
/// @notice Minimal user-directory view required by {AccountFactory}.
/// @dev The factory only needs to know whether the caller is an allowlisted
///      registry user before it lets them mint a native account.
interface IRegistryUsers {
    /// @notice Returns true when `user` is currently allowlisted in the tenant registry.
    function isUser(address user) external view returns (bool);
}

/// @title IRegistryAccounts
/// @notice Minimal account allowlist interface required by {AccountFactory}.
/// @dev Newly-deployed accounts are immediately registered here so later
///      account-mode execution in `Interact` can trust the target vault.
interface IRegistryAccounts {
    /// @notice Allowlist a freshly deployed account vault.
    function addAccount(address account) external;
    /// @notice Returns true when `account` is already registered.
    function isAccountAllowed(address account) external view returns (bool);
}

/// @title AccountFactory
/// @notice Deploys deterministic native `OKAccount` vaults for allowlisted users.
/// @dev Each tenant gets one factory wired to exactly one `Interact` instance,
///      one registry, and one execution engine.
///
///      A typical flow is:
///      1. Governance deploys a tenant stack through `OKFactory`.
///      2. An allowlisted user calls {newAccount} with a salt of their choice.
///      3. The factory deploys an `OKAccount` bound to that tenant's `Interact`,
///         registry, and MiniScript engine.
///      4. The factory registers the new vault in `RegistryAccountsFacet` so
///         later account-mode interaction execution can pass registry checks.
contract AccountFactory is Initializable, ReentrancyGuardUpgradeable, ChainwallUUPSUpgradeable {
    using PagedIndex for PagedIndex.Index;

    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.AccountFactory");
    bytes32 private constant _OK_ACCOUNT_COMPONENT_ID = keccak256("Chainwall.OKAccount");

    /// @notice Tenant-local `Interact` instance that accounts created here are bound to.
    Interact public interact;
    /// @notice Shared `MiniScriptEngine` used by every account deployed by this factory.
    address public engine;

    /// @notice Whether deployment history indexing is enabled for this tenant.
    bool public indexingEnabled;
    /// @notice Block number where deployment indexing started, or zero if disabled.
    uint64 public indexingStartBlock;

    /// @notice Emitted whenever a new account is deployed.
    /// @param account Address of the freshly created `OKAccount`.
    event AccountDeployed(address indexed account);
    /// @notice Emitted once when indexing is enabled during initialization.
    event IndexingEnabled(uint64 startBlock);
    /// @notice Emitted when future accounts adopt a different canonical engine.
    event EngineChanged(address indexed previousEngine, address indexed newEngine);
    /// @notice Emitted when future accounts adopt a different OKAccount implementation.
    event AccountImplementationChanged(address indexed previousImplementation, address indexed newImplementation);

    /// @notice Thrown when callers request index-backed reads while indexing is disabled.
    error IndexingDisabled();
    /// @notice Thrown when a non-user tries to deploy an account.
    error CallerNotUser();
    /// @notice Thrown when the account engine address is zero during initialization.
    error EngineZero();
    /// @notice Thrown when the account engine address has no deployed code during initialization.
    error EngineNotContract(address engine);
    /// @notice Thrown when the account engine runtime is not canonical during initialization.
    error EngineNotCanonical(address engine);
    /// @notice Thrown when the configured OKAccount implementation cannot participate in verified upgrades.
    /// @dev A component-id-only check is insufficient: it could select an implementation that deploys successfully
    ///      but permanently removes the Registry-governed upgrade path from every new account.
    error AccountImplementationInvalid(address implementation);
    /// @notice Thrown when an upgrade is attempted outside the bound tenant Registry.
    error OnlyRegistry();
    /// @notice Thrown when Registry admission was queued instead of becoming effective atomically.
    error AccountRegistryAdmissionPending(address account);

    /// @notice Lightweight deployment record returned by index-backed views.
    struct AccountDeployment {
        /// @notice Address of the deployed account.
        address account;
        /// @notice Block number when the account was first recorded.
        uint64 blockNumber;
        /// @notice Timestamp when the account was first recorded.
        uint64 timestamp;
    }

    PagedIndex.Index private _accounts;
    mapping(address => AccountDeployment) private _accountRecords;
    mapping(address => bool) private _factoryAccounts;
    /// @notice Release-default implementation used for accounts created after initialization.
    address public accountImplementation;
    /// @notice Runtime codehash approved for the current future-account implementation.
    bytes32 public accountImplementationCodehash;

    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the tenant-local account factory.
    /// @param interact_ `Interact` instance that newly deployed accounts will trust.
    /// @param engine_ Shared `MiniScriptEngine` implementation used through delegatecall.
    /// @param indexingEnabled_ Whether deployment history should be indexed on-chain.
    // Engine and implementation are validated by _requireCanonicalEngine and _requireAccountImplementation before storage writes.
    // forge-lint: disable-next-line(missing-zero-check)
    function initialize(Interact interact_, address engine_, address accountImplementation_, bool indexingEnabled_)
        external
        initializer
    {
        _requireCanonicalEngine(engine_);
        bytes32 implementationCodehash = _requireAccountImplementation(accountImplementation_);
        __ReentrancyGuard_init();
        interact = interact_;
        engine = engine_;
        accountImplementation = accountImplementation_;
        accountImplementationCodehash = implementationCodehash;
        indexingEnabled = indexingEnabled_;
        indexingStartBlock = indexingEnabled_ ? SafeCast.toUint64(block.number) : 0;
        if (indexingEnabled_) {
            // Initialization is one-shot and account creation holds nonReentrant through recording; dependency
            // introspection uses STATICCALL.
            // forge-lint: disable-next-line(reentrancy-events)
            emit IndexingEnabled(indexingStartBlock);
        }
        __UUPSUpgradeable_init();
    }

    /// @notice Stable logical type used by Registry upgrade verification.
    function chainwallComponentId() external pure override returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @notice Upgrade entry point reserved for the tenant Registry timelock.
    function timelockUpgrade(address newImplementation, bytes calldata data) external {
        if (msg.sender != address(interact.registry())) revert OnlyRegistry();
        _upgradePreservingBindings(newImplementation, data);
    }

    /// @notice Disable the ordinary UUPS surface so callers must use {timelockUpgrade}.
    function upgradeToAndCall(address, bytes memory) public payable override {
        revert("AccountFactory: use timelockUpgrade");
    }

    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != address(interact.registry())) revert OnlyRegistry();
    }

    /// @dev Existing factory identity is authorized as ACCOUNT_MANAGER, so its tenant Interact and the defaults
    ///      inherited by future accounts must change only through explicit Registry release actions.
    function _chainwallSecurityBindingsHash() internal view override returns (bytes32) {
        return _hashSecurityBindings(
            abi.encode(address(interact), engine, accountImplementation, accountImplementationCodehash)
        );
    }

    /// @notice Return the engine used for newly deployed accounts.
    function chainwallEngine() external view returns (address) {
        return engine;
    }

    /// @notice Change only the engine default for accounts deployed after this action.
    // _requireCanonicalEngine rejects zero, missing code, and noncanonical runtimes before assignment.
    // forge-lint: disable-next-line(missing-zero-check)
    function setChainwallEngine(address newEngine) external {
        if (msg.sender != address(interact.registry())) revert OnlyRegistry();
        _requireCanonicalEngine(newEngine);
        address previous = engine;
        engine = newEngine;
        emit EngineChanged(previous, newEngine);
    }

    /// @notice Return the OKAccount implementation used by future deployments.
    function chainwallAccountImplementation() external view returns (address) {
        return accountImplementation;
    }

    /// @notice Change only the implementation default for accounts deployed after this action.
    /// @dev Existing account proxies retain their independently governed implementation.
    // _requireAccountImplementation uses inspect, which rejects code.length == 0, including the zero address.
    // forge-lint: disable-next-line(missing-zero-check)
    function setChainwallAccountImplementation(address newImplementation) external {
        if (msg.sender != address(interact.registry())) revert OnlyRegistry();
        bytes32 implementationCodehash = _requireAccountImplementation(newImplementation);
        address previous = accountImplementation;
        accountImplementation = newImplementation;
        accountImplementationCodehash = implementationCodehash;
        emit AccountImplementationChanged(previous, newImplementation);
    }

    function _requireCanonicalEngine(address engine_) private view {
        if (engine_ == address(0)) revert EngineZero();
        if (engine_.code.length == 0) revert EngineNotContract(engine_);
        if (!ProtocolCodehashes.isAcceptedMiniScriptDeployment(engine_)) {
            revert EngineNotCanonical(engine_);
        }
    }

    function _requireAccountImplementation(address implementation) private view returns (bytes32 codehash_) {
        (ChainwallInitialImplementationValidation.Issue issue, bytes32 inspectedCodehash) =
            ChainwallInitialImplementationValidation.inspect(implementation, _OK_ACCOUNT_COMPONENT_ID, true);
        if (issue != ChainwallInitialImplementationValidation.Issue.None) {
            revert AccountImplementationInvalid(implementation);
        }
        codehash_ = inspectedCodehash;
    }

    function _requireSelectedAccountImplementation() private view returns (address implementation) {
        implementation = accountImplementation;
        bytes32 actualCodehash = _requireAccountImplementation(implementation);
        if (actualCodehash != accountImplementationCodehash) {
            revert AccountImplementationInvalid(implementation);
        }
    }

    /// @notice Returns true when this factory deployed and recorded `account`.
    /// @dev Registry allowlisting uses this provenance check before trusting an
    ///      account's immutable tenant bindings.
    function isAccount(address account) external view returns (bool) {
        return _factoryAccounts[account];
    }

    /// @notice Deploy a new native account for the calling allowlisted user.
    /// @dev The account address is deterministic with respect to `salt` and the
    ///      tenant bindings. The account is also registered in the tenant
    ///      registry before the function returns.
    /// @param salt CREATE2 salt chosen by the user.
    /// @return account Address of the deployed `OKAccount`.
    function newAccount(bytes32 salt) external nonReentrant returns (address account) {
        _requireUser();
        address registry = address(interact.registry());
        address implementation = _requireSelectedAccountImplementation();
        bytes memory initData = abi.encodeCall(OKAccount.initialize, (address(interact), registry, engine));
        account = address(new ERC1967Proxy{salt: salt}(implementation, initData));
        _recordAccount(account);
        // Initialization is one-shot and account creation holds nonReentrant through recording; dependency
        // introspection uses STATICCALL.
        // forge-lint: disable-next-line(reentrancy-events)
        emit AccountDeployed(account);
    }

    /// @notice Predict the address that {newAccount} would deploy for `salt`.
    /// @dev This mirrors the exact CREATE2 formula used by the factory. The address is chain-independent when this
    ///      factory, its bound Interact/registry/engine addresses, the OKAccount creation bytecode, and `salt` are
    ///      identical on every target chain.
    /// @param salt CREATE2 salt that would be supplied to {newAccount}.
    /// @return Predicted account address.
    function computeAccountAddress(bytes32 salt) external view returns (address) {
        address implementation = _requireSelectedAccountImplementation();
        bytes memory initCode = bytes.concat(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                implementation,
                abi.encodeCall(OKAccount.initialize, (address(interact), address(interact.registry()), engine))
            )
        );
        bytes32 initCodeHash;
        assembly ("memory-safe") {
            initCodeHash := keccak256(add(initCode, 0x20), mload(initCode))
        }
        bytes32 create2Hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0xff)
            mstore(add(ptr, 1), shl(96, address()))
            mstore(add(ptr, 21), salt)
            mstore(add(ptr, 53), initCodeHash)
            create2Hash := keccak256(ptr, 85)
        }
        return address(uint160(uint256(create2Hash)));
    }

    /// @notice Return the number of indexed account deployments.
    function accountDeploymentCount() external view returns (uint256) {
        if (!indexingEnabled) {
            revert IndexingDisabled();
        }
        return _accounts.length();
    }

    /// @notice Return a page of indexed account deployment records.
    /// @param start Zero-based start offset in the deployment index.
    /// @param count Maximum number of records to return.
    function accountDeploymentPage(uint256 start, uint256 count)
        external
        view
        returns (AccountDeployment[] memory out)
    {
        if (!indexingEnabled) {
            revert IndexingDisabled();
        }
        bytes32[] memory accounts = _accounts.page(start, count);
        out = new AccountDeployment[](accounts.length);
        for (uint256 i; i < accounts.length; i++) {
            address account = address(uint160(uint256(accounts[i])));
            out[i] = _accountRecords[account];
        }
    }

    /// @notice Return the indexed deployment record stored at a raw index id.
    /// @param id Raw `PagedIndex` identifier.
    /// @return record Deployment metadata for that slot.
    /// @return isAlive Whether the slot is still live in the index.
    function accountDeploymentAt(uint256 id) external view returns (AccountDeployment memory record, bool isAlive) {
        if (!indexingEnabled) {
            revert IndexingDisabled();
        }
        (bytes32 value, bool alive) = _accounts.get(id);
        address account = address(uint160(uint256(value)));
        record = _accountRecords[account];
        isAlive = alive;
    }

    /// @notice Return the raw index id assigned to `account`, if any.
    function accountDeploymentId(address account) external view returns (uint256 id, bool exists) {
        if (!indexingEnabled) {
            revert IndexingDisabled();
        }
        return _accounts.idOf(_accountKey(account));
    }

    function _accountKey(address account) private pure returns (bytes32) {
        return bytes32(uint256(uint160(account)));
    }

    /// @dev Record a deployed account in the registry allowlist and, when enabled,
    ///      in the local pagination index.
    function _recordAccount(address account) private {
        IRegistryAccounts registryAccounts = IRegistryAccounts(address(interact.registry()));
        _factoryAccounts[account] = true;
        if (!registryAccounts.isAccountAllowed(account)) {
            registryAccounts.addAccount(account);
        }
        // Do not expose a deployed account that Interact cannot use. A Registry
        // category delay may turn addAccount into a queue-only call; this
        // postcondition makes account deployment and admission atomic.
        if (!registryAccounts.isAccountAllowed(account)) revert AccountRegistryAdmissionPending(account);
        if (!indexingEnabled) return;
        bytes32 key = _accountKey(account);
        AccountDeployment storage record = _accountRecords[account];
        if (_accounts.contains(key)) {
            if (record.account == address(0)) {
                record.account = account;
            }
            return;
        }
        _accounts.insert(key);
        _accountRecords[account] = AccountDeployment({
            account: account,
            blockNumber: SafeCast.toUint64(block.number),
            timestamp: SafeCast.toUint64(block.timestamp)
        });
    }

    /// @dev Restrict account creation to allowlisted tenant users.
    function _requireUser() private view {
        address registry = address(interact.registry());
        if (!IRegistryUsers(registry).isUser(msg.sender)) {
            revert CallerNotUser();
        }
    }
}
