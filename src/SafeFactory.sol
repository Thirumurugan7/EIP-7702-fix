// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {Safe} from "@gnosis.pm/safe-contracts/Safe.sol";
import "@gnosis.pm/safe-contracts/base/GuardManager.sol" as GM;
import {Enum} from "@gnosis.pm/safe-contracts/libraries/Enum.sol";
import {IProxy} from "@gnosis.pm/safe-contracts/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@gnosis.pm/safe-contracts/proxies/SafeProxyFactory.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {ChainwallUUPSUpgradeable} from "./ChainwallUpgradeable.sol";
import {Interact} from "./Interact.sol";
import {OKGuard} from "./OKGuard.sol";
import {OKModule} from "./OKModule.sol";
import {PagedIndex} from "./PagedIndex.sol";
import {SafeSingletonMigrator} from "./SafeSingletonMigrator.sol";

/// @title IRegistryUsers
/// @notice Minimal user-directory view required by {SafeFactoryWithCreate2}.
interface IRegistryUsers {
    /// @notice Returns true when `user` is allowlisted in the tenant registry.
    function isUser(address user) external view returns (bool);
}

/// @title IRegistrySafes
/// @notice Minimal Safe allowlist interface required by {SafeFactoryWithCreate2}.
interface IRegistrySafes {
    /// @notice Allowlist a newly deployed or imported Safe.
    function addSafe(address safe) external;
    /// @notice Returns true when `safe` is already registered.
    function isSafeAllowed(address safe) external view returns (bool);
}

/// @title SafeConfigurator
/// @notice Helper used during Safe setup to install extensions via delegatecall.
/// @dev Running inside the Safe's storage context allows configuring the guard,
///      mandatory Interact execution module, and optional automation module in
///      a single initializer step.
contract SafeConfigurator {
    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.SafeConfigurator");

    function chainwallComponentId() external pure returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @notice Install only the guard on the Safe currently running this delegatecall.
    function installGuard(address guard) external {
        GM.IGuardManager(address(this)).setGuard(guard);
    }

    /// @notice Set the guard and execution module, and optionally enable OKModule.
    /// @dev This is used both during initial deployment and during `importSafe`.
    function configure(address guard, bool setGuard, address executionModule, address module, bool enableModule)
        external
    {
        if (setGuard) {
            require(guard != address(0), "Configurator: guard=0x0");
            GM.IGuardManager(address(this)).setGuard(guard);
        }
        require(executionModule != address(0), "Configurator: execution=0x0");
        Safe targetSafe = Safe(payable(address(this)));
        if (!targetSafe.isModuleEnabled(executionModule)) {
            targetSafe.enableModule(executionModule);
        }
        if (enableModule) {
            require(module != address(0), "Configurator: module=0x0");
            targetSafe.enableModule(module);
        }
    }

    /// @notice Set the guard and execution gateway, optionally enable OKModule, and configure extension policy.
    /// @dev The call must run through Safe setup/import delegatecall so `address(this)` is the Safe.
    function configureWithExtensionPolicy(
        address guard,
        bool setGuard,
        address executionModule,
        address module,
        bool enableModule,
        OKModule.ExtensionPolicy modulePolicy,
        address[] calldata allowedModules,
        OKModule.ExtensionPolicy fallbackPolicy,
        address[] calldata allowedFallbackHandlers
    ) external {
        if (setGuard) {
            require(guard != address(0), "Configurator: guard=0x0");
            GM.IGuardManager(address(this)).setGuard(guard);
        }
        require(executionModule != address(0), "Configurator: execution=0x0");
        require(module != address(0), "Configurator: module=0x0");
        Safe targetSafe = Safe(payable(address(this)));
        if (!targetSafe.isModuleEnabled(executionModule)) {
            targetSafe.enableModule(executionModule);
        }
        if (enableModule && !targetSafe.isModuleEnabled(module)) {
            targetSafe.enableModule(module);
        }
        OKModule(module)
            .configureSafeExtensions(
                address(this), modulePolicy, allowedModules, fallbackPolicy, allowedFallbackHandlers
            );
    }
}

/// @title SafeExtensionsFactory
/// @notice Isolates guard/module implementation and proxy initcode from {SafeComponentsFactory} runtime.
/// @dev EIP-170 applies independently to both helpers. Only the component factory that created this helper may
///      consume its CREATE2 namespace, so an external caller cannot predeploy a tenant's extension addresses.
contract SafeExtensionsFactory {
    /// @notice Only component factory allowed to consume this helper's CREATE2 namespace.
    address public immutable COMPONENT_FACTORY = msg.sender;
    /// @notice Stateless implementation shared by every tenant guard proxy in this SafeFactory release.
    address public immutable GUARD_IMPLEMENTATION;
    /// @notice Stateless implementation shared by every tenant module proxy in this SafeFactory release.
    address public immutable MODULE_IMPLEMENTATION;

    error ComponentFactoryOnly();

    constructor() {
        // Implementations are initializer-locked and intentionally unbound.
        // Tenant-specific Interact and singleton-migrator pointers live only in each
        // proxy, so deploying the same implementation bytecode per tenant adds
        // gas without adding storage or authority isolation.
        GUARD_IMPLEMENTATION = address(new OKGuard(Interact(address(0)), SafeSingletonMigrator(address(0))));
        MODULE_IMPLEMENTATION = address(new OKModule(Interact(address(0)), SafeSingletonMigrator(address(0))));
    }

    function deploy(bytes32 callerSalt, Interact interact, SafeSingletonMigrator migrator)
        external
        returns (OKGuard guard, OKModule module)
    {
        if (msg.sender != COMPONENT_FACTORY) revert ComponentFactoryOnly();
        guard = OKGuard(
            address(
                new ERC1967Proxy{salt: keccak256(abi.encode(callerSalt, "guard"))}(
                    GUARD_IMPLEMENTATION, abi.encodeCall(OKGuard.initialize, (interact, migrator))
                )
            )
        );
        module = OKModule(
            address(
                new ERC1967Proxy{salt: keccak256(abi.encode(callerSalt, "module"))}(
                    MODULE_IMPLEMENTATION, abi.encodeCall(OKModule.initialize, (interact, migrator))
                )
            )
        );
    }
}

/// @title SafeComponentsFactory
/// @notice Deploys the fixed extension set used by one SafeFactory without embedding all child initcode in the
///         SafeFactory runtime.
/// @dev CREATE2 salts include `msg.sender`, so another caller cannot predeploy components at a SafeFactory's
///      addresses. SafeFactory initialization is one-shot, making one component set per caller sufficient.
contract SafeComponentsFactory {
    /// @notice Dedicated extension deployer created once with this component factory as its only caller.
    /// @dev Stored rather than immutable so this contract's runtime codehash remains identical across deployments.
    SafeExtensionsFactory public EXTENSION_FACTORY;

    /// @dev Successful probes revert so the temporary Safe deployment and its effects are rolled back.
    error SafeProxyRuntimeCodehashResult(bytes32 codehash);
    error SafeProxyRuntimeProbeFailed();

    constructor() {
        EXTENSION_FACTORY = new SafeExtensionsFactory();
    }

    function deploy(Interact interact)
        external
        returns (SafeSingletonMigrator migrator, OKGuard guard, OKModule module, SafeConfigurator configurator)
    {
        bytes32 callerSalt = bytes32(uint256(uint160(msg.sender)));
        migrator = new SafeSingletonMigrator{salt: keccak256(abi.encode(callerSalt, "migrator"))}(
            address(interact), msg.sender
        );
        (guard, module) = EXTENSION_FACTORY.deploy(callerSalt, interact, migrator);
        configurator = new SafeConfigurator{salt: keccak256(abi.encode(callerSalt, "configurator"))}();
    }

    /// @notice Resolve the runtime produced by the configured proxy factory's exact creation code.
    /// @dev This function always reverts. Returning the result through revert data rolls back
    ///      the temporary deployment and avoids depending on a collision-prone public-factory salt.
    function probeSafeProxyRuntimeCodehash(bytes calldata proxyCreationCode, address singleton) external {
        bytes memory initCode = abi.encodePacked(proxyCreationCode, uint256(uint160(singleton)));
        address proxy;
        assembly ("memory-safe") {
            proxy := create(0, add(initCode, 0x20), mload(initCode))
        }
        if (proxy.code.length == 0) revert SafeProxyRuntimeProbeFailed();
        revert SafeProxyRuntimeCodehashResult(proxy.codehash);
    }
}

/// @title SafeFactoryWithCreate2
/// @notice Deploys a Gnosis Safe proxy with the Chainwall guard, execution gateway, and optional module.
/// @dev Every Safe deployed here shares the same tenant-local execution runtime:
///      one `Interact`, one `OKGuard`, one `OKModule`, and one `SafeSingletonMigrator`.
///
///      This gives tenants a repeatable wallet template:
///      1. an allowlisted user calls {newSafe}
///      2. the Safe is deployed deterministically in this tenant factory's CREATE2 namespace
///      3. the shared guard, Interact execution module, and optional OKModule are installed during setup
///      4. the Safe is recorded in `RegistryAccountsFacet`
///
///      A Safe recorded by this factory is part of Chainwall's allowlisted vault set.
///      Therefore every state-changing deploy/import path requires OKGuard. Module-only
///      or raw Safes can bypass Interact through ordinary owner transactions and must
///      not be registered here.
contract SafeFactoryWithCreate2 is ReentrancyGuard, ChainwallUUPSUpgradeable {
    using PagedIndex for PagedIndex.Index;

    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.SafeFactory");
    /// @notice Import option trusting every current and future module on the Safe.
    uint256 public constant IMPORT_OPTION_SKIP_MODULE_CHECK = 1 << 0;
    /// @notice Supported bits for {importSafeWithOptions}; unknown bits must never be silently ignored.
    uint256 public constant SUPPORTED_IMPORT_OPTIONS = IMPORT_OPTION_SKIP_MODULE_CHECK;
    bytes32 private constant SAFE_SINGLETON_MIGRATOR_COMPONENT_ID = keccak256("Chainwall.SafeSingletonMigrator");
    bytes32 private constant SAFE_CONFIGURATOR_COMPONENT_ID = keccak256("Chainwall.SafeConfigurator");

    /// @notice Gnosis proxy factory whose proxy bytecode is approved for this deployment.
    /// @dev Safe creation uses this tenant factory's CREATE2 namespace so a caller of
    ///      the public proxy factory cannot consume a predicted tenant Safe address.
    SafeProxyFactory public PROXY_FACTORY;
    /// @notice Gnosis Safe singleton used as the proxy master copy.
    address public SAFE_SINGLETON;
    /// @notice Approved runtime codehash for Safe proxies imported by this factory.
    bytes32 public SAFE_PROXY_RUNTIME_CODEHASH;
    /// @notice Codehash of the approved singleton at factory initialization.
    bytes32 public SAFE_SINGLETON_CODEHASH;
    /// @notice Hash of the canonical VERSION reported by the approved singleton.
    bytes32 public SAFE_SINGLETON_VERSION_HASH;
    /// @notice Tenant-local `Interact` instance all managed Safes are wired to.
    Interact public INTERACT_CONTRACT;
    /// @notice Shared guard installed on Safes when requested.
    OKGuard public GUARD_CONTRACT;
    /// @notice Shared automation module installed on Safes when requested.
    OKModule public MODULE_CONTRACT;
    /// @notice One-purpose singleton migrator used by the guard/module pair.
    SafeSingletonMigrator public SAFE_SINGLETON_MIGRATOR;
    /// @notice Delegatecall helper used during Safe setup and import flows.
    SafeConfigurator public CONFIGURATOR;

    /// @notice Whether deployment indexing is enabled.
    bool public INDEXING_ENABLED;
    /// @notice Block where deployment indexing started, or zero when disabled.
    uint64 public INDEXING_START_BLOCK;

    /// @notice Emitted after a Safe is deployed and wired with the mandatory guard plus optional automation module.
    event SafeDeployed(address indexed safe, address guard, address module);
    /// @notice Emitted once when indexing is enabled for this factory.
    event IndexingEnabled(uint64 startBlock);
    /// @notice Emitted when future Safe deployments adopt another approved singleton.
    event SafeSingletonChanged(
        address indexed previousSingleton,
        address indexed newSingleton,
        bytes32 newSingletonCodehash,
        bytes32 newSingletonVersionHash
    );
    /// @notice Emitted when future deployments adopt another approved Safe proxy factory.
    event SafeProxyFactoryChanged(
        address indexed previousProxyFactory,
        address indexed newProxyFactory,
        bytes32 newProxyFactoryCodehash,
        bytes32 newProxyCreationCodehash,
        bytes32 newProxyRuntimeCodehash
    );
    event SafeSingletonMigratorChanged(address indexed previousMigrator, address indexed newMigrator);
    event SafeConfiguratorChanged(address indexed previousConfigurator, address indexed newConfigurator);

    address private constant SENTINEL_MODULES = address(0x1);
    uint256 private constant MODULE_PAGE_SIZE = 16;
    uint256 private constant MODULE_PAGE_LIMIT = 16;
    bytes32 private constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 private constant MODULE_GUARD_STORAGE_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    bytes32 private constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @notice Thrown when callers request index-backed reads while indexing is disabled.
    error IndexingDisabled();
    /// @notice Thrown when an import request is structurally invalid.
    error ImportSafeInvalid();
    /// @notice Thrown when the Safe itself rejects the import transaction.
    error ImportSafeFailed();
    error UnsupportedImportOptions(uint256 options);
    /// @notice Thrown when a non-user attempts to deploy or import a Safe.
    error CallerNotUser();
    /// @notice Thrown when strict mode sees a module other than Interact or the optional shared OKModule.
    error SafeModuleNotAllowed(address safe, address module);
    /// @notice Thrown when strict mode sees a non-zero fallback handler.
    error SafeFallbackHandlerNotAllowed(address safe, address handler);
    /// @notice Thrown when strict module validation would need unbounded pagination.
    error SafeModulePaginationLimit(address safe);
    /// @notice Thrown when a module-managed Safe is not a degenerate 1-of-1 account.
    error SafeOwnerConfigNotAllowed(address safe, uint256 ownerCount, uint256 threshold);
    /// @notice Thrown when a factory flow would record a Safe without the Chainwall guard.
    error SafeGuardRequired();
    /// @notice Thrown when configured Safe infrastructure is not deployed code.
    error SafeInfrastructureInvalid(address target);
    /// @notice Thrown when CREATE2 cannot deploy the configured Safe proxy bytecode.
    error SafeProxyDeploymentFailed();
    /// @notice Thrown when the configured singleton does not report an import-supported release.
    error SafeSingletonVersionNotApproved(address singleton, bytes32 versionHash);
    /// @notice Thrown when a deployed or imported address is not an approved Safe proxy runtime.
    error SafeProxyRuntimeNotApproved(address safe, bytes32 expectedCodehash, bytes32 actualCodehash);
    /// @notice Thrown when an imported Safe points at another singleton.
    error SafeSingletonNotApproved(address safe, address expectedSingleton, address actualSingleton);
    /// @notice Thrown when the configured singleton runtime has changed since initialization.
    error SafeSingletonCodehashMismatch(address singleton, bytes32 expectedCodehash, bytes32 actualCodehash);
    /// @notice Thrown when the configured public Safe proxy factory runtime changes after approval.
    error SafeProxyFactoryCodehashMismatch(address proxyFactory, bytes32 expectedCodehash, bytes32 actualCodehash);
    /// @notice Thrown when the configured factory returns proxy creation bytecode different from the approved bytes.
    error SafeProxyCreationCodehashMismatch(address proxyFactory, bytes32 expectedCodehash, bytes32 actualCodehash);
    /// @notice Thrown when a Safe reports a version different from its approved singleton mapping.
    error SafeVersionMismatch(address safe, bytes32 expectedVersionHash, bytes32 actualVersionHash);
    /// @notice Thrown when an upgrade is attempted outside the bound tenant Registry.
    error OnlyRegistry();
    /// @notice Thrown when a singleton migrator has the wrong type or tenant binding.
    error SafeSingletonMigratorInvalid(address migrator);
    /// @notice Thrown when a setup helper has the wrong runtime type.
    error SafeConfiguratorInvalid(address configurator);
    /// @notice Thrown when a post-migration check targets a Safe not recorded by this factory.
    error SafeNotManaged(address safe);
    /// @notice Thrown when a managed Safe no longer exposes the tenant's exact guard.
    error SafeGuardNotApproved(address safe, address expectedGuard, address actualGuard);
    /// @notice Thrown when a managed Safe no longer enables its tenant Interact execution gateway.
    error SafeExecutionModuleMissing(address safe, address executionModule);
    /// @notice Thrown when Registry admission was queued instead of becoming effective atomically.
    error SafeRegistryAdmissionPending(address safe);

    /// @notice Lightweight deployment record returned by pagination views.
    struct SafeDeployment {
        /// @notice Safe proxy address.
        address safe;
        /// @notice Shared guard address installed on the Safe.
        address guard;
        /// @notice Shared module address enabled on the Safe, if any.
        address module;
        /// @notice Block number when the Safe was first recorded.
        uint64 blockNumber;
        /// @notice Timestamp when the Safe was first recorded.
        uint64 timestamp;
    }

    PagedIndex.Index private _safes;
    mapping(address => SafeDeployment) private _safeRecords;
    mapping(address => bool) private _factorySafes;
    /// @dev Historical singleton metadata remains accepted for existing and imported Safes after the default changes.
    mapping(address => bytes32) private _approvedSafeSingletonCodehash;
    mapping(address => bytes32) private _approvedSafeSingletonVersionHash;
    /// @notice Runtime codehash of the external Safe proxy factory used as the creation-code authority.
    /// @dev Pinned during initialization and changed only by a Registry-timelocked release action.
    bytes32 public SAFE_PROXY_FACTORY_CODEHASH;
    /// @notice Hash of the exact proxy creation bytecode approved for deterministic Safe deployments.
    bytes32 public SAFE_PROXY_CREATION_CODEHASH;
    /// @dev Preserve provenance for Safes created by earlier approved proxy-factory releases.
    mapping(bytes32 => bool) private _approvedSafeProxyRuntimeCodehash;
    /// @notice Fixed release deployer for guard/module/configurator component sets.
    address public immutable COMPONENT_FACTORY;

    /// @param _safeSingleton address of the Gnosis Safe master copy
    /// @param _proxyFactory  address of the GnosisSafeProxyFactory
    /// @param _interactContract tenant-local Interact instance used by the guard/module pair
    /// @param indexingEnabled whether deployment history should be indexed on-chain
    /// @param _componentFactory separately deployed release component factory
    constructor(
        address _safeSingleton,
        address _proxyFactory,
        Interact _interactContract,
        bool indexingEnabled,
        SafeComponentsFactory _componentFactory
    ) {
        if (!Delegation7702.hasContractCode(address(_componentFactory))) {
            revert SafeInfrastructureInvalid(address(_componentFactory));
        }
        COMPONENT_FACTORY = address(_componentFactory);
        initialize(_safeSingleton, _proxyFactory, _interactContract, indexingEnabled);
    }

    /// @notice Initialize a tenant SafeFactory proxy.
    /// @param _safeSingleton address of the Gnosis Safe master copy
    /// @param _proxyFactory  address of the GnosisSafeProxyFactory
    /// @param _interactContract tenant-local Interact instance used by the guard/module pair
    /// @param indexingEnabled whether deployment history should be indexed on-chain
    // The constructor consumes this initializer on the implementation; a proxy initializes its own storage once.
    // Singleton validation requires deployed code and an approved VERSION; the zero address cannot pass.
    // forge-lint: disable-next-line(unprotected-initializer, missing-zero-check)
    function initialize(address _safeSingleton, address _proxyFactory, Interact _interactContract, bool indexingEnabled)
        public
        initializer
    {
        if (!Delegation7702.hasContractCode(_safeSingleton)) revert SafeInfrastructureInvalid(_safeSingleton);
        if (!Delegation7702.hasContractCode(_proxyFactory)) revert SafeInfrastructureInvalid(_proxyFactory);
        SAFE_SINGLETON = _safeSingleton;
        PROXY_FACTORY = SafeProxyFactory(_proxyFactory);
        bytes memory proxyCreationCode = _proxyCreationCodeUnchecked(_proxyFactory);
        SAFE_PROXY_FACTORY_CODEHASH = _proxyFactory.codehash;
        SAFE_PROXY_CREATION_CODEHASH = keccak256(proxyCreationCode);
        SAFE_PROXY_RUNTIME_CODEHASH = _resolveSafeProxyRuntimeCodehash(proxyCreationCode, _safeSingleton);
        _approvedSafeProxyRuntimeCodehash[SAFE_PROXY_RUNTIME_CODEHASH] = true;
        SAFE_SINGLETON_CODEHASH = _safeSingleton.codehash;
        bytes32 singletonVersionHash = keccak256(bytes(Safe(payable(_safeSingleton)).VERSION()));
        if (!_isApprovedSafeVersion(singletonVersionHash)) {
            revert SafeSingletonVersionNotApproved(_safeSingleton, singletonVersionHash);
        }
        SAFE_SINGLETON_VERSION_HASH = singletonVersionHash;
        _approvedSafeSingletonCodehash[_safeSingleton] = SAFE_SINGLETON_CODEHASH;
        _approvedSafeSingletonVersionHash[_safeSingleton] = singletonVersionHash;
        INTERACT_CONTRACT = _interactContract;
        (SAFE_SINGLETON_MIGRATOR, GUARD_CONTRACT, MODULE_CONTRACT, CONFIGURATOR) =
            SafeComponentsFactory(COMPONENT_FACTORY).deploy(_interactContract);
        INDEXING_ENABLED = indexingEnabled;
        INDEXING_START_BLOCK = indexingEnabled ? SafeCast.toUint64(block.number) : 0;
        if (indexingEnabled) {
            // The initializer is one-shot; concrete component construction has no user callback and runtime probes
            // revert before this event.
            // forge-lint: disable-next-line(reentrancy-events)
            emit IndexingEnabled(INDEXING_START_BLOCK);
        }
        __UUPSUpgradeable_init();
    }

    /// @notice Return the mandatory Safe module used for native MiniScript execution.
    function executionModule() external view returns (Interact) {
        return INTERACT_CONTRACT;
    }

    /// @notice Stable logical type used by Registry upgrade verification.
    function chainwallComponentId() external pure override returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @notice Return the singleton used for future Safe deployments.
    function chainwallSafeSingleton() external view returns (address) {
        return SAFE_SINGLETON;
    }

    /// @notice Upgrade entry point reserved for the tenant Registry timelock.
    /// @dev The proxy keeps all Safe provenance, indexing, and extension addresses.
    ///      Upgrading this factory does not silently replace extensions already
    ///      installed on managed Safes.
    function timelockUpgrade(address newImplementation, bytes calldata data) external {
        if (msg.sender != address(INTERACT_CONTRACT.registry())) revert OnlyRegistry();
        _upgradePreservingBindings(newImplementation, data);
    }

    /// @notice Disable the ordinary UUPS surface so callers must use {timelockUpgrade}.
    function upgradeToAndCall(address, bytes memory) public payable override {
        revert("SafeFactory: use timelockUpgrade");
    }

    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != address(INTERACT_CONTRACT.registry())) revert OnlyRegistry();
    }

    /// @dev These values define Safe provenance and the exact extension code installed by this stable factory.
    ///      Their dedicated release actions preserve historical approvals and apply coordinated postconditions.
    function _chainwallSecurityBindingsHash() internal view override returns (bytes32) {
        // This slot held PLAN_EXECUTOR in the pre-minimal release. Validate its
        // new type and tenant bindings before hashing it so equal storage alone
        // cannot authorize a semantic reinterpretation during UUPS admission.
        _requireSafeSingletonMigrator(address(SAFE_SINGLETON_MIGRATOR));
        return _hashSecurityBindings(
            abi.encode(
                address(PROXY_FACTORY),
                SAFE_SINGLETON,
                SAFE_PROXY_RUNTIME_CODEHASH,
                SAFE_SINGLETON_CODEHASH,
                SAFE_SINGLETON_VERSION_HASH,
                address(INTERACT_CONTRACT),
                address(GUARD_CONTRACT),
                address(MODULE_CONTRACT),
                address(SAFE_SINGLETON_MIGRATOR),
                address(CONFIGURATOR),
                SAFE_PROXY_FACTORY_CODEHASH,
                SAFE_PROXY_CREATION_CODEHASH,
                COMPONENT_FACTORY.codehash
            )
        );
    }

    /// @notice Change the singleton default for future deployments without mutating existing Safe proxies.
    /// @dev Historical approved metadata is retained so existing Safes keep valid factory provenance.
    // Singleton validation requires deployed code and an approved VERSION; the zero address cannot pass.
    // forge-lint: disable-next-line(missing-zero-check)
    function setChainwallSafeSingleton(address newSingleton) external {
        if (msg.sender != address(INTERACT_CONTRACT.registry())) revert OnlyRegistry();
        (bytes32 codehash_, bytes32 versionHash) = _requireSafeSingleton(newSingleton);
        address previous = SAFE_SINGLETON;
        _approvedSafeSingletonCodehash[previous] = SAFE_SINGLETON_CODEHASH;
        _approvedSafeSingletonVersionHash[previous] = SAFE_SINGLETON_VERSION_HASH;
        _approvedSafeSingletonCodehash[newSingleton] = codehash_;
        _approvedSafeSingletonVersionHash[newSingleton] = versionHash;
        bytes32 proxyRuntimeCodehash =
            _resolveSafeProxyRuntimeCodehash(_proxyCreationCode(address(PROXY_FACTORY)), newSingleton);
        _approvedSafeProxyRuntimeCodehash[proxyRuntimeCodehash] = true;
        SAFE_SINGLETON = newSingleton;
        SAFE_SINGLETON_CODEHASH = codehash_;
        SAFE_SINGLETON_VERSION_HASH = versionHash;
        SAFE_PROXY_RUNTIME_CODEHASH = proxyRuntimeCodehash;
        // Safe deployment holds nonReentrant; configuration probes revert their entire frame before setters commit
        // and emit.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeSingletonChanged(previous, newSingleton, codehash_, versionHash);
    }

    /// @notice Change the Safe proxy factory used only by future deployments.
    /// @dev The Registry action commits the factory runtime and exact creation
    ///      bytecode hash. Earlier proxy runtimes remain approved for provenance.
    function setChainwallSafeProxyFactory(address newProxyFactory, bytes32 expectedCreationCodehash) external {
        if (msg.sender != address(INTERACT_CONTRACT.registry())) revert OnlyRegistry();
        if (!Delegation7702.hasContractCode(newProxyFactory)) revert SafeInfrastructureInvalid(newProxyFactory);
        bytes memory creationCode = _proxyCreationCodeUnchecked(newProxyFactory);
        bytes32 creationCodehash = keccak256(creationCode);
        if (creationCodehash != expectedCreationCodehash) {
            revert SafeProxyCreationCodehashMismatch(newProxyFactory, expectedCreationCodehash, creationCodehash);
        }
        address previous = address(PROXY_FACTORY);
        bytes32 runtimeCodehash = _resolveSafeProxyRuntimeCodehash(creationCode, SAFE_SINGLETON);
        PROXY_FACTORY = SafeProxyFactory(newProxyFactory);
        SAFE_PROXY_FACTORY_CODEHASH = newProxyFactory.codehash;
        SAFE_PROXY_CREATION_CODEHASH = creationCodehash;
        SAFE_PROXY_RUNTIME_CODEHASH = runtimeCodehash;
        _approvedSafeProxyRuntimeCodehash[runtimeCodehash] = true;
        // Safe deployment holds nonReentrant; configuration probes revert their entire frame before setters commit
        // and emit.
        // forge-lint: disable-start(reentrancy-events)
        emit SafeProxyFactoryChanged(
            previous, newProxyFactory, SAFE_PROXY_FACTORY_CODEHASH, creationCodehash, runtimeCodehash
        );
        // forge-lint: disable-end(reentrancy-events)
    }

    /// @notice Synchronize the factory's singleton migrator with its guard and module release.
    /// @dev The Registry release facet updates all three hosts atomically and verifies their resulting commitments.
    function setChainwallSafeSingletonMigrator(address newMigrator) external {
        if (msg.sender != address(INTERACT_CONTRACT.registry())) revert OnlyRegistry();
        _requireSafeSingletonMigrator(newMigrator);
        address previous = address(SAFE_SINGLETON_MIGRATOR);
        SAFE_SINGLETON_MIGRATOR = SafeSingletonMigrator(newMigrator);
        emit SafeSingletonMigratorChanged(previous, newMigrator);
    }

    /// @notice Replace the setup/import delegatecall helper used for future Safe configurations.
    /// @dev Existing Safes are unaffected because the helper holds no state and is used only while configuring a Safe.
    function setChainwallConfigurator(address newConfigurator) external {
        if (msg.sender != address(INTERACT_CONTRACT.registry())) revert OnlyRegistry();
        _requireConfigurator(newConfigurator);
        address previous = address(CONFIGURATOR);
        CONFIGURATOR = SafeConfigurator(newConfigurator);
        emit SafeConfiguratorChanged(previous, newConfigurator);
    }

    /// @notice Return whether `singleton` is an exact release accepted by this tenant factory.
    function isSafeSingletonApproved(address singleton) external view returns (bool) {
        return _isSafeSingletonApproved(singleton);
    }

    /// @notice Return whether `singleton` is the tenant's current migration destination.
    /// @dev Historical singleton approvals remain valid only for provenance. A rollback
    ///      first makes the historical release current through {setChainwallSafeSingleton}.
    function isSafeSingletonMigrationTarget(address singleton) external view returns (bool) {
        return singleton == SAFE_SINGLETON && _isSafeSingletonApproved(singleton);
    }

    /// @notice Revalidate a managed Safe after changing its singleton.
    /// @dev The migration transaction reverts atomically unless the new singleton
    ///      can still expose the expected guard, module policy, owners, and fallback.
    function validateManagedSafe(address safe) external view {
        if (!_factorySafes[safe]) revert SafeNotManaged(safe);
        _requireAuthenticSafe(safe);

        Safe targetSafe = Safe(payable(safe));
        address actualGuard = _safeStorageAddress(targetSafe, GUARD_STORAGE_SLOT);
        address expectedGuard = address(GUARD_CONTRACT);
        if (actualGuard != expectedGuard) {
            revert SafeGuardNotApproved(safe, expectedGuard, actualGuard);
        }

        MODULE_CONTRACT.validateSafeExtensions(safe);
    }

    function _isSafeSingletonApproved(address singleton) private view returns (bool) {
        bytes32 expectedCodehash = _approvedSafeSingletonCodehash[singleton];
        bytes32 expectedVersionHash = _approvedSafeSingletonVersionHash[singleton];
        if (expectedCodehash == bytes32(0) || singleton.codehash != expectedCodehash) return false;
        try Safe(payable(singleton)).VERSION() returns (string memory version) {
            return keccak256(bytes(version)) == expectedVersionHash;
        } catch {
            return false;
        }
    }

    /// @notice Returns true when this factory deployed/imported and recorded `safe`.
    /// @dev Registry allowlisting uses this provenance check before trusting the
    ///      Safe's guard/module/fallback state.
    function isSafe(address safe) external view returns (bool) {
        return _factorySafes[safe];
    }

    /// @notice Deploy a Safe proxy under CREATE2 and install the Chainwall guard, optionally with the module.
    /// @dev The factory records every deployed Safe in the registry, so the guard is mandatory. Raw or
    ///      module-only Safes can bypass Interact and must not become allowlisted vaults through this factory.
    /// @param salt            caller-supplied salt reused for the factory nonce
    /// @param owners          Safe owners
    /// @param threshold       signature threshold
    /// @param fallbackHandler optional Safe fallback handler
    /// @param installGuard    whether to set the shared OKGuard on the Safe
    /// @param installModule   whether to enable the OKModule on the Safe
    /// @return proxyAddress   address of the newly deployed Safe proxy
    function newSafe(
        bytes32 salt,
        address[] calldata owners,
        uint256 threshold,
        address fallbackHandler,
        bool installGuard,
        bool installModule
    ) external payable nonReentrant returns (address proxyAddress) {
        _requireUser();
        _requireGuardRequested(installGuard);
        if (installModule) {
            _requireSingleOwnerThreshold(address(0), owners.length, threshold);
        }
        if ((installGuard || installModule) && fallbackHandler != address(0)) {
            revert SafeFallbackHandlerNotAllowed(address(0), fallbackHandler);
        }
        bytes memory initializer = _safeInitializer(owners, threshold, fallbackHandler, installGuard, installModule);

        proxyAddress = _deployProxy(salt, initializer);
        // Forward any ETH sent to factory to the new Safe.
        _fundSafe(proxyAddress);

        address guard = installGuard ? address(GUARD_CONTRACT) : address(0);
        address module = installModule ? address(MODULE_CONTRACT) : address(0);
        _requireStrictSafeExtensions(proxyAddress, installModule, true);
        _recordSafe(proxyAddress, guard, module);
        // Safe deployment holds nonReentrant; configuration probes revert their entire frame before setters commit
        // and emit.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeDeployed(proxyAddress, guard, module);
    }

    /// @notice Deploy a guarded Safe and opt into a non-default module/fallback policy.
    /// @dev This path always enables OKModule because the policy lives in the module. The guard is still
    ///      mandatory because the resulting Safe is recorded as a Chainwall-controlled vault.
    function newSafeWithExtensionPolicy(
        bytes32 salt,
        address[] calldata owners,
        uint256 threshold,
        address fallbackHandler,
        bool installGuard,
        OKModule.ExtensionPolicy modulePolicy,
        address[] calldata allowedModules,
        OKModule.ExtensionPolicy fallbackPolicy,
        address[] calldata allowedFallbackHandlers
    ) external payable nonReentrant returns (address proxyAddress) {
        _requireUser();
        _requireGuardRequested(installGuard);
        _requireSingleOwnerThreshold(address(0), owners.length, threshold);
        _requireFallbackPolicyAllows(address(0), fallbackHandler, fallbackPolicy, allowedFallbackHandlers);

        bytes memory initializer = _extensionPolicyInitializer(
            owners,
            threshold,
            fallbackHandler,
            installGuard,
            modulePolicy,
            allowedModules,
            fallbackPolicy,
            allowedFallbackHandlers
        );

        proxyAddress = _deployProxy(salt, initializer);
        _fundSafe(proxyAddress);

        MODULE_CONTRACT.validateSafeExtensions(proxyAddress);
        address guard = installGuard ? address(GUARD_CONTRACT) : address(0);
        _recordSafe(proxyAddress, guard, address(MODULE_CONTRACT));
        // Safe deployment holds nonReentrant; configuration probes revert their entire frame before setters commit
        // and emit.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeDeployed(proxyAddress, guard, address(MODULE_CONTRACT));
    }

    /// @notice Import a Safe with the original ABI and owner-signed configurator payload.
    /// @dev Non-strict preconfigured policies are rejected. Use {importSafeWithOptions} with zero options to
    ///      explicitly reset them to Strict in the owners' signed transaction.
    function importSafe(
        address safe,
        bool installGuard,
        bool installModule,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        bytes calldata signatures
    ) external nonReentrant returns (bool) {
        bool enableModule = _prepareSafeImport(safe, installGuard, installModule, true);
        bytes memory configData = abi.encodeCall(
            SafeConfigurator.configure,
            (address(GUARD_CONTRACT), installGuard, address(INTERACT_CONTRACT), address(MODULE_CONTRACT), enableModule)
        );
        _executeSafeImport(safe, configData, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures);
        // Checking only the current module list would leave a preconfigured permissive/allowlist policy active.
        MODULE_CONTRACT.validateStrictSafeExtensions(safe);
        _recordImportedSafe(safe);
        return true;
    }

    /// @notice Install the guard, Interact gateway, and optional OKModule with explicit import options.
    /// @dev Import always installs the guard before recording the Safe in the registry. Future options must be
    ///      reflected in the owners' signed Safe transaction as well as validated here.
    /// @param options Bitmask: zero keeps module checks enabled; IMPORT_OPTION_SKIP_MODULE_CHECK trusts all
    ///      current and future modules, which can execute outside Chainwall policy. Unsupported bits revert.
    function importSafeWithOptions(
        address safe,
        bool installGuard,
        bool installModule,
        uint256 options,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        bytes calldata signatures
    ) external nonReentrant returns (bool) {
        if (options & ~SUPPORTED_IMPORT_OPTIONS != 0) revert UnsupportedImportOptions(options);
        bool checkModules = options & IMPORT_OPTION_SKIP_MODULE_CHECK == 0;
        bool enableModule = _prepareSafeImport(safe, installGuard, installModule, checkModules);
        bytes memory configData = abi.encodeCall(
            SafeConfigurator.configureWithExtensionPolicy,
            (
                address(GUARD_CONTRACT),
                installGuard,
                address(INTERACT_CONTRACT),
                address(MODULE_CONTRACT),
                enableModule,
                checkModules ? OKModule.ExtensionPolicy.Strict : OKModule.ExtensionPolicy.Permissive,
                new address[](0),
                OKModule.ExtensionPolicy.Strict,
                new address[](0)
            )
        );
        _executeSafeImport(safe, configData, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures);
        MODULE_CONTRACT.validateSafeExtensions(safe);
        _recordImportedSafe(safe);
        return true;
    }

    function _prepareSafeImport(address safe, bool installGuard, bool installModule, bool checkModules)
        private
        view
        returns (bool enableModule)
    {
        _requireUser();
        if (safe == address(0)) revert ImportSafeInvalid();
        _requireAuthenticSafe(safe);
        _requireGuardRequested(installGuard);
        bool moduleAlreadyEnabled = Safe(payable(safe)).isModuleEnabled(address(MODULE_CONTRACT));
        enableModule = installModule && !moduleAlreadyEnabled;
        if (installModule || moduleAlreadyEnabled) _requireSafeSingleOwnerThreshold(safe);
        if (checkModules) _requireStrictSafeExtensions(safe, moduleAlreadyEnabled, false);
    }

    function _executeSafeImport(
        address safe,
        bytes memory configData,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        bytes calldata signatures
    ) private {
        bool success = Safe(payable(safe))
            .execTransaction(
                address(CONFIGURATOR),
                0,
                configData,
                Enum.Operation.DelegateCall,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                payable(refundReceiver),
                signatures
            );
        if (!success) revert ImportSafeFailed();
    }

    function _recordImportedSafe(address safe) private {
        address module =
            Safe(payable(safe)).isModuleEnabled(address(MODULE_CONTRACT)) ? address(MODULE_CONTRACT) : address(0);
        _recordSafe(safe, address(GUARD_CONTRACT), module);
    }

    /// @notice Import an existing guarded Safe while opting into a non-default module/fallback policy.
    /// @dev Existing extensions are explicitly trusted without enabling the optional OKModule. If OKModule was
    ///      already enabled, its 1-of-1 owner constraint remains enforced. The guard is always mandatory.
    function importSafeWithExtensionPolicy(
        address safe,
        bool installGuard,
        OKModule.ExtensionPolicy modulePolicy,
        address[] calldata allowedModules,
        OKModule.ExtensionPolicy fallbackPolicy,
        address[] calldata allowedFallbackHandlers,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        bytes calldata signatures
    ) external nonReentrant returns (bool) {
        _requireUser();
        if (safe == address(0)) {
            revert ImportSafeInvalid();
        }
        _requireAuthenticSafe(safe);
        _requireGuardRequested(installGuard);
        _requireFallbackPolicyAllows(
            safe, _fallbackHandler(Safe(payable(safe))), fallbackPolicy, allowedFallbackHandlers
        );

        bytes memory configData = abi.encodeWithSelector(
            SafeConfigurator.configureWithExtensionPolicy.selector,
            address(GUARD_CONTRACT),
            installGuard,
            address(INTERACT_CONTRACT),
            address(MODULE_CONTRACT),
            false,
            modulePolicy,
            allowedModules,
            fallbackPolicy,
            allowedFallbackHandlers
        );
        bool success = Safe(payable(safe))
            .execTransaction(
                address(CONFIGURATOR),
                0,
                configData,
                Enum.Operation.DelegateCall,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                payable(refundReceiver),
                signatures
            );
        if (!success) {
            revert ImportSafeFailed();
        }

        MODULE_CONTRACT.validateSafeExtensions(safe);
        address guard = installGuard ? address(GUARD_CONTRACT) : address(0);
        address module =
            Safe(payable(safe)).isModuleEnabled(address(MODULE_CONTRACT)) ? address(MODULE_CONTRACT) : address(0);
        _recordSafe(safe, guard, module);
        return true;
    }

    /// @notice Compute the Safe proxy address for provided parameters.
    /// @dev Mirrors the CREATE2 derivation used by `newSafe`. Cross-chain parity additionally requires the same tenant
    ///      SafeFactory, singleton, proxy creation code, extension addresses, initializer inputs, and salt.
    function computeSafeAddress(
        bytes32 salt,
        address[] calldata owners,
        uint256 threshold,
        address fallbackHandler,
        bool installGuard,
        bool installModule
    ) external view returns (address) {
        bytes memory initializer = _safeInitializer(owners, threshold, fallbackHandler, installGuard, installModule);
        return _computeProxyAddress(salt, initializer);
    }

    /// @notice Compute the Safe proxy address for {newSafeWithExtensionPolicy}.
    function computeSafeAddressWithExtensionPolicy(
        bytes32 salt,
        address[] calldata owners,
        uint256 threshold,
        address fallbackHandler,
        bool installGuard,
        OKModule.ExtensionPolicy modulePolicy,
        address[] calldata allowedModules,
        OKModule.ExtensionPolicy fallbackPolicy,
        address[] calldata allowedFallbackHandlers
    ) external view returns (address) {
        bytes memory initializer = _extensionPolicyInitializer(
            owners,
            threshold,
            fallbackHandler,
            installGuard,
            modulePolicy,
            allowedModules,
            fallbackPolicy,
            allowedFallbackHandlers
        );
        return _computeProxyAddress(salt, initializer);
    }

    function safeDeploymentCount() external view returns (uint256) {
        if (!INDEXING_ENABLED) {
            revert IndexingDisabled();
        }
        return _safes.length();
    }

    /// @notice Return a page of indexed Safe deployment records.
    function safeDeploymentPage(uint256 start, uint256 count) external view returns (SafeDeployment[] memory out) {
        if (!INDEXING_ENABLED) {
            revert IndexingDisabled();
        }
        bytes32[] memory safes = _safes.page(start, count);
        out = new SafeDeployment[](safes.length);
        for (uint256 i; i < safes.length; i++) {
            address safe = address(uint160(uint256(safes[i])));
            out[i] = _safeRecords[safe];
        }
    }

    /// @notice Return the indexed deployment record stored at raw id `id`.
    function safeDeploymentAt(uint256 id) external view returns (SafeDeployment memory record, bool isAlive) {
        if (!INDEXING_ENABLED) {
            revert IndexingDisabled();
        }
        (bytes32 value, bool alive) = _safes.get(id);
        address safe = address(uint160(uint256(value)));
        record = _safeRecords[safe];
        isAlive = alive;
    }

    /// @notice Return the raw index id assigned to `safe`, if any.
    function safeDeploymentId(address safe) external view returns (uint256 id, bool exists) {
        if (!INDEXING_ENABLED) {
            revert IndexingDisabled();
        }
        return _safes.idOf(_safeKey(safe));
    }

    function _safeKey(address safe) private pure returns (bytes32) {
        return bytes32(uint256(uint160(safe)));
    }

    function _safeInitializer(
        address[] calldata owners,
        uint256 threshold,
        address fallbackHandler,
        bool installGuard,
        bool installModule
    ) private view returns (bytes memory initializer) {
        address configTarget = address(0);
        bytes memory configData;
        if (installGuard || installModule) {
            configTarget = address(CONFIGURATOR);
            configData = abi.encodeWithSelector(
                SafeConfigurator.configure.selector,
                address(GUARD_CONTRACT),
                installGuard,
                address(INTERACT_CONTRACT),
                address(MODULE_CONTRACT),
                installModule
            );
        }
        return abi.encodeWithSelector(
            Safe.setup.selector, owners, threshold, configTarget, configData, fallbackHandler, address(0), 0, address(0)
        );
    }

    function _extensionPolicyInitializer(
        address[] calldata owners,
        uint256 threshold,
        address fallbackHandler,
        bool installGuard,
        OKModule.ExtensionPolicy modulePolicy,
        address[] calldata allowedModules,
        OKModule.ExtensionPolicy fallbackPolicy,
        address[] calldata allowedFallbackHandlers
    ) private view returns (bytes memory initializer) {
        bytes memory configData = abi.encodeWithSelector(
            SafeConfigurator.configureWithExtensionPolicy.selector,
            address(GUARD_CONTRACT),
            installGuard,
            address(INTERACT_CONTRACT),
            address(MODULE_CONTRACT),
            true,
            modulePolicy,
            allowedModules,
            fallbackPolicy,
            allowedFallbackHandlers
        );
        return abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            threshold,
            address(CONFIGURATOR),
            configData,
            fallbackHandler,
            address(0),
            0,
            address(0)
        );
    }

    function _fundSafe(address safe) private {
        if (msg.value == 0) return;
        // The private helper sends only this call msg.value to its newly deployed, runtime-checked Safe; callers
        // are nonReentrant.
        // forge-lint: disable-next-line(arbitrary-send-eth)
        (bool success,) = payable(safe).call{value: msg.value}("");
        require(success, "Safe funding failed");
    }

    /// @dev Deploy and initialize atomically from the tenant factory. The initializer
    ///      hash is part of the salt, so the same user salt cannot alias another owner
    ///      or extension configuration. The configured proxy factory supplies the exact
    ///      release bytecode, while this factory supplies the isolated CREATE2 namespace.
    ///      Runtime mismatches and initializer failures revert the entire deployment.
    function _deployProxy(bytes32 salt, bytes memory initializer) private returns (address proxyAddress) {
        bytes memory proxyInitCode = _proxyInitCode();
        bytes32 saltedNonce = _proxySalt(salt, initializer);
        assembly ("memory-safe") {
            proxyAddress := create2(0, add(proxyInitCode, 0x20), mload(proxyInitCode), saltedNonce)
        }
        if (proxyAddress == address(0)) revert SafeProxyDeploymentFailed();
        bytes32 actualRuntimeCodehash = proxyAddress.codehash;
        if (actualRuntimeCodehash != SAFE_PROXY_RUNTIME_CODEHASH) {
            revert SafeProxyRuntimeNotApproved(proxyAddress, SAFE_PROXY_RUNTIME_CODEHASH, actualRuntimeCodehash);
        }
        (bool success, bytes memory reason) = proxyAddress.call(initializer);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(reason, 0x20), mload(reason))
            }
        }
    }

    function _computeProxyAddress(bytes32 salt, bytes memory initializer) private view returns (address) {
        bytes memory proxyInitCode = _proxyInitCode();
        bytes32 initCodeHash;
        assembly ("memory-safe") {
            initCodeHash := keccak256(add(proxyInitCode, 0x20), mload(proxyInitCode))
        }

        bytes32 saltedNonce = _proxySalt(salt, initializer);
        address proxyFactoryAddress = address(this);
        bytes32 create2Hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0xff)
            mstore(add(ptr, 1), shl(96, proxyFactoryAddress))
            mstore(add(ptr, 21), saltedNonce)
            mstore(add(ptr, 53), initCodeHash)
            create2Hash := keccak256(ptr, 85)
        }

        return address(uint160(uint256(create2Hash)));
    }

    function _proxySalt(bytes32 salt, bytes memory initializer) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(initializer), salt));
    }

    function _proxyInitCode() private view returns (bytes memory) {
        return abi.encodePacked(_proxyCreationCode(address(PROXY_FACTORY)), uint256(uint160(SAFE_SINGLETON)));
    }

    function _requireStrictSafeExtensions(address safe, bool okModuleAllowed, bool requireExecutionModule)
        private
        view
    {
        Safe targetSafe = Safe(payable(safe));
        address executionModule_ = address(INTERACT_CONTRACT);
        bool executionModuleFound = false;
        address start = SENTINEL_MODULES;
        for (uint256 page; page < MODULE_PAGE_LIMIT; ++page) {
            // Module pagination is bounded by MODULE_PAGE_LIMIT and uses STATICCALL; every returned module must be
            // checked.
            // forge-lint: disable-next-line(calls-loop)
            (address[] memory modules, address next) = targetSafe.getModulesPaginated(start, MODULE_PAGE_SIZE);
            for (uint256 i; i < modules.length; ++i) {
                address module = modules[i];
                if (module == executionModule_) {
                    executionModuleFound = true;
                    continue;
                }
                if (okModuleAllowed && module == address(MODULE_CONTRACT)) {
                    continue;
                }
                // Adoption requires every installed module to be approved; incomplete pagination must fail closed.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert SafeModuleNotAllowed(safe, module);
            }
            if (next == SENTINEL_MODULES) {
                break;
            }
            // Safe versions before 1.4 return the first unreturned module as
            // `next`, while newer versions return the last returned module.
            // The last returned module is an exclusive cursor for both.
            if (modules.length == 0) {
                // Adoption requires every installed module to be approved; incomplete pagination must fail closed.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert SafeModulePaginationLimit(safe);
            }
            start = modules[modules.length - 1];
            if (page + 1 == MODULE_PAGE_LIMIT) {
                // Adoption requires every installed module to be approved; incomplete pagination must fail closed.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert SafeModulePaginationLimit(safe);
            }
        }

        if (requireExecutionModule && !executionModuleFound) {
            revert SafeExecutionModuleMissing(safe, executionModule_);
        }

        address handler = _fallbackHandler(targetSafe);
        if (handler != address(0)) {
            revert SafeFallbackHandlerNotAllowed(safe, handler);
        }

        address moduleGuard = _safeStorageAddress(targetSafe, MODULE_GUARD_STORAGE_SLOT);
        if (moduleGuard != address(0)) {
            revert OKModule.ModuleGuardNotAllowed(safe, moduleGuard);
        }
    }

    function _requireSafeSingleOwnerThreshold(address safe) private view {
        Safe targetSafe = Safe(payable(safe));
        _requireSingleOwnerThreshold(safe, targetSafe.getOwners().length, targetSafe.getThreshold());
    }

    function _requireSingleOwnerThreshold(address safe, uint256 ownerCount, uint256 threshold) private pure {
        if (ownerCount != 1 || threshold != 1) {
            revert SafeOwnerConfigNotAllowed(safe, ownerCount, threshold);
        }
    }

    function _requireGuardRequested(bool installGuard) private pure {
        if (!installGuard) {
            revert SafeGuardRequired();
        }
    }

    function _requireFallbackPolicyAllows(
        address safe,
        address handler,
        OKModule.ExtensionPolicy fallbackPolicy,
        address[] calldata allowedFallbackHandlers
    ) private pure {
        if (handler == address(0) || fallbackPolicy == OKModule.ExtensionPolicy.Permissive) {
            return;
        }
        if (fallbackPolicy == OKModule.ExtensionPolicy.Allowlist) {
            for (uint256 i; i < allowedFallbackHandlers.length; ++i) {
                if (allowedFallbackHandlers[i] == handler) {
                    return;
                }
            }
        }
        revert SafeFallbackHandlerNotAllowed(safe, handler);
    }

    function _fallbackHandler(Safe targetSafe) private view returns (address handler) {
        return _safeStorageAddress(targetSafe, FALLBACK_HANDLER_STORAGE_SLOT);
    }

    function _safeStorageAddress(Safe targetSafe, bytes32 slot) private view returns (address value_) {
        bytes memory value = targetSafe.getStorageAt(uint256(slot), 1);
        value_ = abi.decode(value, (address));
    }

    /// @dev Record the Safe in the registry allowlist and optionally in the local
    ///      deployment index used by pagination UIs.
    function _recordSafe(address safe, address guard, address module) private {
        _requireAuthenticSafe(safe);
        IRegistrySafes registrySafes = IRegistrySafes(address(INTERACT_CONTRACT.registry()));
        _factorySafes[safe] = true;
        if (!registrySafes.isSafeAllowed(safe)) {
            registrySafes.addSafe(safe);
        }
        // A timelocked Registry write may return after merely queueing the
        // admission. Never return a funded, factory-managed Safe that Interact
        // still rejects; reverting also rolls back deployment/import funding.
        if (!registrySafes.isSafeAllowed(safe)) revert SafeRegistryAdmissionPending(safe);
        if (!INDEXING_ENABLED) return;
        bytes32 key = _safeKey(safe);
        SafeDeployment storage record = _safeRecords[safe];
        if (_safes.contains(key)) {
            if (record.safe == address(0)) {
                record.safe = safe;
            }
            if (guard != address(0)) {
                record.guard = guard;
            }
            if (module != address(0)) {
                record.module = module;
            }
            return;
        }
        _safes.insert(key);
        _safeRecords[safe] = SafeDeployment({
            safe: safe,
            guard: guard,
            module: module,
            blockNumber: SafeCast.toUint64(block.number),
            timestamp: SafeCast.toUint64(block.timestamp)
        });
    }

    function _requireAuthenticSafe(address safe) private view {
        bytes32 actualProxyCodehash = safe.codehash;
        if (!_approvedSafeProxyRuntimeCodehash[actualProxyCodehash]) {
            revert SafeProxyRuntimeNotApproved(safe, SAFE_PROXY_RUNTIME_CODEHASH, actualProxyCodehash);
        }

        address actualSingleton = IProxy(safe).masterCopy();
        bytes32 expectedCodehash = _approvedSafeSingletonCodehash[actualSingleton];
        bytes32 expectedVersionHash = _approvedSafeSingletonVersionHash[actualSingleton];
        if (expectedCodehash == bytes32(0)) {
            revert SafeSingletonNotApproved(safe, SAFE_SINGLETON, actualSingleton);
        }

        bytes32 actualSingletonCodehash = actualSingleton.codehash;
        if (actualSingletonCodehash != expectedCodehash) {
            revert SafeSingletonCodehashMismatch(actualSingleton, expectedCodehash, actualSingletonCodehash);
        }

        bytes32 actualVersionHash = keccak256(bytes(Safe(payable(safe)).VERSION()));
        if (actualVersionHash != expectedVersionHash) {
            revert SafeVersionMismatch(safe, expectedVersionHash, actualVersionHash);
        }
    }

    function _requireSafeSingleton(address singleton) private view returns (bytes32 codehash_, bytes32 versionHash) {
        if (!Delegation7702.hasContractCode(singleton)) revert SafeInfrastructureInvalid(singleton);
        codehash_ = singleton.codehash;
        try Safe(payable(singleton)).VERSION() returns (string memory version) {
            versionHash = keccak256(bytes(version));
        } catch {
            revert SafeInfrastructureInvalid(singleton);
        }
        if (!_isApprovedSafeVersion(versionHash)) {
            revert SafeSingletonVersionNotApproved(singleton, versionHash);
        }
    }

    function _requireSafeSingletonMigrator(address migrator) private view {
        if (!Delegation7702.hasContractCode(migrator)) revert SafeSingletonMigratorInvalid(migrator);
        try SafeSingletonMigrator(migrator).chainwallComponentId() returns (bytes32 componentId) {
            if (componentId != SAFE_SINGLETON_MIGRATOR_COMPONENT_ID) revert SafeSingletonMigratorInvalid(migrator);
        } catch {
            revert SafeSingletonMigratorInvalid(migrator);
        }
        try SafeSingletonMigrator(migrator).INTERACT() returns (address interact) {
            if (interact != address(INTERACT_CONTRACT)) revert SafeSingletonMigratorInvalid(migrator);
        } catch {
            revert SafeSingletonMigratorInvalid(migrator);
        }
        try SafeSingletonMigrator(migrator).SAFE_FACTORY() returns (address safeFactory) {
            if (safeFactory != address(this)) revert SafeSingletonMigratorInvalid(migrator);
        } catch {
            revert SafeSingletonMigratorInvalid(migrator);
        }
    }

    function _requireConfigurator(address configurator) private view {
        if (!Delegation7702.hasContractCode(configurator)) revert SafeConfiguratorInvalid(configurator);
        try SafeConfigurator(configurator).chainwallComponentId() returns (bytes32 componentId) {
            if (componentId != SAFE_CONFIGURATOR_COMPONENT_ID) revert SafeConfiguratorInvalid(configurator);
        } catch {
            revert SafeConfiguratorInvalid(configurator);
        }
    }

    function _proxyCreationCode(address proxyFactory) private view returns (bytes memory creationCode) {
        bytes32 expectedFactoryCodehash = SAFE_PROXY_FACTORY_CODEHASH;
        bytes32 expectedCreationCodehash = SAFE_PROXY_CREATION_CODEHASH;
        bytes32 actualFactoryCodehash = proxyFactory.codehash;
        if (actualFactoryCodehash != expectedFactoryCodehash) {
            revert SafeProxyFactoryCodehashMismatch(proxyFactory, expectedFactoryCodehash, actualFactoryCodehash);
        }
        creationCode = _proxyCreationCodeUnchecked(proxyFactory);
        bytes32 actualCreationCodehash = keccak256(creationCode);
        if (actualCreationCodehash != expectedCreationCodehash) {
            revert SafeProxyCreationCodehashMismatch(proxyFactory, expectedCreationCodehash, actualCreationCodehash);
        }
    }

    function _proxyCreationCodeUnchecked(address proxyFactory) private pure returns (bytes memory creationCode) {
        try SafeProxyFactory(proxyFactory).proxyCreationCode() returns (bytes memory value) {
            if (value.length == 0) revert SafeInfrastructureInvalid(proxyFactory);
            return value;
        } catch {
            revert SafeInfrastructureInvalid(proxyFactory);
        }
    }

    function _resolveSafeProxyRuntimeCodehash(bytes memory proxyCreationCode, address singleton)
        private
        returns (bytes32)
    {
        try SafeComponentsFactory(COMPONENT_FACTORY).probeSafeProxyRuntimeCodehash(proxyCreationCode, singleton) {
            revert SafeInfrastructureInvalid(address(PROXY_FACTORY));
        } catch (bytes memory reason) {
            if (reason.length != 36) revert SafeInfrastructureInvalid(address(PROXY_FACTORY));
            bytes4 selector;
            bytes32 codehash;
            assembly ("memory-safe") {
                selector := mload(add(reason, 0x20))
                codehash := mload(add(reason, 0x24))
            }
            if (selector != SafeComponentsFactory.SafeProxyRuntimeCodehashResult.selector || codehash == bytes32(0)) {
                revert SafeInfrastructureInvalid(address(PROXY_FACTORY));
            }
            return codehash;
        }
    }

    function _isApprovedSafeVersion(bytes32 versionHash) private pure returns (bool) {
        return
            versionHash == keccak256("1.3.0") || versionHash == keccak256("1.4.1") || versionHash == keccak256("1.5.0");
    }

    /// @dev Restrict deployment and import flows to allowlisted tenant users.
    function _requireUser() private view {
        address registry = address(INTERACT_CONTRACT.registry());
        if (!IRegistryUsers(registry).isUser(msg.sender)) {
            revert CallerNotUser();
        }
    }
}
