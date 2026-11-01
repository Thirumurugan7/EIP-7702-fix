// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ChainwallUUPSUpgradeable} from "./ChainwallUpgradeable.sol";
import {EntityFlags} from "./EntityFlags.sol";
import {ProtocolCodehashes} from "./ProtocolCodehashes.sol";
import {RegistryPauseModule} from "./RegistryPauseModule.sol";
import {CapabilitiesLib, CapabilityIds} from "./registry/Capabilities.sol";
import {ContractsStorage, ExecutionCatalogStorage} from "./registry/RegistryShared.sol";
import {ExecutionContextLib} from "./registry/TimelockLib.sol";
import {TimelockLib, TimelockRequest} from "./registry/TimelockLib.sol";
import {DiamondAdminStorage} from "./registry/diamond/DiamondAdminStorage.sol";
import {DiamondLoupeStorage} from "./registry/diamond/DiamondLoupeStorage.sol";
import {DiamondSelectors} from "./registry/diamond/DiamondSelectors.sol";
import {IDiamondCut} from "./registry/facets/DiamondCutFacet.sol";
import {IDiamondLoupeExtended} from "./registry/facets/DiamondLoupeFacet.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

interface IDiamondBootstrapValidator {
    function validateBootstrapSelector(bytes4 selector) external pure;
    function emitInitialDiamondCut() external;
}

/**
 * @title OKcontract RegistryDiamond (Dispatcher)
 * @notice Upgradeable registry front door that dispatches calls to facet modules while preserving one shared state.
 * @dev `RegistryDiamond` is the contract operators and clients talk to directly.
 *      It combines a diamond-style selector table with Chainwall-specific behavior:
 *      - hot-path reads for addresses, typed metadata, and price data
 *      - timelock-aware facet administration
 *      - role-aware execution context so timelock replays still see the logical actor
 *
 *      Built-in timelock categories have code-defined zero-delay, no-policy defaults until governance configures them.
 *      Unknown category ids fail closed, while known categories remain easy to prepare during deployment.
 *
 *      Example:
 *      1. `OKFactory` deploys a `RegistryDiamond` proxy for one tenant.
 *      2. `OKFactoryConfig` installs the core and feature facets.
 *      3. Admins manage users, contracts, policies, terms, and timelocks through
 *         the facet selectors exposed here.
 *      4. `Interact`, `MiniScript`, Safe tooling, and off-chain clients all query
 *         the same registry address for the approved world state.
 */
contract RegistryDiamond is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    Ownable2StepUpgradeable,
    ChainwallUUPSUpgradeable
{
    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.Registry");
    RegistryPauseModule public immutable PAUSE_MODULE;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    error NoAddressFound();
    error FacetZeroAddress();
    error FacetNoCode();
    error FacetCodehashChanged(address facet, bytes32 expected, bytes32 actual);
    error FacetRoutingMismatch(bytes4 selector, address dispatcherFacet, address loupeFacet);
    error FacetRouteNotEnumerable(bytes4 selector, address facet);
    error FacetSelfAddress();
    error RegistryUpgradeDataNotEmpty();
    error DirectSelectorProtected(bytes4 selector);
    error InitialDiamondCutEventFailed();
    error OwnershipHandoverAlreadyCompleted();
    error OwnershipHandoverSameOwner(address owner);
    error HandoverRoleMissing(bytes32 role, address account);
    error HandoverRoleRetained(bytes32 role, address account);
    error NoFacet();
    error SelectorNotSet(bytes4 selector);
    error CoreFacetsAlreadyInstalled();
    error RegistryPauseModuleInvalid(address module, bytes32 codehash);

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 internal constant DIAMOND_SCOPE = keccak256("diamond.cut");
    bytes32 internal constant ROLE_GRANT_SCOPE_PREFIX = keccak256("role.admin.grant");
    bytes32 internal constant ROLE_REVOKE_SCOPE_PREFIX = keccak256("role.admin.revoke");

    mapping(bytes4 => address) private _facets;

    /// @notice Emitted when a dispatcher selector is mapped to a facet implementation.
    event FacetSet(bytes4 indexed selector, address indexed facet);
    /// @notice Emitted when facet cuts are permanently disabled for this registry.
    event CutsFrozen();
    /// @notice Emitted when governed role grants/revokes begin requiring admin capabilities and timelock flow.
    event RoleGovernanceEnabled(address indexed operator);
    /// @notice Emitted after the deployment factory atomically hands ownership to the staged tenant.
    event OwnershipHandoverCompleted(address indexed previousOwner, address indexed newOwner);

    error CutsFrozenError();
    error BootstrapFacetChangeMustBeImmediate();
    error CoreSelectorProtected(bytes4 selector);
    error SelfCallBlocked();
    error MulticallFailed();
    error OwnerBootstrapNotFinalized();

    /// @dev Lock the shared UUPS implementation. Tenant proxies initialize through
    ///      `initialize`, but the implementation itself must never acquire owner,
    ///      role, or fallback-routing state.
    constructor() {
        PAUSE_MODULE = new RegistryPauseModule();
        _disableInitializers();
    }

    function _checkAdmin() internal view {
        if (msg.sender == address(this)) {
            DiamondAdminStorage.Layout storage admin = DiamondAdminStorage.state();
            if (admin.selfCallDepth == 0) {
                // Permit explicit self-calls only when the logical actor holds ADMIN_ROLE.
                address actor = ExecutionContextLib.actorOrSender();
                if (!hasRole(ADMIN_ROLE, actor)) revert SelfCallBlocked();
            }
        } else {
            _checkRole(ADMIN_ROLE, msg.sender);
        }
    }

    function _requireCutsOpen() private view {
        if (DiamondAdminStorage.state().cutsFrozen) revert CutsFrozenError();
    }

    function _requireAlignedOwnershipHandover(address previousOwner, address newOwner) private view {
        if (newOwner == address(0)) revert OwnableInvalidOwner(address(0));
        // A handover flag is operational readiness evidence. Letting the owner
        // hand over to itself would make that evidence true without any authority
        // transition or recipient acceptance.
        if (previousOwner == newOwner) revert OwnershipHandoverSameOwner(previousOwner);
        if (!hasRole(ADMIN_ROLE, newOwner)) revert HandoverRoleMissing(ADMIN_ROLE, newOwner);
        if (!hasRole(UPGRADER_ROLE, newOwner)) revert HandoverRoleMissing(UPGRADER_ROLE, newOwner);
        if (hasRole(ADMIN_ROLE, previousOwner)) revert HandoverRoleRetained(ADMIN_ROLE, previousOwner);
        if (hasRole(UPGRADER_ROLE, previousOwner)) revert HandoverRoleRetained(UPGRADER_ROLE, previousOwner);
    }

    function _rejectBootstrapCoreSelector(bytes4 selector) private pure {
        if (DiamondSelectors.isCore(selector)) {
            // Every selector and facet must preserve the committed routing table; a partial update cannot be
            // accepted.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert CoreSelectorProtected(selector);
        }
    }

    function _fwd(bytes4 sel) private {
        if (paused()) {
            uint8 policy = PAUSE_MODULE.containmentPolicy(sel);
            if (policy == 0) revert EnforcedPause();
        }
        address facet = _facets[sel];
        if (facet == address(0)) revert NoFacet();
        DiamondLoupeStorage.Layout storage loupe = DiamondLoupeStorage.getLayout();
        address reportedFacet = loupe.selectorToFacet[sel];
        // Runtime dispatch and ERC-2535 introspection are one security boundary.
        // A disagreement must not leave a hidden live route that cuts validate
        // against different state.
        if (reportedFacet != facet) revert FacetRoutingMismatch(sel, facet, reportedFacet);
        if (!loupe.facetAddrs.contains(facet) || !loupe.selectorsOf[facet].contains(DiamondLoupeStorage._b32(sel))) {
            revert FacetRouteNotEnumerable(sel, facet);
        }
        bytes32 expected = loupe.codehashOf[facet];
        bytes32 actual = facet.codehash;
        // This pins the routed contract's runtime only. A facet that delegates
        // again can still inherit mutable behavior from another address, so such
        // transitive upgradeability is an explicit governance trust decision.
        if (expected == bytes32(0) || actual != expected) {
            revert FacetCodehashChanged(facet, expected, actual);
        }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            let size := returndatasize()
            returndatacopy(0, 0, size)
            switch result
            case 0 { revert(0, size) }
            default { return(0, size) }
        }
    }

    /// @notice Permanently route registry role grants/revokes through capabilities and the registry timelock.
    /// @dev This does not seed nonzero timelock delays. Fresh categories keep the protocol default of immediate
    ///      execution until the tenant configures category defaults or scope overrides.
    function enableRoleGovernance() external {
        _delegatePauseModule();
    }

    /// @notice Returns whether governed role grants/revokes are routed through admin capabilities and timelock.
    function roleGovernanceEnabled() external view returns (bool) {
        return DiamondAdminStorage.state().roleGovernanceEnabled;
    }

    /// @notice Complete the one-time deployment handover after role authority is transferred.
    /// @dev This is the sole exception to two-step ownership. It preserves atomic
    ///      CREATE2 factory deployment while proving that the staged owner already
    ///      holds both Registry admin roles, differs from the old owner, and the
    ///      old owner no longer holds either role.
    function completeOwnershipHandover(address newOwner) external whenNotPaused onlyOwner {
        DiamondAdminStorage.Layout storage admin = DiamondAdminStorage.state();
        if (admin.ownershipHandoverCompleted) revert OwnershipHandoverAlreadyCompleted();
        address previousOwner = owner();
        _requireAlignedOwnershipHandover(previousOwner, newOwner);
        admin.ownershipHandoverCompleted = true;
        _transferOwnership(newOwner);
        ExecutionCatalogStorage.bumpSemantics();
        // Ownership, routing, and timelock helpers update local storage; no mutable external call separates this
        // write and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OwnershipHandoverCompleted(previousOwner, newOwner);
    }

    /// @notice Start a two-step ownership transfer without splitting temporary
    ///         owner governance from Registry role authority.
    /// @dev Before owner bootstrap is finalized, both proposal and acceptance
    ///      revalidate the factory handover role invariant. Afterwards ownership
    ///      is non-authoritative metadata and normal two-step transfer is enough.
    function transferOwnership(address newOwner) public override whenNotPaused onlyOwner {
        DiamondAdminStorage.Layout storage admin = DiamondAdminStorage.state();
        if (newOwner != address(0) && (!admin.ownerBootstrapFinalized || !admin.ownershipHandoverCompleted)) {
            _requireAlignedOwnershipHandover(owner(), newOwner);
        }
        super.transferOwnership(newOwner);
        ExecutionCatalogStorage.bumpSemantics();
    }

    function acceptOwnership() public override whenNotPaused {
        DiamondAdminStorage.Layout storage admin = DiamondAdminStorage.state();
        address previousOwner = owner();
        address nextOwner = pendingOwner();
        // Any acceptance that would create handover-readiness evidence must
        // prove the aligned role transition, even if storage was migrated from
        // an inconsistent pre-hardening state.
        if (!admin.ownerBootstrapFinalized || !admin.ownershipHandoverCompleted) {
            _requireAlignedOwnershipHandover(previousOwner, nextOwner);
        }
        super.acceptOwnership();
        if (!admin.ownershipHandoverCompleted) {
            admin.ownershipHandoverCompleted = true;
            // Ownership, routing, and timelock helpers update local storage; no mutable external call separates
            // this write and event.
            // forge-lint: disable-next-line(reentrancy-events)
            emit OwnershipHandoverCompleted(previousOwner, nextOwner);
        }
        ExecutionCatalogStorage.bumpSemantics();
    }

    function renounceOwnership() public override {
        _delegatePauseModule();
    }

    /// @notice Renounce only the caller's role, recording the change for resume review.
    function renounceRole(bytes32 role, address callerConfirmation) public override {
        // Keep ABI names; the pause module consumes these arguments through msg.data.
        role;
        callerConfirmation;
        _delegatePauseModule();
    }

    /// @notice Grant a role using the active registry governance rules.
    /// @dev Before role governance is enabled this follows OpenZeppelin AccessControl. After it is enabled,
    ///      ADMIN_ROLE, UPGRADER_ROLE, and roles administered by ADMIN_ROLE require GRANT_ADMIN and pass through
    ///      the role-admin timelock category before `_grantRole` mutates state.
    function grantRole(bytes32 role, address account) public override(AccessControlUpgradeable) whenNotPaused {
        if (!_usesRoleGovernance(role)) {
            bool alreadyGranted = hasRole(role, account);
            super.grantRole(role, account);
            if (!alreadyGranted) ExecutionCatalogStorage.bumpSemantics();
            return;
        }
        address actor = _msgSender();
        _requireRoleGovernanceCapability(actor, CapabilityIds.GRANT_ADMIN);
        if (!_enforceRoleAdminTimelock(true, role, account)) {
            return;
        }
        _grantRole(role, account);
    }

    /// @notice Revoke a role using the active registry governance rules.
    /// @dev Before role governance is enabled this follows OpenZeppelin AccessControl. After it is enabled,
    ///      ADMIN_ROLE, UPGRADER_ROLE, and roles administered by ADMIN_ROLE require REVOKE_ADMIN and pass through
    ///      the role-admin timelock category before `_revokeRole` mutates state.
    function revokeRole(bytes32 role, address account) public override(AccessControlUpgradeable) whenNotPaused {
        if (!_usesRoleGovernance(role)) {
            bool wasGranted = hasRole(role, account);
            super.revokeRole(role, account);
            if (wasGranted) ExecutionCatalogStorage.bumpSemantics();
            return;
        }
        address actor = _msgSender();
        _requireRoleGovernanceCapability(actor, CapabilityIds.REVOKE_ADMIN);
        if (!_enforceRoleAdminTimelock(false, role, account)) {
            return;
        }
        _revokeRole(role, account);
    }

    // Facet admin
    /**
     * @notice Register or update a facet for a list of function selectors.
     * @dev Emits `FacetSet` for each selector. Selectors are keyed directly in the dispatcher mapping.
     * @param selectors Function selectors to dispatch.
     * @param facet Target facet contract (must support delegatecall).
     */
    function setFacets(bytes4[] calldata selectors, address facet) external whenNotPaused {
        _checkAdmin();
        _requireCutsOpen();
        bool internalCut = msg.sender == address(this) && DiamondAdminStorage.state().selfCallDepth > 0;
        if (!internalCut && _facets[IDiamondCut.diamondCut.selector] != address(0)) {
            revert CoreFacetsAlreadyInstalled();
        }
        if (!internalCut) {
            bool executing = _enforceDiamondTimelock(msg.data);
            if (!executing) revert BootstrapFacetChangeMustBeImmediate();
        }
        if (facet == address(0)) revert FacetZeroAddress();
        if (facet == address(this)) revert FacetSelfAddress();
        if (facet.code.length == 0) revert FacetNoCode();
        for (uint256 i = 0; i < selectors.length;) {
            bytes4 selector = selectors[i];
            // Direct implementation functions always win Solidity dispatch and must never appear in fallback
            // routing or loupe state. Core facet selectors may be replaced only through an internal strict cut.
            // Every selector and facet must preserve the committed routing table; a partial update cannot be
            // accepted.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (DiamondSelectors.isDirect(selector)) revert DirectSelectorProtected(selector);
            if (!internalCut) _rejectBootstrapCoreSelector(selector);
            unchecked {
                ++i;
            }
        }
        _routeSelectorsToFacet(facet, selectors);
        if (!internalCut) ExecutionCatalogStorage.bumpRuntime();
    }

    /**
     * @notice Remove a selector mapping from the dispatcher and loupe storage.
     */
    function removeFacet(bytes4 selector) external whenNotPaused {
        _checkAdmin();
        _requireCutsOpen();
        bool internalCut = msg.sender == address(this) && DiamondAdminStorage.state().selfCallDepth > 0;
        if (!internalCut && _facets[IDiamondCut.diamondCut.selector] != address(0)) {
            revert CoreFacetsAlreadyInstalled();
        }
        if (!internalCut) {
            bool executing = _enforceDiamondTimelock(msg.data);
            if (!executing) revert BootstrapFacetChangeMustBeImmediate();
        }
        // Core routing is mandatory and can only be replaced by a strict cut.
        _rejectBootstrapCoreSelector(selector);
        if (_facets[selector] == address(0)) revert SelectorNotSet(selector);
        _removeFacetFor(selector);
        if (!internalCut) ExecutionCatalogStorage.bumpRuntime();
    }

    /// @notice Permanently freeze facet cuts and block further diamondCut/init activity.
    /// @dev The irreversible transition uses the same diamond timelock as cuts
    ///      and upgrades, giving governance a review/cancellation window.
    function freezeCuts() external whenNotPaused {
        _checkAdmin();
        DiamondAdminStorage.Layout storage S = DiamondAdminStorage.state();
        if (S.cutsFrozen) revert CutsFrozenError();
        if (!_enforceDiamondTimelock(msg.data)) return;
        if (S.cutsFrozen) revert CutsFrozenError();
        S.cutsFrozen = true;
        // Ownership, routing, and timelock helpers update local storage; no mutable external call separates this
        // write and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit CutsFrozen();
    }

    /// @notice Install core facets required for ERC-2535: DiamondCut and DiamondLoupe.
    function installCoreFacets(address cutFacet, address loupeFacet) external whenNotPaused {
        _checkAdmin();
        _requireCutsOpen();
        if (_facets[IDiamondCut.diamondCut.selector] != address(0)) revert CoreFacetsAlreadyInstalled();
        bool executing = _enforceDiamondTimelock(msg.data);
        if (!executing) revert BootstrapFacetChangeMustBeImmediate();
        if (cutFacet == address(0) || loupeFacet == address(0)) revert FacetZeroAddress();
        if (cutFacet == address(this) || loupeFacet == address(this)) revert FacetSelfAddress();
        if (cutFacet.code.length == 0 || loupeFacet.code.length == 0) revert FacetNoCode();

        DiamondLoupeStorage.Layout storage loupe = DiamondLoupeStorage.getLayout();
        uint256 existingFacetCount = loupe.facetAddrs.length();
        for (uint256 i = 0; i < existingFacetCount;) {
            address existingFacet = loupe.facetAddrs.at(i);
            uint256 selectorCount = loupe.selectorsOf[existingFacet].length();
            for (uint256 j = 0; j < selectorCount;) {
                // Bootstrap validates each existing selector through a pure STATICCALL before installing the
                // admin-selected cut facet.
                // forge-lint: disable-start(calls-loop)
                IDiamondBootstrapValidator(cutFacet)
                    .validateBootstrapSelector(DiamondLoupeStorage._b4(loupe.selectorsOf[existingFacet].at(j)));
                // forge-lint: disable-end(calls-loop)
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        bytes4[] memory cutSels = new bytes4[](1);
        cutSels[0] = IDiamondCut.diamondCut.selector;
        for (uint256 i = 0; i < cutSels.length;) {
            _setFacetFor(cutSels[i], cutFacet);
            unchecked {
                ++i;
            }
        }
        bytes4[] memory loupeSels = new bytes4[](6);
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        loupeSels[0] = bytes4(keccak256("facets()"));
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        loupeSels[1] = bytes4(keccak256("facetFunctionSelectors(address)"));
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        loupeSels[2] = bytes4(keccak256("facetAddresses()"));
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        loupeSels[3] = bytes4(keccak256("facetAddress(bytes4)"));
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        loupeSels[4] = bytes4(keccak256("facetVersion(address)"));
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        loupeSels[5] = bytes4(keccak256("facetVersions()"));
        for (uint256 j = 0; j < loupeSels.length;) {
            _setFacetFor(loupeSels[j], loupeFacet);
            unchecked {
                ++j;
            }
        }
        // Admin-only one-time bootstrap installs this same cutFacet into routing; only its fixed initial-event
        // selector is called.
        // forge-lint: disable-next-line(controlled-delegatecall)
        (bool emitted,) = cutFacet.delegatecall(abi.encodeCall(IDiamondBootstrapValidator.emitInitialDiamondCut, ()));
        if (!emitted) revert InitialDiamondCutEventFailed();
        ExecutionCatalogStorage.bumpRuntime();
    }

    /// @notice Return the revision bound into interaction approvals and signatures.
    /// @dev The revision advances whenever governed state can alter script execution,
    ///      including catalog records, price configuration, facets, and runtime upgrades.
    function getExecutionCatalogVersion() external view returns (uint64) {
        return ExecutionCatalogStorage.version();
    }

    /// @notice Return the revision of shared runtime semantics bound by public interactions.
    function getExecutionRuntimeVersion() external view returns (uint64) {
        return ExecutionCatalogStorage.runtimeVersion();
    }

    /// @notice Return the live guard revision for one atomic interaction execution.
    function getExecutionSemanticsRevision() external view returns (uint64) {
        return ExecutionCatalogStorage.semanticsRevision();
    }

    // Minimal hot-path read; reverts if none
    function getAddressByHash(bytes32 h) external view returns (address) {
        address self = _selfAddressFromHash(h);
        if (self != address(0)) return self;
        address a = _activeLatestAddr(ContractsStorage.getLayout(), h);
        if (a != address(0)) return a;
        revert NoAddressFound();
    }

    /**
     * @notice Batch resolve latest addresses by precomputed keys.
     * @dev For each key, returns (address, ok) using only local storage.
     * @param hs Array of precomputed keys.
     * @return addrs Resolved addresses (zero when not found locally).
     * @return ok Array indicating whether an address was found.
     */
    function getAddressesByHash(bytes32[] calldata hs)
        external
        view
        returns (address[] memory addrs, bool[] memory ok)
    {
        ContractsStorage.Layout storage L = ContractsStorage.getLayout();
        uint256 n = hs.length;
        addrs = new address[](n);
        ok = new bool[](n);
        for (uint256 i = 0; i < n;) {
            address a = _selfAddressFromHash(hs[i]);
            if (a == address(0)) {
                a = _activeLatestAddr(L, hs[i]);
            }
            if (a != address(0)) {
                addrs[i] = a;
                ok[i] = true;
            }
            unchecked {
                ++i;
            }
        }
    }

    function _activeLatestAddr(ContractsStorage.Layout storage L, bytes32 h) private view returns (address) {
        if (EntityFlags.isInactive(L.flags[h])) return address(0);
        return ContractsStorage.latestAddr(L, h);
    }

    function _selfAddressFromHash(bytes32 h) private view returns (address) {
        if (uint256(h) == uint256(uint160(address(this)))) {
            return address(this);
        }
        return address(0);
    }

    /// @dev Applies the diamond category to facet cuts; immediate execution is allowed until configured otherwise.
    function _enforceDiamondTimelock(bytes calldata callDataBlob) private returns (bool executing) {
        (executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryDiamond(),
                scope: DIAMOND_SCOPE,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            callDataBlob
        );
    }

    /// @dev Returns true only after the one-way switch is enabled and the role is in the governed admin set.
    function _usesRoleGovernance(bytes32 role) private view returns (bool) {
        return DiamondAdminStorage.state().roleGovernanceEnabled && _isRegistryGovernedRole(role);
    }

    /// @dev Governed roles are the registry admin roles and any role whose admin is ADMIN_ROLE.
    function _isRegistryGovernedRole(bytes32 role) private view returns (bool) {
        return role == ADMIN_ROLE || role == UPGRADER_ROLE || getRoleAdmin(role) == ADMIN_ROLE;
    }

    /// @dev Role governance intentionally ignores ADMIN_ROLE alone; the narrow capability is required.
    function _requireRoleGovernanceCapability(address actor, bytes32 capability) private view {
        if (CapabilitiesLib.hasCapability(actor, capability)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, capability);
    }

    /// @dev Queues or executes one governed role mutation under the role-admin timelock category.
    function _enforceRoleAdminTimelock(bool grantOp, bytes32 role, address account) private returns (bool executing) {
        bytes memory payload = grantOp
            ? abi.encodeWithSelector(this.grantRole.selector, role, account)
            : abi.encodeWithSelector(this.revokeRole.selector, role, account);
        (executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryRoleAdmin(),
                scope: _roleAdminScope(grantOp, role, account),
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            payload
        );
    }

    /// @dev Scope is per operation type, role, and account so grants and revokes can be configured independently.
    function _roleAdminScope(bool grantOp, bytes32 role, address account) private pure returns (bytes32 result) {
        bytes32 prefix = grantOp ? ROLE_GRANT_SCOPE_PREFIX : ROLE_REVOKE_SCOPE_PREFIX;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, prefix)
            mstore(add(ptr, 0x20), role)
            mstore(add(ptr, 0x40), account)
            result := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60))
        }
    }

    /**
     * @notice Initializer for the diamond dispatcher.
     * @dev Sets up AccessControl (ADMIN_ROLE, UPGRADER_ROLE), Ownable owner, and Pausable.
     *      Dispatcher upgrades are expected to go through the timelock (`upgradeRegistry`), so
     *      production deployments should keep UPGRADER_ROLE only on governance/timelock.
     */
    function initialize() public whenNotPaused initializer {
        _initializeCommon();
    }

    function _initializeCommon() private {
        _requireCanonicalPauseModule(address(PAUSE_MODULE));
        __AccessControl_init();
        __Pausable_init();
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        _grantRole(ADMIN_ROLE, msg.sender);
        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
        _grantRole(UPGRADER_ROLE, msg.sender);
        _setRoleAdmin(UPGRADER_ROLE, ADMIN_ROLE);
        ExecutionCatalogStorage.initialize();
    }

    function _authorizeUpgrade(address) internal view virtual override {
        if (DiamondAdminStorage.state().cutsFrozen) {
            revert CutsFrozenError();
        }
        if (!ExecutionContextLib.isActive()) {
            revert AccessControlUnauthorizedAccount(_msgSender(), UPGRADER_ROLE);
        }
        ExecutionContextLib.ensure(TimelockLib.categoryDiamond(), DIAMOND_SCOPE);
        address actor = ExecutionContextLib.actorOrSender();
        if (!hasRole(UPGRADER_ROLE, actor)) {
            revert AccessControlUnauthorizedAccount(actor, UPGRADER_ROLE);
        }
    }

    /// @notice Registry UUPS entrypoint used only from the diamond-scoped timelock action.
    /// @dev Production v1 Registry upgrades are code-only. State changes require separate typed timelock actions;
    ///      accepting arbitrary delegatecall calldata here would let candidate code mutate uncommitted governance
    ///      storage while preserving the narrower compatibility binding.
    function upgradeToAndCall(address newImplementation, bytes memory data) public payable override whenNotPaused {
        if (data.length != 0) revert RegistryUpgradeDataNotEmpty();
        _upgradePreservingBindings(newImplementation, data);
        _requireFacetCodehashesCurrent();
    }

    function _chainwallSecurityBindingsHash() internal view override returns (bytes32) {
        _requireCanonicalPauseModule(address(PAUSE_MODULE));
        DiamondAdminStorage.Layout storage admin = DiamondAdminStorage.state();
        address currentOwner = owner();
        address nextOwner = pendingOwner();
        bytes32 ownershipHash = _hashSecurityBindings(
            abi.encode(
                currentOwner,
                nextOwner,
                paused(),
                admin.cutsFrozen,
                admin.roleGovernanceEnabled,
                admin.ownershipHandoverCompleted,
                admin.ownerBootstrapFinalized,
                admin.selfCallDepth
            )
        );
        bytes32 roleHash = _hashSecurityBindings(
            abi.encode(
                getRoleAdmin(ADMIN_ROLE),
                getRoleAdmin(UPGRADER_ROLE),
                hasRole(ADMIN_ROLE, currentOwner),
                hasRole(UPGRADER_ROLE, currentOwner)
            )
        );
        bytes32 governorHash = _hashSecurityBindings(
            abi.encode(
                CapabilitiesLib.capabilityGroups(CapabilityIds.TIMELOCK_GOVERNOR),
                CapabilitiesLib.capabilityActors(CapabilityIds.TIMELOCK_GOVERNOR)
            )
        );
        return _hashSecurityBindings(abi.encode(ownershipHash, roleHash, governorHash, _facetRoutingBindingsHash()));
    }

    /// @dev Commit dispatcher/loupe mappings and the exact stored facet codehashes. Production v1 has no migration
    ///      exception that may initialize or rewrite a commitment during an implementation transition.
    function _facetRoutingBindingsHash() private view returns (bytes32 routingHash) {
        DiamondLoupeStorage.Layout storage loupe = DiamondLoupeStorage.getLayout();
        uint256 facetCount = loupe.facetAddrs.length();
        for (uint256 i; i < facetCount; ++i) {
            address facet = loupe.facetAddrs.at(i);
            bytes32 committedCodehash = loupe.codehashOf[facet];
            bytes32 selectorsHash = bytes32(0);
            uint256 selectorCount = loupe.selectorsOf[facet].length();
            for (uint256 j; j < selectorCount; ++j) {
                bytes4 selector = DiamondLoupeStorage._b4(loupe.selectorsOf[facet].at(j));
                selectorsHash = _hashSecurityBindings(
                    abi.encode(selectorsHash, selector, _facets[selector], loupe.selectorToFacet[selector])
                );
            }
            routingHash = _hashSecurityBindings(abi.encode(routingHash, facet, committedCodehash, selectorsHash));
        }
    }

    function _requireFacetCodehashesCurrent() private view {
        DiamondLoupeStorage.Layout storage loupe = DiamondLoupeStorage.getLayout();
        uint256 facetCount = loupe.facetAddrs.length();
        for (uint256 i; i < facetCount; ++i) {
            address facet = loupe.facetAddrs.at(i);
            bytes32 expected = loupe.codehashOf[facet];
            bytes32 actual = facet.codehash;
            if (expected == bytes32(0) || expected != actual) {
                // Every selector and facet must preserve the committed routing table; a partial update cannot be
                // accepted.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert FacetCodehashChanged(facet, expected, actual);
            }
            uint256 selectorCount = loupe.selectorsOf[facet].length();
            for (uint256 j; j < selectorCount; ++j) {
                bytes4 selector = DiamondLoupeStorage._b4(loupe.selectorsOf[facet].at(j));
                address dispatcherFacet = _facets[selector];
                address reportedFacet = loupe.selectorToFacet[selector];
                if (dispatcherFacet != facet || reportedFacet != facet) {
                    // Every selector and facet must preserve the committed routing table; a partial update cannot
                    // be accepted.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert FacetRoutingMismatch(selector, dispatcherFacet, reportedFacet);
                }
            }
        }
    }

    function chainwallComponentId() external pure override returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @notice Contain ordinary Registry writes while preserving authorized cancellation and cleanup.
    function pause() external {
        _delegatePauseModule();
    }

    /// @notice Unpause the registry.
    function unpause() external {
        _delegatePauseModule();
    }

    /// @notice Batch calls with the same caller and execution context. Each nested call rechecks containment.
    function multicall(bytes[] calldata calls) external returns (bytes[] memory results) {
        // Keep ABI names; forwarding passes calldata and returns the module's encoded results.
        calls;
        results;
        _delegatePauseModule();
    }

    /// @dev Terminal forwarding for direct stubs; do not place cleanup after this call.
    function _delegatePauseModule() private {
        RegistryPauseModule module = PAUSE_MODULE;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            let ok := delegatecall(gas(), module, ptr, calldatasize(), 0, 0)
            let size := returndatasize()
            returndatacopy(ptr, 0, size)
            if iszero(ok) { revert(ptr, size) }
            return(ptr, size)
        }
    }

    /// @dev Parent runtime comparison masks immutable addresses. Authenticate the
    ///      constructor-created delegatecall target when an implementation is admitted,
    ///      rather than paying this check on each pause or unpause operation.
    function _requireCanonicalPauseModule(address module) private view {
        bytes32 codehash = module.codehash;
        if (!ProtocolCodehashes.isAcceptedRegistryPauseModuleCodehash(codehash)) {
            revert RegistryPauseModuleInvalid(module, codehash);
        }
    }

    fallback() external {
        _fwd(msg.sig);
    }

    /// @dev ERC-165 reporting for EIP-2535 interfaces and inherited interfaces.
    function supportsInterface(bytes4 interfaceId) public view override(AccessControlUpgradeable) returns (bool) {
        // ERC165
        if (interfaceId == 0x01ffc9a7) return true;
        // IDiamondCut (single function: diamondCut)
        if (interfaceId == 0x1f931c1c) return true;
        // IDiamondLoupe (4 view fns)
        if (interfaceId == 0x48e2b093) return true;
        // Extended loupe (facetVersion + facetVersions)
        if (interfaceId == type(IDiamondLoupeExtended).interfaceId) return true;
        return super.supportsInterface(interfaceId);
    }

    // Forwarder stubs removed to minimize code size; calls route via fallback using function selectors.

    /// @dev Override OZ Context to honor timelock execution context.
    function _msgSender() internal view override(ContextUpgradeable) returns (address) {
        return ExecutionContextLib.actorOrSender();
    }

    // Internal helpers to keep loupe storage in sync.
    function _setFacetFor(bytes4 selector, address facet) internal {
        DiamondLoupeStorage.Layout storage L = DiamondLoupeStorage.getLayout();
        bytes32 actualCodehash = facet.codehash;
        // Every selector and facet must preserve the committed routing table; a partial update cannot be accepted.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (actualCodehash == bytes32(0)) revert FacetNoCode();
        bytes32 approvedCodehash = L.codehashOf[facet];
        if (approvedCodehash != bytes32(0) && approvedCodehash != actualCodehash) {
            // Every selector and facet must preserve the committed routing table; a partial update cannot be
            // accepted.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert FacetCodehashChanged(facet, approvedCodehash, actualCodehash);
        }
        if (approvedCodehash == bytes32(0)) L.codehashOf[facet] = actualCodehash;
        address prev = L.selectorToFacet[selector];
        address mapped = _facets[selector];
        // An Add may repair missing loupe metadata only when it preserves the
        // already-live dispatcher target. Otherwise a nominal Add could replace
        // runtime behavior after the two maps diverged.
        if (mapped != prev && !(prev == address(0) && mapped == facet)) {
            // Every selector and facet must preserve the committed routing table; a partial update cannot be
            // accepted.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert FacetRoutingMismatch(selector, mapped, prev);
        }
        if (prev == facet) {
            // Heal loupe sets in case they were missing from early installs
            _facets[selector] = facet;
            L.selectorToFacet[selector] = facet;
            bytes32 sel32 = DiamondLoupeStorage._b32(selector);
            if (!L.selectorsOf[facet].contains(sel32)) {
                L.selectorsOf[facet].add(sel32);
            }
            if (!L.facetAddrs.contains(facet)) {
                L.facetAddrs.add(facet);
            }
            // Ownership, routing, and timelock helpers update local storage; no mutable external call separates
            // this write and event.
            // forge-lint: disable-next-line(reentrancy-events)
            emit FacetSet(selector, facet);
            return;
        }
        if (prev != address(0)) {
            // remove from previous facet index
            L.selectorsOf[prev].remove(DiamondLoupeStorage._b32(selector));
            if (L.selectorsOf[prev].length() == 0) {
                L.facetAddrs.remove(prev);
                delete L.codehashOf[prev];
            }
        }
        _facets[selector] = facet;
        L.selectorToFacet[selector] = facet;
        L.selectorsOf[facet].add(DiamondLoupeStorage._b32(selector));
        L.facetAddrs.add(facet);
        // Ownership, routing, and timelock helpers update local storage; no mutable external call separates this
        // write and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit FacetSet(selector, facet);
    }

    function _removeFacetFor(bytes4 selector) internal {
        DiamondLoupeStorage.Layout storage L = DiamondLoupeStorage.getLayout();
        address prev = L.selectorToFacet[selector];
        address mapped = _facets[selector];
        if (prev == address(0) && mapped == address(0)) revert SelectorNotSet(selector);
        if (prev != mapped) revert FacetRoutingMismatch(selector, mapped, prev);
        // Clear dispatcher mapping
        _facets[selector] = address(0);
        // Update loupe storage
        if (prev != address(0)) {
            delete L.selectorToFacet[selector];
            bytes32 s32 = DiamondLoupeStorage._b32(selector);
            if (L.selectorsOf[prev].contains(s32)) {
                L.selectorsOf[prev].remove(s32);
            }
            if (L.selectorsOf[prev].length() == 0) {
                L.facetAddrs.remove(prev);
                delete L.codehashOf[prev];
            }
        }
        // Ownership, routing, and timelock helpers update local storage; no mutable external call separates this
        // write and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit FacetSet(selector, address(0));
    }

    function _routeSelectorsToFacet(address facet, bytes4[] calldata selectors) internal {
        for (uint256 i = 0; i < selectors.length;) {
            _setFacetFor(selectors[i], facet);
            unchecked {
                ++i;
            }
        }
    }
}
