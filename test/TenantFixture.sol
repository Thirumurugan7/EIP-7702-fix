// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {
    ContractAddress,
    ERCToken,
    InteractionBundleInput,
    LinkedArtifactInput
} from "@chainwall/interfaces/RegistryTypes.sol";

import {ChainwallDeployer} from "./ChainwallDeployer.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

interface IRegistryView {
    function owner() external view returns (address);
    function paused() external view returns (bool);
    function hasRole(bytes32 role, address account) external view returns (bool);
    function ADMIN_ROLE() external view returns (bytes32);
    function UPGRADER_ROLE() external view returns (bytes32);
    function acceptTerms(bytes32 documentHash) external;
    function instanceHasAcceptedInitialTerms() external view returns (bool);
    function getTermsContext() external view returns (address factory, TermsDoc memory initialTerms);
}

/// @dev Same layout as `TermsDocument` in packages/interfaces/src/TermsTypes.sol.
struct TermsDoc {
    string ipfsUri;
    bytes32 documentHash;
}

interface IRegistryAdmin {
    function addUser(address user) external;
    function isUser(address user) external view returns (bool);
    function createGroup(bytes32 groupId) external returns (bytes32);
    function addGroupMember(bytes32 groupHash, address user) external;
    function grantCapabilityGroup(bytes32 capability, bytes32 groupHash) external;
    function grantCapabilityActor(bytes32 capability, address actor) external;
    function createPolicy(bytes32 policyId, bytes32[] calldata groupIds, uint256[] calldata thresholds) external;
    function upsertOrg(string calldata id, address owner_, bool rugged, address[] calldata initialMembers) external;
    function addContractVersion(string calldata org, string calldata id, ContractAddress calldata a, bytes32 label)
        external;
    function getInteractionBundleHash(bytes32 baseId) external view returns (bytes32);
    function upsertInteractionBundle(bytes32 expectedCurrentBundleHash, InteractionBundleInput calldata bundle)
        external;
    function isAccountAllowed(address account) external view returns (bool);
    function allowDelegate(address delegate) external;
    function disallowDelegate(address delegate) external;
    function isDelegateAllowed(address delegate) external view returns (bool);
    function getAllowedDelegateCount() external view returns (uint256);
    function getAllowedDelegateAt(uint256 index) external view returns (address delegate, bytes32 codehash);
    function delegateOf(address account) external view returns (address);
    function isActorUsable(address actor) external view returns (bool);
    function isGroupMemberByHash(bytes32 groupHash, address user) external view returns (bool);
    function hasCapability(bytes32 capability, address actor) external view returns (bool);

    // pause
    function pause() external;
    function unpause() external;
    function paused() external view returns (bool);
    function requireActorUsable(address actor) external view;

    // roles
    function hasRole(bytes32 role, address account) external view returns (bool);
    function grantRole(bytes32 role, address account) external;
    function revokeRole(bytes32 role, address account) external;

    // timelock
    function setCategoryConfig(bytes32 category, TimelockCategoryConfig calldata cfg) external;
    function getPendingActionIds(uint256 start, uint256 count) external view returns (bytes32[] memory);
    function approveAction(bytes32 actionId) external returns (bool);
    function executeAction(bytes32 actionId) external returns (bytes memory);

    // private commit / reveal
    function setOrgCatalogDelegationEnabled(bool enabled) external;
    function getAddress(string calldata org, string calldata id) external view returns (address);
    function commitContractPrivate(
        string calldata org,
        string calldata id,
        bytes32 commitHash,
        uint64 deadline,
        address forwarder,
        bytes32 hint
    ) external;
    function revealContractCommit(
        string calldata org,
        string calldata id,
        ContractAddress calldata addrData,
        bytes32 label,
        bytes32 salt,
        bytes calldata actorSignature
    ) external;
    function commitTokenPrivate(
        string calldata org,
        string calldata id,
        bytes32 commitHash,
        uint64 deadline,
        address forwarder,
        bytes32 hint
    ) external;
    function revealTokenCommit(ERCToken calldata data, uint256 flags, bytes32 salt, bytes calldata actorSignature)
        external;
    function commitInteractionPrivate(bytes32 id, bytes32 commitHash, uint64 deadline, address forwarder, bytes32 hint)
        external;
    function setPolicyProgram(bytes32 policyId, bytes calldata program, uint32 maxSteps) external;
    // governed upgrades
    function upgradeInteract(address target, address newImplementation, bytes calldata data) external returns (bytes32);
    function upgradeMiniScript(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32);
    function upgradeAccountFactory(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32);
    function upgradeOkAccount(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32);
    function setAccountImplementation(address factory, address newImplementation) external returns (bytes32);
    function setTimelockPolicyRunner(address runner) external;
    function getTimelockPolicyRunner() external view returns (address);
    function facetAddress(bytes4 functionSelector) external view returns (address);
    function upsertToken(ERCToken calldata data) external;
    function setSyncSourceAllowed(address sourceRegistry, bool allowed) external;
    function setAuthAccountFactory(address factory, bool allowed) external;
    function upgradeRegistry(address newImplementation, bytes calldata data) external returns (bytes32);
    function replaceEngine(address target, address newEngine) external returns (bytes32);
    function revealInteractionCommit(
        InteractionBundleInput calldata bundle,
        bytes32[] calldata relatedContracts,
        bytes32 salt,
        bytes calldata actorSignature
    ) external;
}

/// @dev Same layout as `TimelockCategoryConfigInput` in RegistryTimelockFacet.
struct TimelockCategoryConfig {
    uint64 minDelay;
    uint64 maxDelay;
    uint64 defaultDelay;
    uint64 gracePeriod;
    bytes32 defaultPolicyId;
}

/// @dev The EIP-7702 cheatcode is newer than the forge-std revision pinned by the OpenZeppelin submodule.
interface IVm7702 {
    struct SignedDelegation {
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint64 nonce;
        address implementation;
    }

    /// @notice Sign an EIP-7702 authorization with `privateKey` and attach it to the next call.
    function signAndAttachDelegation(address implementation, uint256 privateKey)
        external
        returns (SignedDelegation memory);
}

interface IInteract {
    function getPayloadHash(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe
    ) external view returns (bytes32);
    function propose(bytes32 payloadHash, bytes32 policyId, uint256 deadline, uint256 nativeValue, address safe)
        external
        returns (uint256);
    function approveOperation(uint256 operationId) external returns (bool);
    function executeFromAccount(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        returns (uint256);
    function directExecuteFromAccount(
        address account,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature
    ) external returns (uint256);
}

interface IAccountFactory {
    function newAccount(bytes32 salt) external returns (address);
}

/// @notice A configured tenant on the Arbitrum One fork: three users, a 2-of-2 treasury policy,
///         a single-actor ops policy, a registered USDC contract, a USDC transfer interaction and
///         one funded OKAccount vault.
abstract contract TenantFixture is ChainwallDeployer {
    address internal constant USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831; // native USDC, Arbitrum One
    bytes32 internal constant INITIAL_TERMS_HASH = 0xc0d0b6034b7971648ff8332f4002119b0b39358ce84d4865a90101fc2220ab80;
    bytes32 internal constant INTERACTION_EXECUTOR = keccak256("cap.registry.interaction.execute");
    bytes32 internal constant ACCOUNT_MANAGER = keccak256("cap.registry.account.write");

    /// @dev Output of `miniscript compile test/scripts/usdc-transfer.core.ls` (Chainwall CLI 0.3.1).
    ///      Requires nativeValue == 0, exactly 2 args, arg0 != 0, arg1 > 0, then
    ///      WRITE keccak("circle/usdc").transfer(arg0, arg1) and requires it to succeed.
    bytes internal constant TRANSFER_SCRIPT =
        hex"0102320100601801053201026018010023010061180101230100631801012301002302bad6ccbe8f6bed92553dd18910f79c66afaaa5d196515ba83f48c7fe256ee89a0300000000a9059cbb010221180101ff";

    address internal tenantOwner;
    uint256 internal tenantOwnerPk;
    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal carol;
    uint256 internal carolPk;
    address internal outsider = makeAddr("chainwall-test outsider");
    address internal recipient = makeAddr("chainwall-test recipient");

    bytes32 internal constant TREASURY_GROUP = keccak256("treasury");
    bytes32 internal constant OPS_GROUP = keccak256("ops");
    /// @dev 2 approvals from the treasury group (alice, bob).
    bytes32 internal constant TREASURY_POLICY = keccak256("treasury 2-of-2");
    /// @dev 1 approval from the ops group (carol): a single-actor policy, usable with direct execute.
    bytes32 internal constant OPS_POLICY = keccak256("ops 1-of-1");
    bytes32 internal constant TRANSFER_INTERACTION = keccak256("usdc-transfer");

    IVm7702 internal constant vm7702 = IVm7702(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal attacker = makeAddr("chainwall-test attacker");

    IRegistryAdmin internal reg;
    IInteract internal interact;
    address internal vault;

    function _setUpTenant() internal {
        _initActorsAndFork();
        _deployFactoryFamily();
        _deployTenant(tenantOwner, 0, keccak256("chainwall e2e"));
        _bindTenant();
    }

    function _initActorsAndFork() internal {
        (tenantOwner, tenantOwnerPk) = makeAddrAndKey("chainwall-test tenant owner");
        (alice, alicePk) = makeAddrAndKey("chainwall-test alice");
        (bob, bobPk) = makeAddrAndKey("chainwall-test bob");
        (carol, carolPk) = makeAddrAndKey("chainwall-test carol");

        _fork();
        // The usual forge labels ("alice", ...) derive well-known private keys. On Arbitrum One the
        // "alice" address really carries an EIP-7702 delegation, so the fixture uses its own labels
        // and proves every test account starts as a plain EOA on the fork.
        _requirePlainEOA(tenantOwner);
        _requirePlainEOA(alice);
        _requirePlainEOA(bob);
        _requirePlainEOA(carol);
        _requirePlainEOA(outsider);
        _requirePlainEOA(recipient);
        _requirePlainEOA(attacker);
    }

    /// @dev Point the fixture's handles at the tenant most recently deployed with `_deployTenant`.
    function _bindTenant() internal {
        reg = IRegistryAdmin(registry);
        interact = IInteract(instance.interact);
    }

    function _requirePlainEOA(address account) internal view {
        require(account.code.length == 0, "test account has code on the fork");
    }

    function _configureTenant() internal {
        vm.startPrank(tenantOwner);
        // Accept whatever initial terms this tenant's factory snapshotted (the official factory on
        // Arbitrum One serves a different document than the one compiled into this checkout).
        (, TermsDoc memory initialTerms) = IRegistryView(registry).getTermsContext();
        IRegistryView(registry).acceptTerms(initialTerms.documentHash);
        reg.addUser(alice);
        reg.addUser(bob);
        reg.addUser(carol);
        reg.createGroup(TREASURY_GROUP);
        reg.addGroupMember(TREASURY_GROUP, alice);
        reg.addGroupMember(TREASURY_GROUP, bob);
        reg.createGroup(OPS_GROUP);
        reg.addGroupMember(OPS_GROUP, carol);
        reg.grantCapabilityGroup(INTERACTION_EXECUTOR, TREASURY_GROUP);
        reg.grantCapabilityGroup(INTERACTION_EXECUTOR, OPS_GROUP);

        _createPolicy(TREASURY_POLICY, TREASURY_GROUP, 2);
        _createPolicy(OPS_POLICY, OPS_GROUP, 1);

        reg.upsertOrg("circle", tenantOwner, false, new address[](0));
        reg.addContractVersion("circle", "usdc", ContractAddress(USDC, bytes32("1"), address(0)), bytes32(0));
        _publishInteraction(TRANSFER_INTERACTION, TRANSFER_SCRIPT);
        vm.stopPrank();

        vm.prank(alice);
        vault = IAccountFactory(instance.accountFactory).newAccount(keccak256("vault 1"));
        assertTrue(reg.isAccountAllowed(vault), "vault not admitted");

        // Test funding only: sets the vault's balance in the real USDC contract on the fork.
        deal(USDC, vault, 1_000e6);
        assertEq(IERC20(USDC).balanceOf(vault), 1_000e6, "funding");
    }

    /// @dev Signs one real EIP-7702 authorization with the account's key and lands it on chain with a
    ///      call to `ping()` on the account. Afterwards the account's code is `0xef0100 || delegate`.
    function _delegate(uint256 privateKey, address account, address delegate) internal {
        vm7702.signAndAttachDelegation(delegate, privateKey);
        vm.prank(attacker);
        (bool ok,) = account.call(abi.encodeWithSignature("ping()"));
        assertTrue(ok, "delegation carrier call failed");
        bytes memory code = account.code;
        assertEq(code.length, 23, "account is not delegated");
        assertEq(code, abi.encodePacked(hex"ef0100", delegate), "unexpected designator");
    }

    /// @dev Clears the account's delegation with a real authorization to the zero address.
    function _clearDelegation(uint256 privateKey, address account) internal {
        vm7702.signAndAttachDelegation(address(0), privateKey);
        vm.prank(attacker);
        (bool ok,) = account.call("");
        assertTrue(ok, "clearing carrier call failed");
        assertEq(account.code.length, 0, "delegation not cleared");
    }

    /// @dev The delegate timelock category has no code-defined default: governance must configure it
    ///      before any delegate can be approved or removed.
    function _configureDelegateCategory(uint64 delay) internal {
        vm.prank(tenantOwner);
        reg.setCategoryConfig(
            keccak256("timelock.category.delegate"), TimelockCategoryConfig(0, 30 days, delay, 1 days, bytes32(0))
        );
    }

    function _createPolicy(bytes32 policyId, bytes32 group, uint256 threshold) internal {
        bytes32[] memory groups = new bytes32[](1);
        groups[0] = group;
        uint256[] memory thresholds = new uint256[](1);
        thresholds[0] = threshold;
        reg.createPolicy(policyId, groups, thresholds);
    }

    function _publishInteraction(bytes32 id, bytes memory script) internal {
        InteractionBundleInput memory bundle;
        bundle.id = id;
        bundle.script = script;
        bundle.flags = 0;
        bundle.linked = new LinkedArtifactInput[](0);
        reg.upsertInteractionBundle(reg.getInteractionBundleHash(id), bundle);
    }

    function _transferArgs(address to, uint256 amount) internal pure returns (uint256[] memory args) {
        args = new uint256[](2);
        args[0] = uint256(uint160(to));
        args[1] = amount;
    }
}
