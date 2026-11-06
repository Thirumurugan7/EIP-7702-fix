// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {console2} from "forge-std/console2.sol";

import {OKFactory} from "../src/OKFactory.sol";
import {Selectors} from "../src/registry/Selectors.sol";

import {IERC20, IRegistryAdmin, IInteract, IRegistryView, TenantFixture} from "./TenantFixture.sol";

interface INewFamily {
    function USERS_FACET() external view returns (address);
    function ACCOUNTS_FACET() external view returns (address);
    function ORGS_FACET() external view returns (address);
    function CONTRACTS_FACET() external view returns (address);
    function INTERACTIONS_FACET() external view returns (address);
    function METADATA_FACET() external view returns (address);
    function POLICIES_FACET() external view returns (address);
    function POLICY_STATE_FACET() external view returns (address);
    function TIMELOCK_FACET() external view returns (address);
    function TIMELOCK_UPGRADE_FACET() external view returns (address);
    function TIMELOCK_RELEASE_FACET() external view returns (address);
    function TOKENS_FACET() external view returns (address);
    function TOKEN_COMMITS_FACET() external view returns (address);
    function SYNC_FACET() external view returns (address);
    function SYNC_QUERY_FACET() external view returns (address);
    function AUTH_FACET() external view returns (address);
    function CAPABILITIES_FACET() external view returns (address);
    function TERMS_FACET() external view returns (address);
    function CUT_FACET() external view returns (address);
    function LOUPE_FACET() external view returns (address);
    function REGISTRY_IMPL() external view returns (address);
    function MINISCRIPT_IMPL() external view returns (address);
    function INTERACT_IMPL() external view returns (address);
    function ACCOUNT_FACTORY_IMPL() external view returns (address);
    function OK_ACCOUNT_IMPL() external view returns (address);
    function SAFE_FACTORY_IMPL() external view returns (address);
    function ACCOUNT_ENGINE() external view returns (address);
}

interface ISyncCompanion {
    function interactionSyncFacet() external view returns (address);
}

interface IDiamond {
    enum FacetCutAction {
        Add,
        Replace,
        Remove
    }

    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }

    function diamondCut(FacetCut[] calldata cuts, address init, bytes calldata data) external;
    function facetAddress(bytes4 selector) external view returns (address);
    function facetFunctionSelectors(address facet) external view returns (bytes4[] memory);
}

interface IUpgrades {
    function upgradeRegistry(address newImplementation, bytes calldata data) external returns (bytes32);
    function upgradeInteract(address target, address newImplementation, bytes calldata data) external returns (bytes32);
    function upgradeMiniScript(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32);
    function upgradeAccountFactory(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32);
    function upgradeSafeFactory(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32);
    function upgradeOkAccount(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32);
    function upgradeOkGuard(address target, address newImplementation, bytes calldata data) external returns (bytes32);
    function upgradeOkModule(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32);
    function replaceEngine(address target, address newEngine) external returns (bytes32);
    function setTimelockPolicyRunner(address runner) external;
    function getTimelockPolicyRunner() external view returns (address);
}

interface ISafeParts {
    function COMPONENT_FACTORY() external view returns (address);
    function EXTENSION_FACTORY() external view returns (address);
    function GUARD_IMPLEMENTATION() external view returns (address);
    function MODULE_IMPLEMENTATION() external view returns (address);
    function GUARD_CONTRACT() external view returns (address);
    function MODULE_CONTRACT() external view returns (address);
}

interface IImplView {
    function chainwallImplementation() external view returns (address);
    function chainwallEngine() external view returns (address);
}

contract ForgedSigDelegate {
    function ping() external {}

    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// @notice Upgrade path for a tenant that already exists.
///         The tenant is deployed from the UNPATCHED release of this repository (the branch's base
///         commit, compiled into out-orig/ by test/tools/build-original.sh), so it runs the original
///         code with the original codehash pins. It is then upgraded in place to the patched build
///         through its own governance: every step goes through the Registry's diamond-cut, upgrade
///         and release entrypoints. Nothing is written to storage directly.
contract Migration7702Test is TenantFixture {
    INewFamily internal fam;
    IDiamond internal diamond;
    IUpgrades internal up;
    ForgedSigDelegate internal yes;
    address internal migratedSafeFactoryImpl;

    function setUp() public {
        (tenantOwner, tenantOwnerPk) = makeAddrAndKey("chainwall-test tenant owner");
        (alice, alicePk) = makeAddrAndKey("chainwall-test alice");
        (bob, bobPk) = makeAddrAndKey("chainwall-test bob");
        (carol, carolPk) = makeAddrAndKey("chainwall-test carol");
        if (!vm.exists("out-orig/OKFactory.sol/OKFactory.json")) {
            vm.skip(true, "unpatched release not built: run test/tools/build-original.sh");
        }
        _fork();

        // 1. an existing tenant on the unpatched release
        artifactRoot = "out-orig/";
        _deployFactoryFamily();
        _deployTenant(tenantOwner, 0, keccak256("chainwall migration test"));
        reg = IRegistryAdmin(registry);
        interact = IInteract(instance.interact);
        _configureTenant();
        diamond = IDiamond(registry);
        up = IUpgrades(registry);
        yes = new ForgedSigDelegate();

        // 2. the patched code, deployed next to it (facets, implementations, engine)
        artifactRoot = "";
        _deployFactoryFamily();
        fam = INewFamily(address(config));
    }

    // ------------------------------------------------------------------ attack helper

    /// @return drained True when a non-user drained the vault with a garbage signature for carol.
    function _forgedSignatureAttack() internal returns (bool drained) {
        _delegate(carolPk, carol, address(yes));
        uint256[] memory args = _transferArgs(attacker, 1_000e6);
        vm.prank(attacker);
        try interact.directExecuteFromAccount(
            vault, OPS_POLICY, TRANSFER_INTERACTION, args, 10_000, 0, block.timestamp + 1 hours, carol, hex"deadbeef"
        ) {} catch {}
        drained = IERC20(USDC).balanceOf(attacker) == 1_000e6;
    }

    // ------------------------------------------------------------------ migration

    /// @dev Route every selector of one facet to its patched implementation: selectors that are already
    ///      routed are replaced, selectors that are new are added. One cut per facet keeps each
    ///      transaction far below a block's gas limit.
    function _cutFacet(address newFacet, bytes4[] memory selectors) internal {
        uint256 nReplace;
        uint256 nAdd;
        for (uint256 i; i < selectors.length; ++i) {
            address current = diamond.facetAddress(selectors[i]);
            if (current == address(0)) ++nAdd;
            else if (current != newFacet) ++nReplace;
        }
        bytes4[] memory replace = new bytes4[](nReplace);
        bytes4[] memory add = new bytes4[](nAdd);
        (nReplace, nAdd) = (0, 0);
        for (uint256 i; i < selectors.length; ++i) {
            address current = diamond.facetAddress(selectors[i]);
            if (current == address(0)) add[nAdd++] = selectors[i];
            else if (current != newFacet) replace[nReplace++] = selectors[i];
        }
        uint256 n = (replace.length != 0 ? 1 : 0) + (add.length != 0 ? 1 : 0);
        if (n == 0) return;
        IDiamond.FacetCut[] memory cuts = new IDiamond.FacetCut[](n);
        uint256 k;
        if (replace.length != 0) cuts[k++] = IDiamond.FacetCut(newFacet, IDiamond.FacetCutAction.Replace, replace);
        if (add.length != 0) cuts[k++] = IDiamond.FacetCut(newFacet, IDiamond.FacetCutAction.Add, add);
        vm.prank(tenantOwner);
        diamond.diamondCut(cuts, address(0), "");
    }

    function _migrate() internal {
        // --- A. Registry facets, one governed diamond cut each. The users facet goes first: it carries
        //        the rule itself and the two views every other patched component calls.
        address oldCut = diamond.facetAddress(IDiamond.diamondCut.selector);
        address oldLoupe = diamond.facetAddress(IDiamond.facetAddress.selector);
        bytes4[] memory cutSelectors = diamond.facetFunctionSelectors(oldCut);
        bytes4[] memory loupeSelectors = diamond.facetFunctionSelectors(oldLoupe);

        _cutFacet(fam.USERS_FACET(), Selectors.users());
        _cutFacet(fam.CAPABILITIES_FACET(), Selectors.capabilities());
        _cutFacet(fam.ACCOUNTS_FACET(), Selectors.accounts());
        _cutFacet(fam.ORGS_FACET(), Selectors.orgs());
        _cutFacet(fam.CONTRACTS_FACET(), Selectors.contractsFacet());
        _cutFacet(fam.INTERACTIONS_FACET(), Selectors.interactions());
        _cutFacet(fam.METADATA_FACET(), Selectors.metadata());
        _cutFacet(fam.POLICIES_FACET(), Selectors.policies());
        _cutFacet(fam.POLICY_STATE_FACET(), Selectors.policyState());
        _cutFacet(fam.TOKENS_FACET(), Selectors.tokens());
        _cutFacet(fam.TOKEN_COMMITS_FACET(), Selectors.tokenCommits());
        _cutFacet(fam.AUTH_FACET(), Selectors.auth());
        _cutFacet(fam.TERMS_FACET(), Selectors.terms());
        _cutFacet(fam.SYNC_FACET(), Selectors.syncFacet());
        _cutFacet(ISyncCompanion(fam.SYNC_FACET()).interactionSyncFacet(), Selectors.interactionSync());
        _cutFacet(fam.SYNC_QUERY_FACET(), Selectors.syncQueries());
        _cutFacet(fam.TIMELOCK_FACET(), Selectors.timelock());
        _cutFacet(fam.TIMELOCK_UPGRADE_FACET(), Selectors.timelockUpgrade());
        _cutFacet(fam.TIMELOCK_RELEASE_FACET(), Selectors.timelockRelease());
        _cutFacet(fam.LOUPE_FACET(), loupeSelectors);
        _cutFacet(fam.CUT_FACET(), cutSelectors);

        // --- B. Registry implementation (roles, pause table)
        address newRegistryImpl = fam.REGISTRY_IMPL();
        vm.prank(tenantOwner);
        up.upgradeRegistry(newRegistryImpl, "");

        // --- C. component implementations
        vm.startPrank(tenantOwner);
        up.upgradeMiniScript(instance.miniScript, fam.MINISCRIPT_IMPL(), "");
        up.upgradeInteract(instance.interact, fam.INTERACT_IMPL(), "");
        up.upgradeAccountFactory(instance.accountFactory, fam.ACCOUNT_FACTORY_IMPL(), "");
        up.upgradeOkAccount(vault, fam.OK_ACCOUNT_IMPL(), "");

        // Safe side. A SafeFactory's security bindings include the codehash of its component factory, so a
        // code-only upgrade must keep the component factory the tenant already has: the patched factory
        // implementation is built against that same component factory. The tenant's guard and module are
        // then upgraded to the patched implementations.
        address currentSafeFactoryImpl = IImplView(instance.safeFactory).chainwallImplementation();
        migratedSafeFactoryImpl = deployCode(
            "SafeFactory.sol:SafeFactoryWithCreate2",
            abi.encode(
                SAFE_SINGLETON,
                SAFE_PROXY_FACTORY,
                fam.INTERACT_IMPL(),
                false,
                ISafeParts(currentSafeFactoryImpl).COMPONENT_FACTORY()
            )
        );
        up.upgradeSafeFactory(instance.safeFactory, migratedSafeFactoryImpl, "");
        ISafeParts ext =
            ISafeParts(ISafeParts(ISafeParts(fam.SAFE_FACTORY_IMPL()).COMPONENT_FACTORY()).EXTENSION_FACTORY());
        up.upgradeOkGuard(ISafeParts(instance.safeFactory).GUARD_CONTRACT(), ext.GUARD_IMPLEMENTATION(), "");
        up.upgradeOkModule(ISafeParts(instance.safeFactory).MODULE_CONTRACT(), ext.MODULE_IMPLEMENTATION(), "");

        // --- D. the patched engine, for the policy host, future accounts and the existing vault
        address newEngine = fam.ACCOUNT_ENGINE();
        up.replaceEngine(instance.miniScript, newEngine);
        up.replaceEngine(instance.accountFactory, newEngine);
        up.replaceEngine(vault, newEngine);
        address runner =
            deployCode("TimelockPolicyProgramRunner.sol:TimelockPolicyProgramRunner", abi.encode(registry, newEngine));
        up.setTimelockPolicyRunner(runner);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ tests

    /// @notice Before the upgrade the tenant is vulnerable: one delegation, vault drained.
    function test_migration_00_unpatchedTenantIsVulnerable() public {
        assertTrue(_forgedSignatureAttack(), "expected the unpatched tenant to be drained");
    }

    /// @notice The full in-place upgrade, then the same attack, then normal operation on the old state.
    function test_migration_01_upgradeInPlaceThenAttackRefused() public {
        _migrate();

        // everything points at the patched code
        assertEq(diamond.facetAddress(IRegistryAdmin.addUser.selector), fam.USERS_FACET(), "users facet");
        assertEq(diamond.facetAddress(IRegistryAdmin.isActorUsable.selector), fam.USERS_FACET(), "new selector");
        assertEq(IImplView(registry).chainwallImplementation(), fam.REGISTRY_IMPL(), "registry impl");
        assertEq(IImplView(instance.interact).chainwallImplementation(), fam.INTERACT_IMPL(), "interact impl");
        assertEq(IImplView(instance.miniScript).chainwallImplementation(), fam.MINISCRIPT_IMPL(), "miniscript impl");
        assertEq(IImplView(vault).chainwallImplementation(), fam.OK_ACCOUNT_IMPL(), "vault impl");
        assertEq(IImplView(vault).chainwallEngine(), fam.ACCOUNT_ENGINE(), "vault engine");
        assertEq(
            IImplView(instance.safeFactory).chainwallImplementation(), migratedSafeFactoryImpl, "safe factory impl"
        );

        // tenant state survived
        assertEq(IRegistryView(registry).owner(), tenantOwner, "owner");
        assertTrue(reg.isUser(alice) && reg.isUser(bob) && reg.isUser(carol), "users");
        assertTrue(reg.isGroupMemberByHash(TREASURY_GROUP, alice), "membership");
        assertTrue(reg.hasCapability(INTERACTION_EXECUTOR, carol), "capability");
        assertTrue(reg.isAccountAllowed(vault), "vault allowlisted");
        assertEq(IERC20(USDC).balanceOf(vault), 1_000e6, "vault funds");

        // the attack that drains the unpatched tenant is refused
        assertFalse(_forgedSignatureAttack(), "VULNERABLE after migration");
        assertEq(IERC20(USDC).balanceOf(vault), 1_000e6, "vault funds after attack");
    }

    /// @notice After the upgrade the tenant still works: a 2-of-2 payout on the pre-existing vault.
    function test_migration_02_normalOperationAfterUpgrade() public {
        _migrate();

        uint256[] memory args = _transferArgs(recipient, 250e6);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, TREASURY_POLICY, deadline, 0, vault);
        vm.prank(alice);
        uint256 opId = interact.propose(payloadHash, TREASURY_POLICY, deadline, 0, vault);
        vm.prank(bob);
        assertTrue(interact.approveOperation(opId));
        vm.prank(alice);
        interact.executeFromAccount(opId, TRANSFER_INTERACTION, args, 10_000);
        assertEq(IERC20(USDC).balanceOf(recipient), 250e6, "payout");
    }
}

/// @notice The deployment that is live on Arbitrum One today, reached through the official factory.
contract OfficialDeployment7702Test is TenantFixture {
    address internal constant OFFICIAL_FACTORY = 0x20d2eD7f3d008a70b2aED91CC7F9801Ff14b449b;
    ForgedSigDelegate internal yes;

    function setUp() public {
        (tenantOwner, tenantOwnerPk) = makeAddrAndKey("chainwall-test tenant owner");
        (alice, alicePk) = makeAddrAndKey("chainwall-test alice");
        (bob, bobPk) = makeAddrAndKey("chainwall-test bob");
        (carol, carolPk) = makeAddrAndKey("chainwall-test carol");
        _fork();
        factory = OKFactory(OFFICIAL_FACTORY);
        _deployTenant(tenantOwner, 0, keccak256("chainwall official test"));
        reg = IRegistryAdmin(registry);
        interact = IInteract(instance.interact);
        _configureTenant();
        yes = new ForgedSigDelegate();
    }

    /// @notice A tenant created by the official factory, running the deployed bytecode, is drained by a
    ///         non-user with a garbage signature after one EIP-7702 delegation by a single-actor signer.
    function test_official_tenantIsVulnerable() public {
        _delegate(carolPk, carol, address(yes));
        uint256[] memory args = _transferArgs(attacker, 1_000e6);
        vm.prank(attacker);
        interact.directExecuteFromAccount(
            vault, OPS_POLICY, TRANSFER_INTERACTION, args, 10_000, 0, block.timestamp + 1 hours, carol, hex"deadbeef"
        );
        assertEq(IERC20(USDC).balanceOf(attacker), 1_000e6, "attacker");
        assertEq(IERC20(USDC).balanceOf(vault), 0, "vault");
    }

    /// @notice The Registry deployed on Arbitrum One is not the Registry in this repository: the deployed
    ///         one refuses this repository's Registry implementation as its successor, because the two
    ///         compute different security-binding hashes. (The unpatched base commit is refused the same
    ///         way, so this is not caused by the EIP-7702 patch.) An in-place upgrade of an official
    ///         tenant therefore needs the source of what is actually deployed.
    function test_official_registryUpgradeToThisRepoIsRefused() public {
        address officialTenantRegistry = registry;
        _deployFactoryFamily();
        address newRegistryImpl = INewFamily(address(config)).REGISTRY_IMPL();

        vm.prank(tenantOwner);
        try IUpgrades(officialTenantRegistry).upgradeRegistry(newRegistryImpl, "") {
            revert("the official Registry accepted this repository's implementation");
        } catch (bytes memory reason) {
            console2.logBytes(reason);
            assertEq(
                bytes4(reason),
                bytes4(keccak256("UpgradeBindingsChanged(address,bytes32,bytes32)")),
                "refused for a different reason"
            );
        }
    }
}
