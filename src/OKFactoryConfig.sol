// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
import {ChainwallInitialImplementationValidation} from "./ChainwallUpgradeable.sol";
import {ProtocolCodehashes} from "./ProtocolCodehashes.sol";
import {RegistryDiamond} from "./RegistryDiamond.sol";
import {WebAuthnEntryPoint} from "./WebAuthnEntryPoint.sol";
import {Selectors} from "./registry/Selectors.sol";
import {RegistrySyncFacet} from "./registry/facets/RegistrySyncFacet.sol";

/// @title OKFactoryConfig
/// @notice Immutable configuration object that tells `OKFactory` what to deploy and what selectors to install.
/// @dev The factory itself stays relatively small and stable; this contract carries
///      the moving parts:
///      - implementation addresses for registry, interact, miniscript, and account factory
///      - SafeFactory implementation address for tenant SafeFactory proxies
///      - facet addresses for every registry surface
///      - Safe singleton / proxy factory bindings
///      - the instance-local terms acceptance facet
///      - canonical predictor address used to bind staged deployments
///
///      Example deployment flow:
///      1. Deploy all facet contracts and implementation contracts.
///      2. Construct `OKFactoryConfig` with those addresses.
///      3. Deploy the canonical factory modules.
///      4. Deploy `OKFactory(config, stage1Module, stage2Module, authAccountModule)`.
///      5. Let the factory call {installRegistryFacets} during tenant setup.
contract OKFactoryConfig {
    uint256 private constant _UPGRADE_PROTOCOL_VERSION = 1;
    bytes32 private constant _REGISTRY_COMPONENT_ID = keccak256("Chainwall.Registry");
    bytes32 private constant _MINISCRIPT_COMPONENT_ID = keccak256("Chainwall.MiniScript");
    bytes32 private constant _INTERACT_COMPONENT_ID = keccak256("Chainwall.Interact");
    bytes32 private constant _SAFE_FACTORY_COMPONENT_ID = keccak256("Chainwall.SafeFactory");
    bytes32 private constant _ACCOUNT_FACTORY_COMPONENT_ID = keccak256("Chainwall.AccountFactory");
    bytes32 private constant _OK_ACCOUNT_COMPONENT_ID = keccak256("Chainwall.OKAccount");
    bytes32 private constant _AUTH_FACTORY_COMPONENT_ID = keccak256("Chainwall.WebAuthnAuthAccountFactory");
    bytes32 private constant _AUTH_ACCOUNT_COMPONENT_ID = keccak256("Chainwall.WebAuthnAuthAccount");
    error ConfigComponentInvalid(address implementation, bytes32 expectedComponentId);
    error ConfigUpgradeProtocolInvalid(address implementation, uint256 expectedVersion);
    error ConfigUUPSInterfaceInvalid(address implementation);
    error ConfigSecurityBindingsInvalid(address implementation);

    /// @notice Bundle of facet implementation addresses used when wiring a registry.
    /// @dev The names mirror the logical registry surfaces rather than Solidity filenames.
    struct FacetAddresses {
        /// @notice Facet handling user and group management.
        address users;
        /// @notice Facet handling Safe and native-account allowlists.
        address accounts;
        /// @notice Facet handling organization records.
        address orgs;
        /// @notice Facet handling versioned contract directory writes.
        address contractsFacet;
        /// @notice Facet handling interaction bundles and commit-reveal flows.
        address interactions;
        /// @notice Facet handling metadata blobs and typed metadata helpers.
        address metadata;
        /// @notice Facet handling policy criteria and policy programs.
        address policies;
        /// @notice Facet handling policy-owned typed state and scoped meters.
        address policyState;
        /// @notice Facet handling timelock queues, approvals, execution, and configuration.
        address timelock;
        /// @notice Facet handling timelock-controlled upgrade entrypoints.
        address timelockUpgrade;
        /// @notice Facet handling timelock-controlled future-deployment release defaults.
        address timelockRelease;
        /// @notice Facet handling token metadata and price-feed references.
        address tokens;
        /// @notice Facet handling private token commit/reveal publication.
        address tokenCommits;
        /// @notice Facet handling source allowlists and catalog imports.
        address sync;
        /// @notice Facet handling sync source and import provenance queries.
        address syncQuery;
        /// @notice Facet handling WebAuthn credential links and approved AuthAccount factories.
        address auth;
        /// @notice Facet handling capability grants.
        address capabilities;
        /// @notice Facet handling the initial terms snapshot and document acceptance.
        address terms;
        /// @notice ERC-2535 diamond-cut facet.
        address cut;
        /// @notice ERC-2535 loupe facet.
        address loupe;
    }

    /// @notice WebAuthn AuthAccount factory configuration shared by new tenant instances.
    struct WebAuthnConfig {
        address factoryImpl;
        address accountImpl;
        address entryPoint;
        bytes32 rpIdHash;
        string origin;
        bool requireUserVerification;
    }

    address public immutable SAFE_SINGLETON;
    address public immutable SAFE_PROXY_FACTORY;
    address public immutable SAFE_FACTORY_IMPL;
    address public immutable MINISCRIPT_IMPL;
    address public immutable REGISTRY_IMPL;
    address public immutable ACCOUNT_ENGINE;
    address public immutable ACCOUNT_FACTORY_IMPL;
    address public immutable OK_ACCOUNT_IMPL;
    address public immutable PREDICTOR;
    address public immutable WEB_AUTHN_FACTORY_IMPL;
    address public immutable INTERACT_IMPL;
    address public immutable WEB_AUTHN_ACCOUNT_IMPL;
    address public immutable WEB_AUTHN_ENTRY_POINT;
    bytes32 public immutable WEB_AUTHN_RP_ID_HASH;
    bool public immutable WEB_AUTHN_REQUIRE_USER_VERIFICATION;
    string private _webAuthnOrigin;

    address public immutable USERS_FACET;
    address public immutable ACCOUNTS_FACET;
    address public immutable ORGS_FACET;
    address public immutable CONTRACTS_FACET;
    address public immutable INTERACTIONS_FACET;
    address public immutable METADATA_FACET;
    address public immutable POLICIES_FACET;
    address public immutable POLICY_STATE_FACET;
    address public immutable TIMELOCK_FACET;
    address public immutable TIMELOCK_UPGRADE_FACET;
    address public immutable TIMELOCK_RELEASE_FACET;
    address public immutable TOKENS_FACET;
    address public immutable TOKEN_COMMITS_FACET;
    address public immutable SYNC_FACET;
    address public immutable SYNC_QUERY_FACET;
    address public immutable AUTH_FACET;
    address public immutable CAPABILITIES_FACET;
    address public immutable TERMS_FACET;
    address public immutable CUT_FACET;
    address public immutable LOUPE_FACET;

    /// @notice Build a configuration object for one factory family.
    /// @param safeSingleton Gnosis Safe singleton used by tenant Safe factories.
    /// @param safeProxyFactory Gnosis Safe proxy factory used by tenant Safe factories.
    /// @param safeFactoryImpl SafeFactoryWithCreate2 implementation used for tenant proxies.
    /// @param facets Facet addresses to install on deployed registries.
    /// @param registryImpl RegistryDiamond implementation used for tenant proxies.
    /// @param miniScriptImpl MiniScript implementation used for tenant proxies.
    /// @param interactImpl Interact implementation used for tenant proxies.
    /// @param accountEngine Shared MiniScriptEngine for native accounts.
    /// @param accountFactoryImpl AccountFactory implementation used for tenant proxies.
    /// @param okAccountImpl OKAccount implementation used for newly deployed vault proxies.
    /// @param predictor Canonical `OKFactoryPredictor` deployment used by staged instance creation.
    ///        `OKFactory` validates this once at construction, freezes the address internally, and rejects
    ///        non-canonical predictor bytecode.
    /// @param webAuthn Shared WebAuthn factory implementation, account implementation, and policy constants.
    constructor(
        address safeSingleton,
        address safeProxyFactory,
        address safeFactoryImpl,
        FacetAddresses memory facets,
        address registryImpl,
        address miniScriptImpl,
        address interactImpl,
        address accountEngine,
        address accountFactoryImpl,
        address okAccountImpl,
        address predictor,
        WebAuthnConfig memory webAuthn
    ) {
        require(safeSingleton != address(0), "config:safeSingleton=0");
        require(safeProxyFactory != address(0), "config:safeProxyFactory=0");
        require(safeFactoryImpl != address(0), "config:safeFactoryImpl=0");
        require(Delegation7702.hasContractCode(safeFactoryImpl), "config:safeFactoryImpl !contract");
        require(facets.users != address(0), "config:usersFacet=0");
        require(facets.accounts != address(0), "config:accountsFacet=0");
        require(facets.orgs != address(0), "config:orgsFacet=0");
        require(facets.contractsFacet != address(0), "config:contractsFacet=0");
        require(facets.interactions != address(0), "config:interactionsFacet=0");
        require(facets.metadata != address(0), "config:metadataFacet=0");
        require(facets.policies != address(0), "config:policiesFacet=0");
        require(facets.policyState != address(0), "config:policyStateFacet=0");
        require(facets.timelock != address(0), "config:timelockFacet=0");
        require(facets.timelockUpgrade != address(0), "config:timelockUpgradeFacet=0");
        require(facets.timelockRelease != address(0), "config:timelockReleaseFacet=0");
        require(facets.tokens != address(0), "config:tokensFacet=0");
        require(facets.tokenCommits != address(0), "config:tokenCommitsFacet=0");
        require(facets.sync != address(0), "config:syncFacet=0");
        require(facets.syncQuery != address(0), "config:syncQueryFacet=0");
        require(facets.auth != address(0), "config:authFacet=0");
        require(facets.capabilities != address(0), "config:capabilitiesFacet=0");
        require(facets.terms != address(0), "config:termsFacet=0");
        require(facets.cut != address(0), "config:cutFacet=0");
        require(facets.loupe != address(0), "config:loupeFacet=0");
        require(registryImpl != address(0), "config:registryImpl=0");
        require(miniScriptImpl != address(0), "config:miniScriptImpl=0");
        require(interactImpl != address(0), "config:interactImpl=0");
        require(accountEngine != address(0), "config:accountEngine=0");
        require(Delegation7702.hasContractCode(accountEngine), "config:accountEngine !contract");
        require(ProtocolCodehashes.isAcceptedMiniScriptDeployment(accountEngine), "config:accountEngine !canon");
        require(accountFactoryImpl != address(0), "config:accountFactoryImpl=0");
        require(okAccountImpl != address(0), "config:okAccountImpl=0");
        require(Delegation7702.hasContractCode(okAccountImpl), "config:okAccountImpl !contract");
        require(predictor != address(0), "config:predictor=0");
        require(webAuthn.factoryImpl != address(0), "config:webAuthnFactoryImpl=0");
        require(Delegation7702.hasContractCode(webAuthn.factoryImpl), "config:webAuthnFactoryImpl !contract");
        require(webAuthn.accountImpl != address(0), "config:webAuthnAccountImpl=0");
        require(Delegation7702.hasContractCode(webAuthn.accountImpl), "config:webAuthnAccountImpl !contract");
        require(webAuthn.entryPoint != address(0), "config:webAuthnEntryPoint=0");
        WebAuthnEntryPoint.requireCanonical(webAuthn.entryPoint);
        require(webAuthn.rpIdHash != bytes32(0), "config:webAuthnRpIdHash=0");
        require(bytes(webAuthn.origin).length != 0, "config:webAuthnOrigin=0");
        // Both the tenant AuthAccount factory and every account require UV.
        // Reject an unusable top-level configuration before staged deployment.
        require(webAuthn.requireUserVerification, "config:webAuthnUV=false");

        // Every persistent implementation selected by a new factory family must
        // expose the same upgrade protocol that tenant Registry actions enforce.
        // Rejecting a wrong release here avoids deploying an otherwise healthy
        // tenant graph whose vaults or factories can never be upgraded.
        _requireUpgradeableComponent(registryImpl, _REGISTRY_COMPONENT_ID, true);
        _requireUpgradeableComponent(miniScriptImpl, _MINISCRIPT_COMPONENT_ID, true);
        _requireUpgradeableComponent(interactImpl, _INTERACT_COMPONENT_ID, true);
        _requireUpgradeableComponent(safeFactoryImpl, _SAFE_FACTORY_COMPONENT_ID, true);
        _requireUpgradeableComponent(accountFactoryImpl, _ACCOUNT_FACTORY_COMPONENT_ID, true);
        _requireUpgradeableComponent(okAccountImpl, _OK_ACCOUNT_COMPONENT_ID, true);
        _requireUpgradeableComponent(webAuthn.factoryImpl, _AUTH_FACTORY_COMPONENT_ID, true);
        // Account clones keep their upgrade slot and authority in the permanent
        // dispatcher, so replaceable WebAuthn logic intentionally is not UUPS.
        _requireUpgradeableComponent(webAuthn.accountImpl, _AUTH_ACCOUNT_COMPONENT_ID, false);

        SAFE_SINGLETON = safeSingleton;
        SAFE_PROXY_FACTORY = safeProxyFactory;
        SAFE_FACTORY_IMPL = safeFactoryImpl;
        USERS_FACET = facets.users;
        ACCOUNTS_FACET = facets.accounts;
        ORGS_FACET = facets.orgs;
        CONTRACTS_FACET = facets.contractsFacet;
        INTERACTIONS_FACET = facets.interactions;
        METADATA_FACET = facets.metadata;
        POLICIES_FACET = facets.policies;
        POLICY_STATE_FACET = facets.policyState;
        TIMELOCK_FACET = facets.timelock;
        TIMELOCK_UPGRADE_FACET = facets.timelockUpgrade;
        TIMELOCK_RELEASE_FACET = facets.timelockRelease;
        TOKENS_FACET = facets.tokens;
        TOKEN_COMMITS_FACET = facets.tokenCommits;
        SYNC_FACET = facets.sync;
        SYNC_QUERY_FACET = facets.syncQuery;
        AUTH_FACET = facets.auth;
        CAPABILITIES_FACET = facets.capabilities;
        TERMS_FACET = facets.terms;
        CUT_FACET = facets.cut;
        LOUPE_FACET = facets.loupe;
        REGISTRY_IMPL = registryImpl;
        MINISCRIPT_IMPL = miniScriptImpl;
        INTERACT_IMPL = interactImpl;
        ACCOUNT_ENGINE = accountEngine;
        ACCOUNT_FACTORY_IMPL = accountFactoryImpl;
        OK_ACCOUNT_IMPL = okAccountImpl;
        PREDICTOR = predictor;
        WEB_AUTHN_FACTORY_IMPL = webAuthn.factoryImpl;
        WEB_AUTHN_ACCOUNT_IMPL = webAuthn.accountImpl;
        WEB_AUTHN_ENTRY_POINT = webAuthn.entryPoint;
        WEB_AUTHN_RP_ID_HASH = webAuthn.rpIdHash;
        _webAuthnOrigin = webAuthn.origin;
        WEB_AUTHN_REQUIRE_USER_VERIFICATION = webAuthn.requireUserVerification;
    }

    function WEB_AUTHN_ORIGIN() external view returns (string memory) {
        return _webAuthnOrigin;
    }

    function _requireUpgradeableComponent(address implementation, bytes32 expectedComponentId, bool requireUups)
        private
        view
    {
        (ChainwallInitialImplementationValidation.Issue issue,) =
            ChainwallInitialImplementationValidation.inspect(implementation, expectedComponentId, requireUups);
        if (
            issue == ChainwallInitialImplementationValidation.Issue.NotContract
                || issue == ChainwallInitialImplementationValidation.Issue.Component
        ) {
            revert ConfigComponentInvalid(implementation, expectedComponentId);
        }
        if (issue == ChainwallInitialImplementationValidation.Issue.Protocol) {
            revert ConfigUpgradeProtocolInvalid(implementation, _UPGRADE_PROTOCOL_VERSION);
        }
        if (issue == ChainwallInitialImplementationValidation.Issue.Uups) {
            revert ConfigUUPSInterfaceInvalid(implementation);
        }
        if (issue == ChainwallInitialImplementationValidation.Issue.SecurityBindings) {
            revert ConfigSecurityBindingsInvalid(implementation);
        }
    }

    /// @notice Installs the first stage-1 facet tranche on a bootstrapped registry.
    /// @dev This tranche is chosen to stay below public-chain transaction caps when
    ///      combined with proxy deployment. The registry remains paused until stage 2
    ///      installs the deferred catalog and core facets and completes tenant handoff.
    function installRegistryBootstrapFacets(RegistryDiamond registry) external {
        _installRegistryBootstrapFacets(registry);
    }

    /// @notice Installs the second stage-1 facet tranche required for registry setup.
    /// @dev Sync and metadata routing are already installed by bootstrap. Emergency,
    ///      token, and core facets remain deferred so this transaction,
    ///      including terms, auth, capability, and timelock setup, stays below
    ///      public-chain gas caps.
    function installRegistryFinalizeFacets(RegistryDiamond registry) external {
        _installRegistryFinalizeFacets(registry);
    }

    /// @notice Installs deferred governance and catalog facets, then closes bootstrap.
    /// @dev Stage 2 invokes this in an atomic bootstrap unpause window while factory-owned.
    ///      Emergency selectors are installed before tenant handoff, and core facets are
    ///      installed last after every bootstrap selector has been validated.
    function installRegistryCompletionFacets(RegistryDiamond registry) external {
        _installRegistryCompletionFacets(registry);
    }

    /// @notice Installs all core and feature facets on a registry.
    /// @dev Caller must possess the necessary admin roles on `registry`.
    ///      Registries receive the full selector map, including terms, sync,
    ///      capabilities and timelock upgrade entrypoints. This convenience path
    ///      can exceed public-chain transaction gas caps; production bring-up uses
    ///      the three staged installers with the Registry paused between transactions.
    function installRegistryFacets(RegistryDiamond registry) external {
        _installRegistryBootstrapFacets(registry);
        _installRegistryFinalizeFacets(registry);
        _installRegistryCompletionFacets(registry);
    }

    function _installRegistryBootstrapFacets(RegistryDiamond registry) internal {
        registry.setFacets(Selectors.users(), USERS_FACET);
        registry.setFacets(Selectors.accounts(), ACCOUNTS_FACET);
        registry.setFacets(Selectors.contractsFacet(), CONTRACTS_FACET);
        registry.setFacets(Selectors.interactions(), INTERACTIONS_FACET);
        registry.setFacets(Selectors.policies(), POLICIES_FACET);
        registry.setFacets(Selectors.policyState(), POLICY_STATE_FACET);
        // Balance all three transactions under EIP-7825. Installing these routes
        // here leaves room for AuthAccount construction in prepare and the runtime
        // stack in completion. The registry stays factory-owned and paused between steps.
        registry.setFacets(Selectors.syncFacet(), SYNC_FACET);
        // Interaction sync uses the companion deployed by the primary sync implementation.
        registry.setFacets(Selectors.interactionSync(), RegistrySyncFacet(SYNC_FACET).interactionSyncFacet());
        registry.setFacets(Selectors.metadata(), METADATA_FACET);
    }

    /// @dev Install governance, sync query, auth, capability, and terms selectors.
    function _installRegistryFinalizeFacets(RegistryDiamond registry) internal {
        registry.setFacets(Selectors.timelock(), TIMELOCK_FACET);
        registry.setFacets(Selectors.timelockUpgrade(), TIMELOCK_UPGRADE_FACET);
        registry.setFacets(Selectors.timelockRelease(), TIMELOCK_RELEASE_FACET);
        registry.setFacets(Selectors.syncQueries(), SYNC_QUERY_FACET);
        registry.setFacets(Selectors.auth(), AUTH_FACET);
        registry.setFacets(Selectors.capabilities(), CAPABILITIES_FACET);
        registry.setFacets(Selectors.terms(), TERMS_FACET);
    }

    function _installRegistryCompletionFacets(RegistryDiamond registry) internal {
        registry.setFacets(Selectors.orgs(), ORGS_FACET);
        registry.setFacets(Selectors.tokens(), TOKENS_FACET);
        registry.setFacets(Selectors.tokenCommits(), TOKEN_COMMITS_FACET);
        registry.installCoreFacets(CUT_FACET, LOUPE_FACET);
    }
}
