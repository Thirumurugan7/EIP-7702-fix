// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title IRegistryIndexing
/// @notice Minimal registry hook used by factory stage 1 to enable optional indexing on fresh tenants.
interface IRegistryIndexing {
    /// @notice Turn on registry-side indexes and snapshot the starting block.
    function enableIndexing() external;
}

/// @title ICapabilityActorsRegistry
/// @notice Minimal capability registry view used to verify stage-1 authorizations before stage 2.
interface ICapabilityActorsRegistry {
    /// @notice Return the direct actor assignments currently mapped to `capability`.
    function getCapabilityActors(bytes32 capability) external view returns (address[] memory);
}

/// @title OKFactoryState
/// @notice Shared state, constants, and user-facing errors/events for OKFactory and its fixed stage modules.
/// @dev The factory remains the deployment and security boundary. The companion modules execute via delegatecall so
///      CREATE2 addresses, storage, and authority checks all stay anchored at the factory address.
abstract contract OKFactoryState {
    /// @dev Access-control role granted to the temporary installer during registry setup.
    bytes32 internal constant _ADMIN_ROLE = keccak256("ADMIN_ROLE");
    /// @dev Upgrade role granted during setup so the config contract can install registry facets.
    bytes32 internal constant _UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    /// @dev Instance flag bit enabling index-backed views on the deployed tenant stack.
    uint8 internal constant _INSTANCE_FLAG_INDEXING = 0x01;
    /// @dev Instance flag bit enabling a trusted WebAuthn AuthAccount factory for the tenant stack.
    uint8 internal constant _INSTANCE_FLAG_AUTH_ACCOUNT_FACTORY = 0x02;
    /// @dev Bitmask of every supported instance flag.
    uint8 internal constant _INSTANCE_FLAGS_MASK = _INSTANCE_FLAG_INDEXING | _INSTANCE_FLAG_AUTH_ACCOUNT_FACTORY;
    /// @dev Bit offset used when packing pending stage-1 flags with the owner and tenant index.
    ///      Owner occupies the upper 160 bits, flags occupy the next 8 bits, and the index occupies the low 88 bits.
    uint256 internal constant _PENDING_FLAGS_SHIFT = 88;
    /// @dev Mask for the low 88 bits that store the tenant index in `_pendingInstances`.
    uint256 internal constant _PENDING_INDEX_MASK = (uint256(1) << _PENDING_FLAGS_SHIFT) - 1;

    /// @notice Next discovery ordinal assigned during stage-1 deployment.
    /// @dev The ordinal is metadata only and does not affect deterministic deployment addresses.
    // The EVM initializes this ordinal to zero; the stage-1 module advances it through factory delegatecall.
    // forge-lint: disable-next-line(uninitialized-state)
    uint256 public nextInstanceId;
    /// @dev Set once by OKFactory. Stage modules use it to reject direct calls while keeping runtime codehash stable.
    // OKFactory assigns address(this) in its constructor; stage modules read that shared storage through delegatecall.
    // forge-lint: disable-next-line(uninitialized-state)
    address internal _factorySelf;

    /// @notice Persisted deployment snapshot for a fully deployed tenant stack.
    /// @dev Keyed by registry in `_deployedInstances` so post-deploy discovery does not depend on mutable config.
    ///      Fields record the stage-2 deployment facts. `initialOwner` is not a live owner mirror.
    struct FactoryInstance {
        uint256 index;
        address initialOwner;
        address miniScript;
        address interact;
        address safeFactory;
        address accountFactory;
        uint8 flags;
        address authAccountFactory;
    }

    /// @dev Bootstrapped registry address to packed data: owner in upper 160 bits, flags in bits 88-95,
    ///      index in lower 88 bits.
    mapping(address => uint256) internal _bootstrappedInstances;
    /// @dev Bootstrapped registry address to the stage-2 binding commitment frozen during stage-1 bootstrap.
    mapping(address => bytes32) internal _bootstrappedStageCommitments;
    /// @dev Bootstrapped registry address to the WebAuthn AuthAccount factory config commitment.
    mapping(address => bytes32) internal _bootstrappedAuthConfigCommitments;
    /// @dev Pending registry address to packed data: owner in upper 160 bits, flags in bits 88-95,
    ///      index in lower 88 bits.
    mapping(address => uint256) internal _pendingInstances;
    /// @dev Pending registry address to commitment over the remaining stage-2 deployment bindings.
    mapping(address => bytes32) internal _pendingStageCommitments;
    /// @dev Pending registry address to the AuthAccount factory deployed during stage-1 finalize.
    mapping(address => address) internal _pendingAuthAccountFactories;
    /// @dev Deployed registry address to its tenant runtime component addresses.
    mapping(address => FactoryInstance) internal _deployedInstances;
    /// @dev Bootstrapped registry to its deterministic deployment key.
    mapping(address => bytes32) internal _bootstrappedDeploymentKeys;
    /// @dev Pending registry to its deterministic deployment key.
    mapping(address => bytes32) internal _pendingDeploymentKeys;
    /// @dev Completed registry to its deterministic deployment key.
    mapping(address => bytes32) internal _deployedInstanceKeys;
    /// @dev Deterministic deployment key to its registry from bootstrap onward. Entries are never recycled.
    mapping(bytes32 => address) internal _deploymentKeyRegistries;

    /// @notice Emitted when stage 1 bootstraps a registry shell and pauses it until stage 2 completion.
    /// @param index Discovery ordinal; it does not affect deterministic deployment addresses.
    /// @param instanceOwner Owner/controller that will receive the registry during stage 2.
    /// @param registry Registry proxy address.
    event InstanceStage1Bootstrapped(uint256 indexed index, address indexed instanceOwner, address registry);
    /// @notice Emitted when stage 1 freezes the deterministic stage-2 bindings for a bootstrapped registry.
    /// @dev Tooling can compare the emitted `stage2Commitment` against a fresh local preview to detect config drift
    ///      before stage-1 finalize executes.
    /// @param index Discovery ordinal; it does not affect deterministic deployment addresses.
    /// @param instanceOwner Owner/controller that will receive the registry during stage 2.
    /// @param registry Bootstrapped registry proxy address.
    /// @param miniScript Predicted MiniScript proxy address frozen at bootstrap.
    /// @param interact Predicted Interact proxy address frozen at bootstrap.
    /// @param safeFactory Predicted SafeFactoryWithCreate2 address frozen at bootstrap.
    /// @param accountFactory Predicted AccountFactory proxy address frozen at bootstrap.
    /// @param stage2Commitment Commitment over the frozen stage-2 bindings.
    event InstanceStage1BindingsCommitted(
        uint256 indexed index,
        address indexed instanceOwner,
        address registry,
        address miniScript,
        address interact,
        address safeFactory,
        address accountFactory,
        bytes32 stage2Commitment
    );

    /// @notice Emitted when a tenant commits a deterministic address family.
    /// @param deploymentKey Domain-separated key derived from the user salt, owner, and flags.
    /// @param index Discovery ordinal assigned by this factory; it does not affect deterministic addresses.
    /// @param registry Registry proxy address committed to the deployment key.
    event InstanceDeploymentKeyCommitted(
        bytes32 indexed deploymentKey, uint256 indexed index, address indexed registry
    );

    /// @notice Emitted when a tenant stack is fully deployed.
    /// @param index Discovery ordinal; it does not affect deterministic deployment addresses.
    /// @param instanceOwner Initial owner/controller recorded for the deployed tenant stack.
    /// @param registry Registry proxy address.
    /// @param miniScript MiniScript proxy address.
    /// @param interact Interact proxy address.
    /// @param safeFactory SafeFactoryWithCreate2 address.
    /// @param accountFactory AccountFactory proxy address.
    /// @param authAccountFactory WebAuthn AuthAccount factory address, or zero when disabled.
    event InstanceDeployed(
        uint256 indexed index,
        address indexed instanceOwner,
        address registry,
        address miniScript,
        address interact,
        address safeFactory,
        address accountFactory,
        address authAccountFactory
    );
}
