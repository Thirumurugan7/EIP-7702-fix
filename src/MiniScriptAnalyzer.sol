// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {MiniScriptBytecode} from "./MiniScriptBytecode.sol";
import {MiniScriptLimits} from "./MiniScriptLimits.sol";
import {ERCToken} from "./RegistryTypes.sol";
import {IRegistry} from "./registry/RegistryShared.sol";

/// @notice Minimal Chainlink-style metadata surface needed to bind feed decimals.
interface IAnalyzerPriceFeed {
    /// @return Decimal count reported by the live feed.
    function decimals() external view returns (uint8);
}

/// @notice Common execution-host configuration surface used by MiniScript and account vaults.
interface IAnalyzerHostConfig {
    function miniScriptHostConfig() external view returns (address engine, address registry);
}

/// @notice Registry admission check for Safe-native MiniScript execution.
interface IAnalyzerSafeAdmissionRegistry {
    function isSafeExecutionAuthorityAllowed(address safe, address authority) external view returns (bool);
}

/// @title MiniScriptAnalyzer
/// @notice Stateless bytecode dependency analysis for MiniScript hosts.
/// @dev Kept separate from the execution engine to keep both runtimes deployable
///      under EIP-170. It shares the canonical decoder with the interpreter.
contract MiniScriptAnalyzer {
    /// @dev Mutable scratch state shared by one depth-first dependency walk.
    struct DependencyWalk {
        /// @dev Base interaction whose linked namespace is authoritative.
        bytes32 rootId;
        /// @dev Deduplicated generic Registry target hashes.
        bytes32[] targets;
        /// @dev Deduplicated public CALLI interaction ids.
        bytes32[] interactions;
        /// @dev Deduplicated linked-artifact relations under `rootId`.
        bytes32[] relations;
        /// @dev Deduplicated assets read through VALUEUSD.
        bytes32[] priceAssets;
        /// @dev Number of initialized entries in `targets`.
        uint256 targetCount;
        /// @dev Number of initialized entries in `interactions`.
        uint256 interactionCount;
        /// @dev Number of initialized entries in `relations`.
        uint256 relationCount;
        /// @dev Number of initialized entries in `priceAssets`.
        uint256 priceAssetCount;
        /// @dev Raw syntactic references consumed across every visited frame.
        uint256 rawReferenceCount;
        /// @dev Active CALLI and linked frame keys used for cycle detection.
        bytes32[] activeFrames;
        /// @dev Number of initialized entries in `activeFrames`.
        uint256 activeFrameCount;
        /// @dev Number of nested CALLI and STATICLINK frames below the root.
        uint256 recursionDepth;
        /// @dev False when any reachable dependency is hidden, malformed, dynamic, or cyclic.
        bool complete;
        /// @dev True when any visited frame may price a generic target through PRICEUSD.
        bool readsStackPrice;
        /// @dev True when the root interaction is private and cannot expose linked contents.
        bool hiddenRoot;
        /// @dev True when STATICLINK relations should be followed.
        bool followLinkedArtifacts;
    }

    /// @notice Thrown when one dependency graph exceeds the raw static-reference bound.
    error StaticReferenceLimitExceeded();
    /// @notice Thrown when a Registry batch lookup returns arrays with an invalid shape.
    error RegistryResponseMalformed();
    /// @notice Thrown when a bound price feed is missing, malformed, or changes decimals.
    error InvalidPriceFeedConfiguration();
    /// @notice Thrown when opaque generic-call analysis resolves the configured execution engine.
    error GenericEngineTargetForbidden();
    /// @notice Thrown when MiniScript execution is not hosted by an authenticated vault.
    error DelegatecallContextRequired();

    uint256 private constant MAX_STATIC_REFERENCES = 128;
    bytes32 private constant EXECUTION_DEPENDENCY_TYPEHASH = keccak256(
        "ExecutionDependencyV2(bytes32[] interactionBindings,bytes32[] linkedBindings,bytes32[] targetBindings,bytes32[] priceBindings,bytes32 priceConfigHash)"
    );

    /// @notice Authenticate a configured execution host or an admitted Safe execution context.
    /// @return safeHost True only when execution is hosted by a managed Safe.
    function requireExecutionHost(
        address logicalHost,
        address expectedEngine,
        address expectedRegistry,
        address executionAuthority
    ) external view returns (bool safeHost) {
        (bool valid, address configuredEngine, address configuredRegistry) = _hostConfig(logicalHost);
        if (valid && configuredEngine == expectedEngine && configuredRegistry == expectedRegistry) return false;
        if (logicalHost == expectedEngine || executionAuthority == address(0)) revert DelegatecallContextRequired();

        (valid, configuredEngine, configuredRegistry) = _hostConfig(executionAuthority);
        if (!valid || configuredEngine != expectedEngine || configuredRegistry != expectedRegistry) {
            revert DelegatecallContextRequired();
        }

        (bool ok, bytes memory result) = expectedRegistry.staticcall(
            abi.encodeCall(
                IAnalyzerSafeAdmissionRegistry.isSafeExecutionAuthorityAllowed, (logicalHost, executionAuthority)
            )
        );
        if (!ok || result.length != 32 || !abi.decode(result, (bool))) revert DelegatecallContextRequired();
        return true;
    }

    function _hostConfig(address host)
        private
        view
        returns (bool valid, address configuredEngine, address registryAddr)
    {
        (bool ok, bytes memory result) = host.staticcall(abi.encodeCall(IAnalyzerHostConfig.miniScriptHostConfig, ()));
        if (!ok || result.length != 64) return (false, address(0), address(0));
        (configuredEngine, registryAddr) = abi.decode(result, (address, address));
        valid = registryAddr != address(0) && registryAddr.code.length != 0;
    }

    /// @notice Hash the exact public catalog state reachable by one interaction.
    /// @dev Returns zero for a private root or a graph with a hidden, malformed,
    ///      dynamic, cyclic, or over-depth child. Interact uses that sentinel to
    ///      bind approvals to the conservative full catalog revision.
    /// @param registryAddr Registry whose catalog is authoritative.
    /// @param engineAddr Configured engine excluded from opaque generic calls.
    /// @param interactionId Public root interaction to analyze.
    /// @return bindingHash Exact dependency hash, or zero when the graph is incomplete.
    function getExecutionDependencyHash(address registryAddr, address engineAddr, bytes32 interactionId)
        external
        view
        returns (bytes32 bindingHash)
    {
        IRegistry registry = IRegistry(registryAddr);
        bytes memory script = registry.getInteractionScript(interactionId);
        if (script.length == 0) return bytes32(0);

        DependencyWalk memory walk = _newWalk(interactionId, true, true);
        _walkDependencies(registry, script, walk);
        if (!walk.complete) return bytes32(0);
        return _dependencyHash(registry, walk, engineAddr);
    }

    /// @notice Hash exact catalog dependencies reachable from an inline policy program.
    /// @param registryAddr Registry whose catalog is authoritative.
    /// @param engineAddr Configured engine excluded from opaque generic calls.
    /// @param program Policy MiniScript bytecode.
    /// @param subjectInteractionId Interaction whose linked namespace is visible to the program.
    /// @return dependencyHash Exact dependency hash, or zero when analysis is incomplete.
    /// @return complete True when every reachable dependency was public and structurally analyzable.
    function getProgramDependencyHash(
        address registryAddr,
        address engineAddr,
        bytes calldata program,
        bytes32 subjectInteractionId
    ) external view returns (bytes32 dependencyHash, bool complete) {
        IRegistry registry = IRegistry(registryAddr);
        if (program.length == 0) {
            // An empty program cannot read its subject or any linked artifact.
            // Retain the Registry pause gate without hashing the subject bundle,
            // and use the same dependency encoder and target-response validation.
            // This call enforces the Registry pause gate; an empty program has no dependency on the returned flags.
            // forge-lint: disable-next-line(unused-return)
            if (subjectInteractionId != bytes32(0)) registry.getInteractionFlags(subjectInteractionId);
            DependencyWalk memory emptyWalk;
            return (_dependencyHash(registry, emptyWalk, engineAddr), true);
        }
        DependencyWalk memory walk = _newWalk(subjectInteractionId, false, true);
        if (subjectInteractionId != bytes32(0)) {
            try registry.getInteractionContentHash(subjectInteractionId) returns (bytes32) {}
            catch {
                walk.hiddenRoot = registry.getInteractionBindingHash(subjectInteractionId)
                    != registry.getInteractionBundleHash(subjectInteractionId);
            }
        }
        _walkDependencies(registry, program, walk);
        if (!walk.complete) return (bytes32(0), false);
        return (_dependencyHash(registry, walk, engineAddr), true);
    }

    function _newWalk(bytes32 rootId, bool seedRoot, bool followLinkedArtifacts)
        private
        pure
        returns (DependencyWalk memory walk)
    {
        walk.rootId = rootId;
        walk.targets = new bytes32[](MAX_STATIC_REFERENCES);
        walk.interactions = new bytes32[](MAX_STATIC_REFERENCES);
        walk.relations = new bytes32[](MAX_STATIC_REFERENCES);
        walk.priceAssets = new bytes32[](MAX_STATIC_REFERENCES);
        // A dependency-hash walk also seeds the root interaction for cycle
        // detection, so its active-frame set can contain root plus max depth.
        walk.activeFrames = new bytes32[](MiniScriptLimits.MAX_RECURSION_DEPTH + 1);
        walk.complete = true;
        walk.followLinkedArtifacts = followLinkedArtifacts;
        if (seedRoot) {
            walk.interactions[walk.interactionCount++] = rootId;
            walk.activeFrames[0] = _calliFrameKey(rootId);
            walk.activeFrameCount = 1;
        }
    }

    function _walkDependencies(IRegistry registry, bytes memory script, DependencyWalk memory walk) private view {
        (bool structurallyValid, MiniScriptBytecode.DecodedReferences memory decoded) =
            MiniScriptBytecode.tryDecode(script);
        if (!structurallyValid) {
            // A dependency hash must bind every reachable reference; invalid bounds or feed metadata must fail
            // closed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (decoded.referenceLimitExceeded) revert StaticReferenceLimitExceeded();
            walk.complete = false;
            return;
        }
        if (
            walk.rawReferenceCount > MAX_STATIC_REFERENCES
                || decoded.rawReferenceCount > MAX_STATIC_REFERENCES - walk.rawReferenceCount
        ) {
            // A dependency hash must bind every reachable reference; invalid bounds must fail closed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert StaticReferenceLimitExceeded();
        }
        walk.rawReferenceCount += decoded.rawReferenceCount;
        if (!decoded.complete) walk.complete = false;
        if (decoded.readsStackPrice) walk.readsStackPrice = true;

        for (uint256 i; i < decoded.targets.length; ++i) {
            walk.targetCount = _appendUnique(walk.targets, walk.targetCount, decoded.targets[i]);
        }
        for (uint256 i; i < decoded.priceAssets.length; ++i) {
            walk.priceAssetCount = _appendUnique(walk.priceAssets, walk.priceAssetCount, decoded.priceAssets[i]);
        }
        for (uint256 i; i < decoded.calliIds.length; ++i) {
            bytes32 childId = decoded.calliIds[i];
            bytes32 frameKey = _calliFrameKey(childId);
            if (_walkFrameActive(walk, frameKey) || walk.recursionDepth == MiniScriptLimits.MAX_RECURSION_DEPTH) {
                walk.complete = false;
                continue;
            }
            uint256 priorCount = walk.interactionCount;
            walk.interactionCount = _appendUnique(walk.interactions, walk.interactionCount, childId);
            if (walk.interactionCount == priorCount) continue;
            // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
            // weaken its commitment.
            // forge-lint: disable-next-line(calls-loop)
            bytes memory childScript = registry.getInteractionScript(childId);
            // A syntactically declared child may sit behind an untaken branch.
            // Treat a missing, private, or malformed child as an opaque dependency
            // during analysis. Strict frame validation still rejects it before
            // execution can perform an unprotected effect.
            if (childScript.length == 0 || !MiniScriptBytecode.isStructurallyValid(childScript)) {
                walk.complete = false;
                continue;
            }
            _pushWalkFrame(walk, frameKey);
            _walkDependencies(registry, childScript, walk);
            _popWalkFrame(walk);
        }
        if (!walk.followLinkedArtifacts) return;
        for (uint256 i; i < decoded.linkedRelations.length; ++i) {
            bytes32 relation = decoded.linkedRelations[i];
            if (walk.hiddenRoot) {
                walk.complete = false;
                continue;
            }
            bytes32 frameKey = _linkFrameKey(walk.rootId, relation);
            if (_walkFrameActive(walk, frameKey) || walk.recursionDepth == MiniScriptLimits.MAX_RECURSION_DEPTH) {
                walk.complete = false;
                continue;
            }
            uint256 priorCount = walk.relationCount;
            walk.relationCount = _appendUnique(walk.relations, walk.relationCount, relation);
            if (walk.relationCount == priorCount) continue;
            // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
            // weaken its commitment.
            // forge-lint: disable-next-line(calls-loop)
            bytes memory linkedScript = registry.getLinkedArtifact(walk.rootId, relation);
            // Missing public artifacts have an explicit binding and no hidden graph.
            if (linkedScript.length == 0) continue;
            if (!MiniScriptBytecode.isStructurallyValid(linkedScript)) {
                walk.complete = false;
                continue;
            }
            _pushWalkFrame(walk, frameKey);
            _walkDependencies(registry, linkedScript, walk);
            _popWalkFrame(walk);
        }
    }

    /// @dev Bind every reachable interaction, artifact, target, price feed, and runtime price setting.
    function _dependencyHash(IRegistry registry, DependencyWalk memory walk, address engineAddr)
        private
        view
        returns (bytes32)
    {
        if (engineAddr == address(0)) revert GenericEngineTargetForbidden();
        bytes32[] memory interactionBindings = new bytes32[](walk.interactionCount);
        for (uint256 i; i < walk.interactionCount; ++i) {
            // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
            // weaken its commitment.
            // forge-lint: disable-next-line(calls-loop)
            interactionBindings[i] = registry.getInteractionBindingHash(walk.interactions[i]);
        }
        bytes32[] memory linkedBindings = new bytes32[](walk.relationCount);
        for (uint256 i; i < walk.relationCount; ++i) {
            // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
            // weaken its commitment.
            // forge-lint: disable-next-line(calls-loop)
            linkedBindings[i] = registry.getLinkedArtifactBindingHash(walk.rootId, walk.relations[i]);
        }

        bytes32[] memory hashes = _copyBytes32(walk.targets, walk.targetCount);
        (address[] memory targets, bool[] memory allowed) = registry.getAddressesByHash(hashes);
        if (targets.length != hashes.length || allowed.length != hashes.length) {
            revert RegistryResponseMalformed();
        }
        bytes32[] memory targetBindings = new bytes32[](hashes.length);
        for (uint256 i; i < hashes.length; ++i) {
            // A dependency hash must bind every reachable reference; invalid bounds or feed metadata must fail
            // closed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (targets[i] == engineAddr) revert GenericEngineTargetForbidden();
            targetBindings[i] = _targetBinding(registry, hashes[i], targets[i], allowed[i], walk.readsStackPrice);
        }

        bytes32[] memory priceBindings = new bytes32[](walk.priceAssetCount);
        uint256 globalStaleness = walk.readsStackPrice || walk.priceAssetCount != 0 ? registry.getMaxFeedStaleness() : 0;
        for (uint256 i; i < walk.priceAssetCount; ++i) {
            priceBindings[i] = _priceBinding(registry, walk.priceAssets[i], globalStaleness);
        }
        bytes32 priceConfigHash =
            walk.readsStackPrice || walk.priceAssetCount != 0 ? keccak256(abi.encode(globalStaleness)) : bytes32(0);
        return keccak256(
            abi.encode(
                EXECUTION_DEPENDENCY_TYPEHASH,
                interactionBindings,
                linkedBindings,
                targetBindings,
                priceBindings,
                priceConfigHash
            )
        );
    }

    function _priceBinding(IRegistry registry, bytes32 asset, uint256 globalStaleness) private view returns (bytes32) {
        if (asset == bytes32(0)) {
            // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
            // weaken its commitment.
            // forge-lint: disable-next-line(calls-loop)
            (address feed, uint8 expectedDecimals) = registry.getNativeUsdFeedConfig();
            _requireFeedDecimals(feed, expectedDecimals);
            uint64 nativeFeedMaxAge = _requireFeedMaxAge(registry, feed);
            return keccak256(abi.encode(asset, feed, expectedDecimals, nativeFeedMaxAge, globalStaleness));
        }

        // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would weaken
        // its commitment.
        // forge-lint: disable-next-line(calls-loop)
        ERCToken memory token = registry.getTokenByHash(asset);
        _requireFeedDecimals(token.price, token.priceFeedDecimals);
        uint64 tokenFeedMaxAge = _requireFeedMaxAge(registry, token.price);
        // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would weaken
        // its commitment.
        // forge-lint: disable-next-line(calls-loop)
        (address[] memory resolved, bool[] memory ok) = registry.getAddressesByHash(_single(asset));
        // A dependency hash must bind every reachable reference; invalid bounds or feed metadata must fail closed.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (resolved.length != 1 || ok.length != 1) revert RegistryResponseMalformed();
        return keccak256(
            abi.encode(
                asset,
                token,
                // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
                // weaken its commitment.
                // forge-lint: disable-next-line(calls-loop)
                registry.getTokenFlagsByHash(asset),
                resolved[0],
                ok[0],
                // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
                // weaken its commitment.
                // forge-lint: disable-next-line(calls-loop)
                registry.getContractFlagsByHash(asset),
                tokenFeedMaxAge,
                globalStaleness
            )
        );
    }

    function _targetBinding(IRegistry registry, bytes32 hash, address target, bool allowed, bool readsStackPrice)
        private
        view
        returns (bytes32)
    {
        // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would weaken
        // its commitment.
        // forge-lint: disable-next-line(calls-loop)
        bool isToken = registry.isTokenByHash(hash);
        ERCToken memory token;
        uint256 tokenFlags = 0;
        uint64 feedMaxAge = 0;
        if (isToken) {
            // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
            // weaken its commitment.
            // forge-lint: disable-next-line(calls-loop)
            token = registry.getTokenByHash(hash);
            // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
            // weaken its commitment.
            // forge-lint: disable-next-line(calls-loop)
            tokenFlags = registry.getTokenFlagsByHash(hash);
            if (readsStackPrice) {
                _requireFeedDecimals(token.price, token.priceFeedDecimals);
                feedMaxAge = _requireFeedMaxAge(registry, token.price);
            }
        }
        return keccak256(
            abi.encode(
                hash,
                target,
                allowed,
                // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would
                // weaken its commitment.
                // forge-lint: disable-next-line(calls-loop)
                registry.getContractFlagsByHash(hash),
                isToken,
                keccak256(abi.encode(token)),
                tokenFlags,
                feedMaxAge
            )
        );
    }

    /// @dev Require the mandatory reviewed heartbeat that makes one feed executable.
    function _requireFeedMaxAge(IRegistry registry, address feed) private view returns (uint64 maxAge) {
        // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would weaken
        // its commitment.
        // forge-lint: disable-next-line(calls-loop)
        maxAge = registry.getFeedMaxAge(feed);
        // A dependency hash must bind every reachable reference; invalid bounds or feed metadata must fail closed.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (maxAge == 0) revert InvalidPriceFeedConfiguration();
    }

    /// @dev Require a deployed feed whose live decimals match the Registry-bound value.
    function _requireFeedDecimals(address feed, uint8 expectedDecimals) private view {
        if (feed == address(0) || feed.code.length == 0 || expectedDecimals > 36) {
            // A dependency hash must bind every reachable reference; invalid bounds or feed metadata must fail
            // closed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert InvalidPriceFeedConfiguration();
        }
        // Bounded dependency traversal requires per-reference STATICCALL reads; skipping a dependency would weaken
        // its commitment.
        // forge-lint: disable-next-line(calls-loop)
        try IAnalyzerPriceFeed(feed).decimals() returns (uint8 actual) {
            // A dependency hash must bind every reachable reference; invalid bounds or feed metadata must fail
            // closed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (actual != expectedDecimals || actual > 36) revert InvalidPriceFeedConfiguration();
        } catch {
            // A dependency hash must bind every reachable reference; invalid bounds or feed metadata must fail
            // closed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert InvalidPriceFeedConfiguration();
        }
    }

    function _walkFrameActive(DependencyWalk memory walk, bytes32 frameKey) private pure returns (bool) {
        for (uint256 i; i < walk.activeFrameCount; ++i) {
            if (walk.activeFrames[i] == frameKey) return true;
        }
        return false;
    }

    function _pushWalkFrame(DependencyWalk memory walk, bytes32 frameKey) private pure {
        walk.activeFrames[walk.activeFrameCount++] = frameKey;
        ++walk.recursionDepth;
    }

    function _popWalkFrame(DependencyWalk memory walk) private pure {
        --walk.activeFrameCount;
        delete walk.activeFrames[walk.activeFrameCount];
        --walk.recursionDepth;
    }

    function _appendUnique(bytes32[] memory values, uint256 count, bytes32 value) private pure returns (uint256) {
        for (uint256 i; i < count; ++i) {
            if (values[i] == value) return count;
        }
        // A dependency hash must bind every reachable reference; invalid bounds or feed metadata must fail closed.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (count == MAX_STATIC_REFERENCES) revert StaticReferenceLimitExceeded();
        values[count] = value;
        return count + 1;
    }

    function _copyBytes32(bytes32[] memory values, uint256 count) private pure returns (bytes32[] memory out) {
        out = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            out[i] = values[i];
        }
    }

    function _single(bytes32 value) private pure returns (bytes32[] memory values) {
        values = new bytes32[](1);
        values[0] = value;
    }

    function _linkFrameKey(bytes32 baseId, bytes32 relation) private pure returns (bytes32) {
        return keccak256(abi.encode(uint8(1), baseId, relation));
    }

    function _calliFrameKey(bytes32 interactionId) private pure returns (bytes32) {
        return keccak256(abi.encode(uint8(2), interactionId));
    }
}
