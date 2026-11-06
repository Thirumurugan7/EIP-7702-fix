// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "../../Delegation7702.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {EntityFlags} from "../../EntityFlags.sol";
import {PagedIndex} from "../../PagedIndex.sol";
import {AggregatorV3Interface} from "../../PriceModule.sol";
import {
    CatalogImportKind,
    ContractAddress,
    ContractImportProvenance,
    DappContract,
    ERCToken,
    ImportProvenance,
    TokenImportProvenance
} from "../../RegistryTypes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {KeccakHelpers as KH} from "../../registry/Hashing.sol";
import {Authority, ContractsStorage, SyncStorage, TokensStorage} from "../../registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {RegistryInteractionSyncFacet} from "./RegistryInteractionSyncFacet.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @notice Trusted-source contract catalog surface used during value imports.
interface IRegistrySyncContractSource {
    /// @notice Return source ownership metadata and the latest published version.
    function getContractMetadata(string calldata org, string calldata id)
        external
        view
        returns (address submitter, uint32 latestVersion);
    /// @notice Return one exact source contract version.
    function getContractVersion(string calldata org, string calldata id, uint32 version)
        external
        view
        returns (ContractAddress memory);
    /// @notice Resolve a source label to its contract data and version.
    function getContractByLabel(string calldata org, string calldata id, bytes32 label)
        external
        view
        returns (ContractAddress memory, uint32);
    /// @notice Return source entity flags for one contract.
    function getContractFlags(string calldata org, string calldata id) external view returns (uint256);
}

/// @notice Trusted-source token catalog surface used during value imports.
interface IRegistrySyncTokenSource {
    /// @notice Return one complete source token record, including bound feed decimals.
    function getToken(string calldata org, string calldata id) external view returns (ERCToken memory);
    /// @notice Return source entity flags for one token.
    function getTokenFlags(string calldata org, string calldata id) external view returns (uint256);
}

/// @title RegistrySyncFacet
/// @notice Allowlists source registries and imports contracts and tokens by value.
/// @dev Interaction bundles are isolated in the companion `RegistryInteractionSyncFacet`
///      so both facet runtimes remain comfortably below the EIP-170 size limit.
contract RegistrySyncFacet is FacetGuard {
    using PagedIndex for PagedIndex.Index;

    /// @notice Initial sync-facet version.
    uint256 public constant VERSION = 1;
    /// @notice Registry administrator role recognized by sync authorization.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    /// @notice Companion implementation that handles complete interaction-bundle imports.
    /// @dev Read this getter directly from the deployed sync implementation while
    ///      installing selectors; it is not dispatcher storage.
    address public interactionSyncFacet;

    /// @notice Deploy the companion interaction-sync implementation once per sync facet.
    constructor() {
        interactionSyncFacet = address(new RegistryInteractionSyncFacet());
    }

    /// @notice Thrown when the logical actor lacks the required sync capability.
    error NotAuthorized();
    /// @notice Thrown when an organization or catalog identifier is empty.
    error EmptyId();
    /// @notice Thrown when a requested source Registry is the zero address.
    error SourceRegistryZero();
    /// @notice Thrown when a requested source Registry has no deployed code.
    error SourceRegistryNotContract();
    /// @notice Thrown when a source Registry is not currently allowlisted.
    error SourceRegistryNotAllowed(address sourceRegistry);
    /// @notice Thrown when a source contract version differs from the expected value.
    error SourceContractVersionInvalid();
    /// @notice Thrown when source contract data or flags differ from the expected snapshot.
    error SourceContractMismatch();
    /// @notice Thrown when a source contract label does not resolve to the expected version.
    error SourceContractLabelMismatch();
    /// @notice Thrown when source token data or flags differ from the expected snapshot.
    error SourceTokenMismatch();
    /// @notice Thrown when imported contract flags contain unsupported bits.
    error InvalidContractFlags();
    /// @notice Thrown when imported token flags contain unsupported bits.
    error InvalidTokenFlags();
    /// @notice Thrown when a token feed is missing code or disagrees with bound metadata.
    error TokenFeedInvalid();
    /// @notice Thrown when an imported contract version uses the zero target address.
    error ContractAddressZero();
    /// @notice The imported address (or its implementation) is an EOA carrying an EIP-7702 delegation.
    error ContractAddressDelegated(address addr);
    /// @notice Thrown when imported token decimals exceed the protocol bound.
    error TokenDecimalsTooHigh(uint8 decimals);

    /// @notice Emitted after source trust is enabled or disabled.
    event SyncSourceSet(address indexed sourceRegistry, bool allowed, address indexed operator);
    /// @notice Emitted after one exact source contract version is imported.
    event ContractImported(
        address indexed sourceRegistry,
        bytes32 indexed key,
        uint32 indexed localVersion,
        uint32 sourceVersion,
        bytes32 label,
        address operator
    );
    /// @notice Emitted after one complete token snapshot is imported.
    event TokenImported(address indexed sourceRegistry, bytes32 indexed key, address indexed operator);

    /// @notice Enable or disable a Registry as a trusted catalog source.
    /// @dev Source trust changes use the sync-source timelock category. Disabling
    ///      remains possible after a source loses code.
    /// @param sourceRegistry Registry whose trust status is changed.
    /// @param allowed True to permit subsequent imports, false to revoke trust.
    function setSyncSourceAllowed(address sourceRegistry, bool allowed) external whenNotPausedD nonReentrantD {
        address actor = _msgSenderD();
        if (!_isSyncAdmin(actor)) {
            revert NotAuthorized();
        }
        if (sourceRegistry == address(0)) revert SourceRegistryZero();
        // Disabling is always permitted so a source that self-destructed or lost
        // code cannot remain stuck in the enumerable trust set.
        if (allowed && !Delegation7702.hasContractCode(sourceRegistry)) revert SourceRegistryNotContract();

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categorySyncSource(),
                scope: _sourceScope(sourceRegistry),
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setSyncSourceAllowed.selector, sourceRegistry, allowed)
        );
        if (!executing) {
            return;
        }

        SyncStorage.setSourceAllowed(SyncStorage.getLayout(), sourceRegistry, allowed);
        // Import entrypoints hold nonReentrantD; source/feed reads are STATICCALLs and import/index writes are
        // internal.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SyncSourceSet(sourceRegistry, allowed, actor);
    }

    /// @notice Import one exact active contract version from an allowlisted source.
    /// @dev This convenience form expects zero entity flags.
    /// @param sourceRegistry Trusted Registry publishing the source snapshot.
    /// @param org Lowercase organization identifier.
    /// @param id Lowercase contract identifier.
    /// @param sourceVersion Exact source version to copy.
    /// @param expectedData Exact address, version tag, and implementation expected at execution.
    /// @param label Optional source label that must resolve to `sourceVersion`.
    function importContract(
        address sourceRegistry,
        string calldata org,
        string calldata id,
        uint32 sourceVersion,
        ContractAddress calldata expectedData,
        bytes32 label
    ) external whenNotPausedD nonReentrantD {
        _importContract(sourceRegistry, org, id, sourceVersion, expectedData, label, 0, false);
    }

    /// @notice Import one exact contract version and its explicit entity flags.
    /// @param sourceRegistry Trusted Registry publishing the source snapshot.
    /// @param org Lowercase organization identifier.
    /// @param id Lowercase contract identifier.
    /// @param sourceVersion Exact source version to copy.
    /// @param expectedData Exact address, version tag, and implementation expected at execution.
    /// @param label Optional source label that must resolve to `sourceVersion`.
    /// @param expectedFlags Exact source flags to copy.
    function importContractWithFlags(
        address sourceRegistry,
        string calldata org,
        string calldata id,
        uint32 sourceVersion,
        ContractAddress calldata expectedData,
        bytes32 label,
        uint256 expectedFlags
    ) external whenNotPausedD nonReentrantD {
        _importContract(sourceRegistry, org, id, sourceVersion, expectedData, label, expectedFlags, true);
    }

    /// @dev Validate, timelock, revalidate, and persist one contract snapshot.
    function _importContract(
        address sourceRegistry,
        string calldata org,
        string calldata id,
        uint32 sourceVersion,
        ContractAddress calldata expectedData,
        bytes32 label,
        uint256 expectedFlags,
        bool explicitFlags
    ) private {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        if (expectedData.addr == address(0)) revert ContractAddressZero();
        _requireLowercase(org);
        _requireLowercase(id);
        if (sourceVersion == 0) revert SourceContractVersionInvalid();
        if (expectedFlags & ~EntityFlags.MASK != 0) revert InvalidContractFlags();

        address actor = _msgSenderD();
        if (!_canImportContract(actor)) {
            revert NotAuthorized();
        }

        bytes32 key = KH.joinSlash(org, id);
        _requireAllowedSource(sourceRegistry);

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categorySyncContract(),
                scope: _catalogScope(sourceRegistry, key),
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            explicitFlags
                ? abi.encodeWithSelector(
                    this.importContractWithFlags.selector,
                    sourceRegistry,
                    org,
                    id,
                    sourceVersion,
                    expectedData,
                    label,
                    expectedFlags
                )
                : abi.encodeWithSelector(
                    this.importContract.selector, sourceRegistry, org, id, sourceVersion, expectedData, label
                )
        );
        if (!executing) {
            return;
        }

        _requireAllowedSource(sourceRegistry);
        _verifySourceContract(sourceRegistry, org, id, sourceVersion, expectedData, label, expectedFlags);

        // Imported entries obey the same rule as direct registration: no EIP-7702 delegated EOAs.
        if (Delegation7702.isDelegated(expectedData.addr) || Delegation7702.isDelegated(expectedData.implementation)) {
            revert ContractAddressDelegated(expectedData.addr);
        }
        ContractsStorage.Layout storage cl = ContractsStorage.getLayout();
        uint32 localVersion = ContractsStorage.addVersion(cl, key, expectedData, label);
        DappContract storage contract_ = ContractsStorage.get(cl, key);
        if (localVersion == 1) {
            contract_.org = org;
            contract_.id = id;
            if (Authority._getSubmitter(key) == address(0)) {
                Authority._setSubmitterIfUnset(key, actor);
            }
            cl.contractKeys.insert(key);
        }
        ContractsStorage.setFlags(cl, key, expectedFlags);

        SyncStorage.recordContractImport(
            SyncStorage.getLayout(),
            key,
            ContractImportProvenance({
                common: ImportProvenance({
                    sourceRegistry: sourceRegistry,
                    importedAt: SafeCast.toUint64(block.timestamp),
                    importedBy: actor,
                    sourceKeyHash: key,
                    sourcePayloadHash: _hashContractPayload(sourceVersion, label, expectedData, expectedFlags),
                    importKind: CatalogImportKind.Contract
                }),
                sourceVersion: sourceVersion,
                label: label,
                localVersion: localVersion
            })
        );

        // Import entrypoints hold nonReentrantD; source/feed reads are STATICCALLs and import/index writes are
        // internal.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ContractImported(sourceRegistry, key, localVersion, sourceVersion, label, actor);
    }

    /// @notice Import one exact active token snapshot from an allowlisted source.
    /// @dev This convenience form expects zero entity flags.
    /// @param sourceRegistry Trusted Registry publishing the source snapshot.
    /// @param expectedData Exact token metadata and price-feed binding expected at execution.
    function importToken(address sourceRegistry, ERCToken calldata expectedData) external whenNotPausedD nonReentrantD {
        _importToken(sourceRegistry, expectedData, 0, false);
    }

    /// @notice Import one exact token snapshot and its explicit entity flags.
    /// @param sourceRegistry Trusted Registry publishing the source snapshot.
    /// @param expectedData Exact token metadata and price-feed binding expected at execution.
    /// @param expectedFlags Exact source flags to copy.
    function importTokenWithFlags(address sourceRegistry, ERCToken calldata expectedData, uint256 expectedFlags)
        external
        whenNotPausedD
        nonReentrantD
    {
        _importToken(sourceRegistry, expectedData, expectedFlags, true);
    }

    /// @dev Validate, timelock, revalidate, and persist one token snapshot.
    function _importToken(
        address sourceRegistry,
        ERCToken calldata expectedData,
        uint256 expectedFlags,
        bool explicitFlags
    ) private {
        if (bytes(expectedData.org).length == 0 || bytes(expectedData.id).length == 0) {
            revert EmptyId();
        }
        if (expectedData.decimals > 36) revert TokenDecimalsTooHigh(expectedData.decimals);
        _requireLowercase(expectedData.org);
        _requireLowercase(expectedData.id);
        if (expectedFlags & ~EntityFlags.MASK != 0) revert InvalidTokenFlags();

        address actor = _msgSenderD();
        if (!_canImportToken(actor)) {
            revert NotAuthorized();
        }

        bytes32 key = KH.joinSlash(expectedData.org, expectedData.id);
        _requireAllowedSource(sourceRegistry);

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categorySyncToken(),
                scope: _catalogScope(sourceRegistry, key),
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            explicitFlags
                ? abi.encodeWithSelector(
                    this.importTokenWithFlags.selector, sourceRegistry, expectedData, expectedFlags
                )
                : abi.encodeWithSelector(this.importToken.selector, sourceRegistry, expectedData)
        );
        if (!executing) {
            return;
        }

        _requireAllowedSource(sourceRegistry);
        _verifySourceToken(sourceRegistry, expectedData, expectedFlags);
        _validateTokenFeed(expectedData.price, expectedData.priceFeedDecimals);
        if (!ContractsStorage.exists(ContractsStorage.getLayout(), key)) {
            revert("Contract not found for token");
        }

        TokensStorage.Layout storage tl = TokensStorage.getLayout();
        ERCToken storage token = tl.tokens[key];
        bool fresh = bytes(token.id).length == 0;
        token.org = expectedData.org;
        token.id = expectedData.id;
        token.symbol = expectedData.symbol;
        token.decimals = expectedData.decimals;
        token.price = expectedData.price;
        token.priceFeedDecimals = expectedData.priceFeedDecimals;
        TokensStorage.setFlags(tl, key, expectedFlags);
        if (fresh) {
            tl.tokenKeys.insert(key);
        }

        bytes32 submitterKey = KH.tokenAuthKey(expectedData.org, expectedData.id);
        if (Authority._getSubmitter(submitterKey) == address(0)) {
            Authority._setSubmitterIfUnset(submitterKey, actor);
        }

        SyncStorage.recordTokenImport(
            SyncStorage.getLayout(),
            key,
            TokenImportProvenance({
                common: ImportProvenance({
                    sourceRegistry: sourceRegistry,
                    importedAt: SafeCast.toUint64(block.timestamp),
                    importedBy: actor,
                    sourceKeyHash: key,
                    sourcePayloadHash: _hashTokenPayloadCalldata(expectedData, expectedFlags),
                    importKind: CatalogImportKind.Token
                })
            })
        );

        // Import entrypoints hold nonReentrantD; source/feed reads are STATICCALLs and import/index writes are
        // internal.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TokenImported(sourceRegistry, key, actor);
    }

    /// @dev Return whether `actor` has global Registry sync administration authority.
    function _isSyncAdmin(address actor) private view returns (bool) {
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.REGISTRY_MANAGER)) return true;
        return false;
    }

    /// @dev Accept global sync administration or contract-write capability.
    function _canImportContract(address actor) private view returns (bool) {
        if (_isSyncAdmin(actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.CONTRACT_WRITE)) return true;
        return false;
    }

    /// @dev Accept global sync administration or token-manager capability.
    function _canImportToken(address actor) private view returns (bool) {
        if (_isSyncAdmin(actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.TOKEN_MANAGER)) return true;
        return false;
    }

    /// @dev Require a deployed source currently present in the sync allowlist.
    function _requireAllowedSource(address sourceRegistry) private view {
        if (sourceRegistry == address(0)) revert SourceRegistryZero();
        if (!Delegation7702.hasContractCode(sourceRegistry)) revert SourceRegistryNotContract();
        if (!SyncStorage.getLayout().isSyncSourceAllowed[sourceRegistry]) {
            revert SourceRegistryNotAllowed(sourceRegistry);
        }
    }

    /// @dev Re-read source state and require an exact version, flag, address, and label match.
    function _verifySourceContract(
        address sourceRegistry,
        string calldata org,
        string calldata id,
        uint32 sourceVersion,
        ContractAddress calldata expectedData,
        bytes32 label,
        uint256 expectedFlags
    ) private view {
        // Only the latest version is needed here; the exact versioned data, flags, and label are checked below.
        // forge-lint: disable-next-line(unused-return)
        (, uint32 latestVersion) = IRegistrySyncContractSource(sourceRegistry).getContractMetadata(org, id);
        if (latestVersion < sourceVersion) revert SourceContractMismatch();
        if (IRegistrySyncContractSource(sourceRegistry).getContractFlags(org, id) != expectedFlags) {
            revert SourceContractMismatch();
        }

        ContractAddress memory actual =
            IRegistrySyncContractSource(sourceRegistry).getContractVersion(org, id, sourceVersion);
        if (
            _hashContractAddress(actual.addr, actual.version, actual.implementation)
                != _hashContractAddress(expectedData.addr, expectedData.version, expectedData.implementation)
        ) {
            revert SourceContractMismatch();
        }

        if (label != bytes32(0)) {
            (ContractAddress memory labeledData, uint32 labeledVersion) =
                IRegistrySyncContractSource(sourceRegistry).getContractByLabel(org, id, label);
            if (
                labeledVersion != sourceVersion
                    || _hashContractAddress(labeledData.addr, labeledData.version, labeledData.implementation)
                        != _hashContractAddress(expectedData.addr, expectedData.version, expectedData.implementation)
            ) {
                revert SourceContractLabelMismatch();
            }
        }
    }

    /// @dev Re-read source state and require an exact token, flag, and feed-metadata match.
    function _verifySourceToken(address sourceRegistry, ERCToken calldata expectedData, uint256 expectedFlags)
        private
        view
    {
        ERCToken memory actual = IRegistrySyncTokenSource(sourceRegistry).getToken(expectedData.org, expectedData.id);
        uint256 actualFlags = IRegistrySyncTokenSource(sourceRegistry).getTokenFlags(expectedData.org, expectedData.id);
        if (_hashTokenPayloadMemory(actual, actualFlags) != _hashTokenPayloadCalldata(expectedData, expectedFlags)) {
            revert SourceTokenMismatch();
        }
    }

    /// @dev Hash the semantic address fields of one contract version.
    function _hashContractAddress(address addr, bytes32 version, address implementation)
        private
        pure
        returns (bytes32)
    {
        return _hashEncoded(abi.encode(addr, version, implementation));
    }

    /// @dev Hash all source state bound by one contract import.
    function _hashContractPayload(
        uint32 sourceVersion,
        bytes32 label,
        ContractAddress calldata expectedData,
        uint256 flags
    ) private pure returns (bytes32) {
        return _hashEncoded(
            abi.encode(
                sourceVersion, label, expectedData.addr, expectedData.version, expectedData.implementation, flags
            )
        );
    }

    /// @dev Hash all source state bound by one token import from memory.
    function _hashTokenPayloadMemory(ERCToken memory data, uint256 flags) private pure returns (bytes32) {
        return _hashEncoded(
            abi.encode(data.org, data.id, data.symbol, data.decimals, data.price, data.priceFeedDecimals, flags)
        );
    }

    /// @dev Hash all source state bound by one token import from calldata.
    function _hashTokenPayloadCalldata(ERCToken calldata data, uint256 flags) private pure returns (bytes32) {
        return _hashEncoded(
            abi.encode(data.org, data.id, data.symbol, data.decimals, data.price, data.priceFeedDecimals, flags)
        );
    }

    /// @dev Derive the timelock scope for one source trust decision.
    function _sourceScope(address sourceRegistry) private pure returns (bytes32) {
        return bytes32(uint256(uint160(sourceRegistry)));
    }

    /// @dev Derive a source-and-key-specific catalog import scope.
    function _catalogScope(address sourceRegistry, bytes32 key) private pure returns (bytes32) {
        return _hashEncoded(abi.encode(sourceRegistry, key));
    }

    /// @dev Keccak-hash an ABI-encoded payload without another allocation.
    function _hashEncoded(bytes memory encoded) private pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            digest := keccak256(add(encoded, 0x20), mload(encoded))
        }
    }

    /// @dev Reject uppercase ASCII in canonical Registry identifiers.
    function _requireLowercase(string memory s) private pure {
        bytes memory b = bytes(s);
        for (uint256 i = 0; i < b.length;) {
            bytes1 c = b[i];
            // All identifier bytes must be lowercase; skipping uppercase bytes would admit a noncanonical key.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (c >= 0x41 && c <= 0x5A) revert("Identifier must be lowercase");
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Require absent feeds to bind zero decimals, or deployed feeds to match their bound decimals exactly.
    function _validateTokenFeed(address feed, uint8 expectedDecimals) private view {
        if (feed == address(0)) {
            if (expectedDecimals != 0) revert TokenFeedInvalid();
            return;
        }
        if (feed.code.length <= 23 || expectedDecimals > 36) { // 23 = EIP-7702 designator length
            revert TokenFeedInvalid();
        }
        uint8 decimals = AggregatorV3Interface(feed).decimals();
        if (decimals > 36 || decimals != expectedDecimals) {
            revert TokenFeedInvalid();
        }
    }
}
