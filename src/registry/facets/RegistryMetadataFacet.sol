// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {PagedIndex} from "../../PagedIndex.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {KeccakHelpers as KH} from "../../registry/Hashing.sol";
import {MetaStorage} from "../../registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/**
 * @title RegistryMetadataFacet
 * @notice Raw and typed metadata accessors for entities (org/user/group/contract/token).
 * @dev Keys are stored under EIP-7201 namespaced storage (entityHash x keyHash).
 *      This facet is intentionally descriptive rather than authoritative: metadata can power UIs, discovery, docs,
 *      and icons, but it does not grant execution permissions on its own.
 */
contract RegistryMetadataFacet is FacetGuard {
    using PagedIndex for PagedIndex.Index;

    uint256 public constant VERSION = 2;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 internal constant MAX_META_BYTES = 1024;

    error MetadataTooLarge();
    error InvalidMetadataPageSize();

    /// @notice Emitted when one metadata field is written through the string-keyed API.
    event MetaSet(string kind, string id, string key, address indexed operator);
    /// @notice Emitted when one metadata field is removed.
    event MetaDeleted(string kind, string id, string key, address indexed operator);

    /// @notice Sets a raw metadata value.
    /// @dev Keys are stored under keccak256(abi.encodePacked(kind, "/", id)) and key hash.
    /// @param kind Entity kind label (e.g., "org", "user", "contract").
    /// @param id Entity identifier.
    /// @param key Metadata key string; hashed internally.
    /// @param value ABI-encoded bytes value.
    function setMeta(string calldata kind, string calldata id, string calldata key, bytes calldata value)
        external
        whenNotPausedD
        nonReentrantD
    {
        _requireMetadataWriteRole();
        if (value.length > MAX_META_BYTES) revert MetadataTooLarge();
        (bytes32 entityHash, bytes32 keyHash) = _hash(kind, id, key);
        bytes32 scope = _scopeFromHashes(entityHash, keyHash);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryMetadata(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setMeta.selector, kind, id, key, value)
        );
        if (!executing) {
            return;
        }
        MetaStorage.set(entityHash, keyHash, value);
        _indexField(kind, id, keyHash, value.length != 0);
        // Metadata entrypoints hold nonReentrantD and only use internal storage/index helpers before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit MetaSet(kind, id, key, _msgSenderD());
    }

    /// @notice Reads a raw metadata value.
    /// @param kind Entity kind.
    /// @param id Entity id.
    /// @param key Metadata key string; hashed internally.
    /// @return Raw value bytes (empty when unset).
    function getMeta(string calldata kind, string calldata id, string calldata key)
        external
        view
        returns (bytes memory)
    {
        (bytes32 ek, bytes32 kk) = _hash(kind, id, key);
        return MetaStorage.get(ek, kk);
    }

    /// @notice Enumerate identifiers with a nonempty metadata field using stable PagedIndex cursors.
    /// @dev Reads at most `count` slots, including deleted slots. A page can be
    ///      empty while `hasMore` is true. Pin all pages to the same block.
    ///      Values predating this facet version are indexed on their next write.
    function getMetaIndexPage(string calldata kind, string calldata key, uint256 start, uint256 count)
        external
        view
        returns (string[] memory ids, uint256 nextCursor, bool hasMore)
    {
        if (count == 0 || count > 256) revert InvalidMetadataPageSize();
        MetaStorage.Layout storage l = MetaStorage.getLayout();
        PagedIndex.Index storage index = l.fieldIndexes[_fieldScope(kind, keccak256(bytes(key)))];
        uint256 limit = index.nextId();
        if (start >= limit) return (new string[](0), limit, false);
        uint256 remaining = limit - start;
        nextCursor = start + (count < remaining ? count : remaining);
        ids = new string[](nextCursor - start);
        uint256 written = 0;
        for (uint256 i = start; i < nextCursor; ++i) {
            (bytes32 value, bool alive) = index.get(i);
            if (alive) ids[written++] = l.identifiers[value];
        }
        assembly ("memory-safe") {
            mstore(ids, written)
        }
        hasMore = nextCursor < limit;
    }

    /// @notice Deletes a raw metadata value.
    function deleteMeta(string calldata kind, string calldata id, string calldata key)
        external
        whenNotPausedD
        nonReentrantD
    {
        _requireMetadataWriteRole();
        (bytes32 entityHash, bytes32 keyHash) = _hash(kind, id, key);
        bytes32 scope = _scopeFromHashes(entityHash, keyHash);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryMetadata(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.deleteMeta.selector, kind, id, key)
        );
        if (!executing) {
            return;
        }
        MetaStorage.del(entityHash, keyHash);
        _indexField(kind, id, keyHash, false);
        // Metadata entrypoints hold nonReentrantD and only use internal storage/index helpers before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit MetaDeleted(kind, id, key, _msgSenderD());
    }

    // Typed helpers
    /// @notice Typed setter for the standard `image` metadata field.
    /// @dev Mirrors `setMeta(kind, id, "image", abi.encode(value))` with stricter typing.
    function setImage(string calldata kind, string calldata id, string calldata value)
        external
        whenNotPausedD
        nonReentrantD
    {
        _requireMetadataWriteRole();
        if (bytes(value).length > MAX_META_BYTES) revert MetadataTooLarge();
        bytes32 entityHash = _entityHash(kind, id);
        bytes32 scope = _scopeFromHashes(entityHash, MetaStorage.KEY_IMAGE);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryMetadata(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setImage.selector, kind, id, value)
        );
        if (!executing) {
            return;
        }
        MetaStorage.setString(entityHash, MetaStorage.KEY_IMAGE, value);
        // Even an empty string has a nonempty ABI encoding, just like setMeta.
        _indexField(kind, id, MetaStorage.KEY_IMAGE, true);
        // Metadata entrypoints hold nonReentrantD and only use internal storage/index helpers before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit MetaSet(kind, id, "image", _msgSenderD());
    }

    function getImage(string calldata kind, string calldata id)
        external
        view
        returns (bool found, string memory value)
    {
        return MetaStorage.getStringFound(_entityHash(kind, id), MetaStorage.KEY_IMAGE);
    }

    function getChannels(string calldata kind, string calldata id)
        external
        view
        returns (bool found, string memory value)
    {
        return MetaStorage.getStringFound(_entityHash(kind, id), MetaStorage.KEY_CHANNELS);
    }

    function getForeignIds(string calldata kind, string calldata id)
        external
        view
        returns (bool found, string memory value)
    {
        return MetaStorage.getStringFound(_entityHash(kind, id), MetaStorage.KEY_FOREIGN_IDS);
    }

    function getDoc(string calldata kind, string calldata id) external view returns (bool found, string memory value) {
        return MetaStorage.getStringFound(_entityHash(kind, id), MetaStorage.KEY_DOC);
    }

    function _requireMetadataWriteRole() private view {
        address actor = _msgSenderD();
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) {
            return;
        }
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.METADATA_MANAGER)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, ADMIN_ROLE);
    }

    function _fieldScope(string calldata kind, bytes32 keyHash) private pure returns (bytes32) {
        return keccak256(abi.encode(kind, keyHash));
    }

    function _indexField(string calldata kind, string calldata id, bytes32 keyHash, bool present) private {
        MetaStorage.Layout storage l = MetaStorage.getLayout();
        PagedIndex.Index storage index = l.fieldIndexes[_fieldScope(kind, keyHash)];
        bytes32 value = keccak256(bytes(id));
        if (present) {
            if (!index.contains(value)) {
                l.identifiers[value] = id;
                index.insert(value);
            }
        } else if (index.contains(value)) {
            index.removeValue(value);
        }
    }

    function _scopeFromHashes(bytes32 entityHash, bytes32 keyHash) private pure returns (bytes32 scopeHash) {
        assembly ("memory-safe") {
            mstore(0x00, entityHash)
            mstore(0x20, keyHash)
            scopeHash := keccak256(0x00, 0x40)
        }
    }

    function _hash(string calldata kind, string calldata id, string calldata key)
        private
        pure
        returns (bytes32 entityHash, bytes32 keyHash)
    {
        string memory kindMem = kind;
        string memory idMem = id;
        string memory keyMem = key;
        entityHash = KH.joinSlash(kindMem, idMem);
        keyHash = KH.stringHash(keyMem);
    }

    function _entityHash(string calldata kind, string calldata id) private pure returns (bytes32 h) {
        string memory kindMem = kind;
        string memory idMem = id;
        h = KH.joinSlash(kindMem, idMem);
    }
}
