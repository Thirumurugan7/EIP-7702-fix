// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {EntityFlags} from "../../EntityFlags.sol";
import {PagedIndex} from "../../PagedIndex.sol";
import {ContractAddress, ContractRecord, DappContract} from "../../RegistryTypes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {KeccakHelpers as KH} from "../../registry/Hashing.sol";
import {
    Authority,
    ContractCommitsStorage,
    ContractsStorage,
    OrgsStorage,
    SyncStorage
} from "../../registry/RegistryShared.sol";
import {SecretCommitLib} from "../../registry/SecretCommitLib.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title IAddrResolver
/// @notice Minimal dispatcher-facing address resolver used for local reads.
interface IAddrResolver {
    function getAddressByHash(bytes32) external view returns (address);
}

/**
 * @title RegistryContractsFacet
 * @notice Contract address/versions CRUD for the modular Registry.
 * @dev Enforces Registry authority plus organization owner/member authority only
 *      when catalog delegation is explicitly enabled for an existing,
 *      unsuspended organization. Records are versioned with optional labels.
 *      This is the canonical on-chain directory for contract ids such as `exchange/router` or `treasury/main`.
 *      Private announcements follow the same commit/reveal pattern used for private interactions.
 */
contract RegistryContractsFacet is FacetGuard {
    using PagedIndex for PagedIndex.Index;

    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 internal constant MAX_CONTRACT_COMMIT_LIFETIME = 90 days;

    error NotAuthorized();
    error EmptyId();
    error CommitExists();
    error CommitMissing();
    error CommitExpired();
    error CommitHashMismatch();
    error RevealSignatureRequired();
    error RevealSignatureInvalid();
    error CommitterNoLongerAuthorized();
    error CommitNotExpired();
    error CommitDeadlineInvalid();
    error ContractMissing();
    error ContractAddressZero();
    error InvalidContractFlags();

    event ContractUpsert(string indexed orgId, string indexed id, address indexed operator);
    event ContractFlagsSet(bytes32 indexed key, uint256 flags, address indexed operator);
    event ContractCommitCreated(
        bytes32 indexed key,
        address indexed committer,
        bytes32 commitHash,
        uint64 deadline,
        address forwarder,
        bytes32 hint
    );
    event ContractCommitCancelled(bytes32 indexed key, address indexed operator);
    event ContractCommitExpired(bytes32 indexed key, address indexed operator);
    event ContractCommitRevealed(bytes32 indexed key, address indexed operator, bytes32 commitHash);

    /// @notice Adds a new version for a contract under an org/id.
    /// @param org Organization identifier (lowercase enforced).
    /// @param id Contract identifier (lowercase enforced).
    /// @param addrData Struct containing address, version tag, and optional implementation.
    /// @param label Optional label for this version.
    /// @dev The target address must be nonzero. Runtime code and optional
    ///      implementation provenance remain deployment/application checks.
    function addContractVersion(
        string calldata org,
        string calldata id,
        ContractAddress calldata addrData,
        bytes32 label
    ) external whenNotPausedD nonReentrantD {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);

        bytes32 orgHash = KH.stringHash(org);
        address actor = _msgSenderD();
        if (!_canWriteContracts(orgHash, actor)) {
            revert NotAuthorized();
        }

        bytes32 key = KH.joinSlash(org, id);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryContract(), scope: key, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.addContractVersion.selector, org, id, addrData, label)
        );
        if (!executing) {
            return;
        }
        _recordContractVersion(key, org, id, addrData, label);
    }

    /// @notice Adds a new contract version and explicitly sets contract-level flags.
    /// @dev Pass `EntityFlags.INACTIVE` to create the record inactive after the write timelock executes.
    function addContractVersionWithFlags(
        string calldata org,
        string calldata id,
        ContractAddress calldata addrData,
        bytes32 label,
        uint256 flags
    ) external whenNotPausedD nonReentrantD {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);
        _validateContractFlags(flags);

        bytes32 orgHash = KH.stringHash(org);
        address actor = _msgSenderD();
        if (!_canWriteContracts(orgHash, actor)) {
            revert NotAuthorized();
        }

        bytes32 key = KH.joinSlash(org, id);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryContract(), scope: key, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.addContractVersionWithFlags.selector, org, id, addrData, label, flags)
        );
        if (!executing) {
            return;
        }
        _recordContractVersionWithFlags(key, org, id, addrData, label, flags);
    }

    /// @notice Gets contract submitter and latest version.
    function getContractMetadata(string calldata org, string calldata id)
        external
        view
        returns (address submitter, uint32 latestVersion)
    {
        ContractsStorage.Layout storage cl = ContractsStorage.getLayout();
        bytes32 key = KH.joinSlash(org, id);
        DappContract storage c = ContractsStorage.get(cl, key);
        return (Authority._getSubmitter(key), c.latest);
    }

    /// @notice Returns contract metadata and latest deployment by hash.
    function getContractByHash(bytes32 h) external view returns (ContractRecord memory record) {
        ContractsStorage.Layout storage cl = ContractsStorage.getLayout();
        DappContract storage c = ContractsStorage.get(cl, h);
        record.org = c.org;
        record.id = c.id;
        record.submitter = Authority._getSubmitter(h);
        record.latestVersion = c.latest;
        if (c.latest != 0) {
            ContractAddress storage latest = c.versions[c.latest];
            record.latest =
                ContractAddress({addr: latest.addr, version: latest.version, implementation: latest.implementation});
        }
    }

    /// @notice Returns contract-level flags by org/id.
    function getContractFlags(string calldata org, string calldata id) external view returns (uint256) {
        return ContractsStorage.getFlags(ContractsStorage.getLayout(), KH.joinSlash(org, id));
    }

    /// @notice Returns contract-level flags by precomputed key.
    function getContractFlagsByHash(bytes32 key) external view returns (uint256) {
        return ContractsStorage.getFlags(ContractsStorage.getLayout(), key);
    }

    /// @notice Activates or deactivates an existing contract record through the activation timelock category.
    function setContractActive(string calldata org, string calldata id, bool active)
        external
        whenNotPausedD
        nonReentrantD
    {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);

        bytes32 orgHash = KH.stringHash(org);
        address actor = _msgSenderD();
        if (!_canWriteContracts(orgHash, actor)) {
            revert NotAuthorized();
        }

        bytes32 key = KH.joinSlash(org, id);
        if (!ContractsStorage.exists(ContractsStorage.getLayout(), key)) revert ContractMissing();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryActivation(), scope: key, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setContractActive.selector, org, id, active)
        );
        if (!executing) {
            return;
        }
        _setContractActive(key, active);
    }

    /// @notice Checks if a contract exists (has at least one version recorded).
    function contractExists(string calldata org, string calldata id) external view returns (bool) {
        return ContractsStorage.exists(ContractsStorage.getLayout(), KH.joinSlash(org, id));
    }

    /// @notice Returns a specific version of a contract.
    function getContractVersion(string calldata org, string calldata id, uint32 version)
        external
        view
        returns (ContractAddress memory)
    {
        return ContractsStorage.version(ContractsStorage.getLayout(), KH.joinSlash(org, id), version);
    }

    /// @notice Returns the latest address for a contract via the dispatcher hot path.
    function getAddress(string calldata org, string calldata id) external view returns (address) {
        return IAddrResolver(address(this)).getAddressByHash(KH.joinSlash(org, id));
    }

    /// @notice Returns the address at a specific version.
    function getAddressAt(string calldata org, string calldata id, uint32 version) external view returns (address) {
        return ContractsStorage.version(ContractsStorage.getLayout(), KH.joinSlash(org, id), version).addr;
    }

    /// @notice Returns the address of the version referenced by `label`.
    function getAddressByLabel(string calldata org, string calldata id, bytes32 label) external view returns (address) {
        ContractsStorage.Layout storage cl = ContractsStorage.getLayout();
        {
            bytes32 key = KH.joinSlash(org, id);
            return ContractsStorage.version(cl, key, ContractsStorage.labelToVersion(cl, key, label)).addr;
        }
    }

    /// @notice Returns the full versioned payload referenced by `label`.
    function getContractByLabel(string calldata org, string calldata id, bytes32 label)
        external
        view
        returns (ContractAddress memory data, uint32 version)
    {
        ContractsStorage.Layout storage cl = ContractsStorage.getLayout();
        bytes32 key = KH.joinSlash(org, id);
        version = ContractsStorage.labelToVersion(cl, key, label);
        data = ContractsStorage.version(cl, key, version);
    }

    // Index views
    /// @notice Returns number of distinct contract keys.
    function getContractCount() external view returns (uint256) {
        return ContractsStorage.getLayout().contractKeys.length();
    }

    /// @notice Returns contract key at index.
    function getContractKeyAt(uint256 index) external view returns (bytes32) {
        return ContractsStorage.getLayout().contractKeys.valueAt(index);
    }

    /// @notice Returns a page of contract keys for pagination.
    function getContractKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return ContractsStorage.getLayout().contractKeys.page(start, count);
    }

    function getContractIndexNextId() external view returns (uint256) {
        return ContractsStorage.getLayout().contractKeys.nextId();
    }

    function getContractIndexCurrentEpoch() external view returns (uint64) {
        return ContractsStorage.getLayout().contractKeys.currentEpoch;
    }

    function getContractIndexAlivePage(uint256 pageIndex) external view returns (uint256) {
        return ContractsStorage.getLayout().contractKeys.alivePage(pageIndex);
    }

    function getContractIndexValues(uint256[] calldata ids) external view returns (bytes32[] memory) {
        return ContractsStorage.getLayout().contractKeys.getValues(ids);
    }

    function getContractIndexEpochPageCount(uint64 epoch) external view returns (uint256) {
        return ContractsStorage.getLayout().contractKeys.epochPageCount(epoch);
    }

    function getContractIndexEpochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return ContractsStorage.getLayout().contractKeys.epochPageAt(epoch, i);
    }

    function getContractIndexJournal(uint64 epoch, uint128 pageIndex)
        external
        view
        returns (uint256 updates, uint256 deletes)
    {
        return ContractsStorage.getLayout().contractKeys.journal(epoch, pageIndex);
    }

    /// @notice Create a private commit for a contract version reveal.
    /// @dev The absolute deadline must be in the future and no more than 90 days
    ///      away when the commit is stored. This guarantees eventual cleanup;
    ///      callers using a timelocked category must include that delay.
    function commitContractPrivate(
        string calldata org,
        string calldata id,
        bytes32 commitHash,
        uint64 deadline,
        address forwarder,
        bytes32 hint
    ) external whenNotPausedD nonReentrantD {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);

        bytes32 orgHash = KH.stringHash(org);
        address actor = _msgSenderD();
        if (!_canWriteContracts(orgHash, actor)) {
            revert NotAuthorized();
        }

        if (commitHash == bytes32(0)) revert CommitHashMismatch();
        // forge-lint: disable-next-line(block-timestamp)
        if (deadline <= block.timestamp || uint256(deadline) > block.timestamp + MAX_CONTRACT_COMMIT_LIFETIME) {
            revert CommitDeadlineInvalid();
        }

        bytes32 key = KH.joinSlash(org, id);
        ContractCommitsStorage.Layout storage cl = ContractCommitsStorage.getLayout();
        if (cl.commits[key].hash != bytes32(0)) revert CommitExists();

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryContract(), scope: key, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.commitContractPrivate.selector, org, id, commitHash, deadline, forwarder, hint)
        );
        if (!executing) {
            return;
        }

        ContractCommitsStorage.Commit memory commit = ContractCommitsStorage.Commit({
            hash: commitHash, committer: actor, forwarder: forwarder, deadline: deadline, hint: hint
        });
        ContractCommitsStorage.upsert(cl, key, commit);
        // Catalog writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ContractCommitCreated(key, actor, commitHash, deadline, forwarder, hint);
    }

    /// @notice Cancel a pending contract commit.
    /// @dev Callable by the committer or anyone currently authorized to write the
    ///      organization namespace. This lets an org recover after member removal.
    ///      Cancellation remains available while paused because it can only
    ///      remove unpublished state.
    function cancelContractCommit(string calldata org, string calldata id) external nonReentrantD {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);
        bytes32 key = KH.joinSlash(org, id);
        ContractCommitsStorage.Layout storage cl = ContractCommitsStorage.getLayout();
        ContractCommitsStorage.Commit memory commit = cl.commits[key];
        if (commit.hash == bytes32(0)) revert CommitMissing();

        address actor = _msgSenderD();
        if (!(actor == commit.committer || _canWriteContracts(KH.stringHash(org), actor))) {
            revert NotAuthorized();
        }

        ContractCommitsStorage.clear(cl, key);
        // Catalog writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ContractCommitCancelled(key, actor);
    }

    /// @notice Remove a commit after its explicit reveal deadline has elapsed.
    /// @dev Permissionless cleanup remains available while paused because it
    ///      cannot reveal or alter the committed payload.
    function expireContractCommit(string calldata org, string calldata id) external nonReentrantD {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);
        bytes32 key = KH.joinSlash(org, id);
        ContractCommitsStorage.Layout storage cl = ContractCommitsStorage.getLayout();
        ContractCommitsStorage.Commit memory commit = cl.commits[key];
        if (commit.hash == bytes32(0)) revert CommitMissing();
        // forge-lint: disable-next-line(block-timestamp)
        if (commit.deadline == 0 || block.timestamp <= commit.deadline) revert CommitNotExpired();
        ContractCommitsStorage.clear(cl, key);
        // Catalog writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ContractCommitExpired(key, _msgSenderD());
    }

    /// @notice Reveal and record a committed contract version.
    /// @dev If a forwarder is set or a non-committer calls, a committer signature
    ///      may be required. Reverts if the commit expired or the hash mismatches.
    function revealContractCommit(
        string calldata org,
        string calldata id,
        ContractAddress calldata addrData,
        bytes32 label,
        bytes32 salt,
        bytes calldata actorSignature
    ) external whenNotPausedD nonReentrantD {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);

        bytes32 key = KH.joinSlash(org, id);
        bytes32 orgHash = KH.stringHash(org);
        ContractCommitsStorage.Layout storage cl = ContractCommitsStorage.getLayout();
        ContractCommitsStorage.Commit memory commit = cl.commits[key];
        if (commit.hash == bytes32(0)) revert CommitMissing();
        // forge-lint: disable-next-line(block-timestamp)
        if (commit.deadline != 0 && block.timestamp > commit.deadline) revert CommitExpired();

        bytes32 expectedCommit = SecretCommitLib.computeContractCommit(key, addrData, label, salt);
        if (expectedCommit != commit.hash) revert CommitHashMismatch();

        address actor = _msgSenderD();
        bool currentActorAuthorized = _canWriteContracts(orgHash, actor);
        if (!_canWriteContracts(orgHash, commit.committer) && !currentActorAuthorized) {
            revert CommitterNoLongerAuthorized();
        }
        bool needsSignature =
            _contractRevealNeedsSignature(commit, actor, currentActorAuthorized, actorSignature.length != 0);

        if (needsSignature) {
            if (actorSignature.length == 0) revert RevealSignatureRequired();
            _verifyContractRevealSignature(commit.committer, key, expectedCommit, salt, actor, actorSignature);
        } else if (actorSignature.length != 0) {
            _verifyContractRevealSignature(commit.committer, key, expectedCommit, salt, actor, actorSignature);
        }

        ContractCommitsStorage.clear(cl, key);
        _recordContractVersion(key, org, id, addrData, label);
        // Catalog writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ContractCommitRevealed(key, actor, expectedCommit);
    }

    /// @notice Fetch a contract commit by its precomputed key.
    function getContractCommitByKey(bytes32 key) external view returns (ContractCommitsStorage.Commit memory commit) {
        commit = ContractCommitsStorage.getLayout().commits[key];
    }

    /// @notice Return a page of committed contract keys.
    function getContractCommitKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return ContractCommitsStorage.getLayout().commitKeys.page(start, count);
    }

    // Helpers
    function _contractRevealNeedsSignature(
        ContractCommitsStorage.Commit memory commit,
        address actor,
        bool currentActorAuthorized,
        bool hasSignature
    ) private pure returns (bool) {
        if (actor == commit.committer) return false;
        if (commit.forwarder != address(0) && actor == commit.forwarder) return true;
        if (currentActorAuthorized) return false;
        if (!hasSignature) revert NotAuthorized();
        return true;
    }

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

    function _recordContractVersion(
        bytes32 key,
        string calldata org,
        string calldata id,
        ContractAddress calldata addrData,
        bytes32 label
    ) private {
        _recordContractVersionCore(key, org, id, addrData, label, 0, false);
    }

    function _recordContractVersionWithFlags(
        bytes32 key,
        string calldata org,
        string calldata id,
        ContractAddress calldata addrData,
        bytes32 label,
        uint256 flags
    ) private {
        _recordContractVersionCore(key, org, id, addrData, label, flags, true);
    }

    function _recordContractVersionCore(
        bytes32 key,
        string calldata org,
        string calldata id,
        ContractAddress calldata addrData,
        bytes32 label,
        uint256 flags,
        bool updateFlags
    ) private {
        if (addrData.addr == address(0)) revert ContractAddressZero();
        address actor = _msgSenderD();
        ContractsStorage.Layout storage cl = ContractsStorage.getLayout();
        uint32 next = ContractsStorage.addVersion(cl, key, addrData, label);
        DappContract storage c = ContractsStorage.get(cl, key);
        if (next == 1) {
            c.org = org;
            c.id = id;
            Authority._setSubmitterIfUnset(key, actor);
            cl.contractKeys.insert(key);
        }
        if (updateFlags) {
            _validateContractFlags(flags);
            ContractsStorage.setFlags(cl, key, flags);
            // Catalog writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
            // nonReentrantD.
            // forge-lint: disable-next-line(reentrancy-events)
            emit ContractFlagsSet(key, flags, actor);
        }
        SyncStorage.clearActiveContractImport(SyncStorage.getLayout(), key);
        // Catalog writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ContractUpsert(org, id, actor);
    }

    function _setContractActive(bytes32 key, bool active) private {
        address actor = _msgSenderD();
        ContractsStorage.Layout storage cl = ContractsStorage.getLayout();
        uint256 flags = EntityFlags.setActive(ContractsStorage.getFlags(cl, key), active);
        ContractsStorage.setFlags(cl, key, flags);
        SyncStorage.clearActiveContractImport(SyncStorage.getLayout(), key);
        // Catalog writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ContractFlagsSet(key, flags, actor);
    }

    function _validateContractFlags(uint256 flags) private pure {
        if (flags & ~EntityFlags.MASK != 0) revert InvalidContractFlags();
    }

    function _verifyContractRevealSignature(
        address committer,
        bytes32 key,
        bytes32 commitHash,
        bytes32 salt,
        address forwarder,
        bytes calldata actorSignature
    ) private view {
        bytes32 structHash;
        {
            bytes memory encoded = abi.encode(
                keccak256(
                    "RevealContract(bytes32 key,bytes32 commitHash,bytes32 salt,uint256 chainId,address forwarder)"
                ),
                key,
                commitHash,
                salt,
                block.chainid,
                forwarder
            );
            assembly ("memory-safe") {
                structHash := keccak256(add(encoded, 0x20), mload(encoded))
            }
        }

        bytes32 ethHash;
        {
            bytes memory prefix = abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash);
            assembly ("memory-safe") {
                ethHash := keccak256(add(prefix, 0x20), mload(prefix))
            }
        }
        if (!SignatureChecker.isValidSignatureNow(committer, ethHash, actorSignature)) {
            revert RevealSignatureInvalid();
        }
    }

    function _canWriteContracts(bytes32 orgHash, address actor) private view returns (bool) {
        if (OrgsStorage.hasCatalogAuthority(OrgsStorage.getLayout(), orgHash, actor)) return true;
        if (_hasRegistryManagerCapability(actor)) return true;
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.CONTRACT_WRITE)) return true;
        return false;
    }

    function _hasRegistryManagerCapability(address actor) private view returns (bool) {
        return CapabilitiesLib.hasCapability(actor, CapabilityIds.REGISTRY_MANAGER);
    }
}
