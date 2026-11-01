// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {EntityFlags} from "../../EntityFlags.sol";
import {PagedIndex} from "../../PagedIndex.sol";
import {AggregatorV3Interface} from "../../PriceModule.sol";
import {ERCToken} from "../../RegistryTypes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {KeccakHelpers as KH} from "../../registry/Hashing.sol";
import {
    Authority,
    ContractsStorage,
    OrgsStorage,
    SyncStorage,
    TokenCommitsStorage,
    TokensStorage
} from "../../registry/RegistryShared.sol";
import {SecretCommitLib} from "../../registry/SecretCommitLib.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @title RegistryTokenCommitsFacet
 * @notice Commit/reveal publication for private token metadata.
 * @dev This surface is separate from RegistryTokensFacet to keep both facets
 *      comfortably below the EIP-170 deployment-size limit. Both facets use the
 *      same namespaced diamond storage and token authority rules.
 *
 *      The org/id key remains public so the token timelock can govern the exact
 *      namespace. The commitment hides symbol, decimals, price feed, flags, and
 *      salt. Reveal is immediate because the opaque commitment has already passed
 *      that timelock, but current namespace authority is checked again before the
 *      committed record can become active registry state.
 */
contract RegistryTokenCommitsFacet is FacetGuard {
    using PagedIndex for PagedIndex.Index;

    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 internal constant MAX_TOKEN_COMMIT_LIFETIME = 90 days;

    error EmptyId();
    error NotAuthorized();
    error TokenFeedInvalid();
    error InvalidTokenFlags();
    error TokenDecimalsTooHigh(uint8 decimals);
    error CommitExists();
    error CommitMissing();
    error CommitExpired();
    error CommitHashMismatch();
    error RevealSignatureRequired();
    error RevealSignatureInvalid();
    error CommitterNoLongerAuthorized();
    error CommitNotExpired();
    error CommitDeadlineInvalid();

    event TokenUpsert(string indexed org, string indexed id, address indexed operator);
    event TokenFlagsSet(bytes32 indexed key, uint256 flags, address indexed operator);
    event TokenCommitCreated(
        bytes32 indexed key,
        address indexed committer,
        bytes32 commitHash,
        uint64 deadline,
        address forwarder,
        bytes32 hint
    );
    event TokenCommitCancelled(bytes32 indexed key, address indexed operator);
    event TokenCommitExpired(bytes32 indexed key, address indexed operator);
    event TokenCommitRevealed(bytes32 indexed key, address indexed operator, bytes32 commitHash);

    /// @notice Create a private commitment for a token metadata reveal.
    /// @dev The deadline must leave enough time for any configured token timelock.
    function commitTokenPrivate(
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
        if (!_canWriteToken(orgHash, actor)) revert NotAuthorized();
        if (commitHash == bytes32(0)) revert CommitHashMismatch();
        // An authorized committer chooses a bounded reveal window measured in chain time.
        // forge-lint: disable-next-line(block-timestamp)
        if (deadline <= block.timestamp || uint256(deadline) > block.timestamp + MAX_TOKEN_COMMIT_LIFETIME) {
            revert CommitDeadlineInvalid();
        }

        bytes32 key = KH.joinSlash(org, id);
        TokenCommitsStorage.Layout storage cl = TokenCommitsStorage.getLayout();
        if (cl.commits[key].hash != bytes32(0)) revert CommitExists();

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryToken(), scope: key, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.commitTokenPrivate.selector, org, id, commitHash, deadline, forwarder, hint)
        );
        if (!executing) return;

        TokenCommitsStorage.Commit memory commit = TokenCommitsStorage.Commit({
            hash: commitHash, committer: actor, forwarder: forwarder, deadline: deadline, hint: hint
        });
        TokenCommitsStorage.upsert(cl, key, commit);
        // Token entrypoints hold nonReentrantD; feed/signature checks are STATICCALLs and remaining helpers write
        // local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TokenCommitCreated(key, actor, commitHash, deadline, forwarder, hint);
    }

    /// @notice Cancel a pending token commitment.
    /// @dev The original committer or any current writer for the namespace may
    ///      cancel, so governance can recover after removing a compromised writer.
    ///      Cancellation remains available while paused because it can only
    ///      remove unpublished state.
    function cancelTokenCommit(string calldata org, string calldata id) external nonReentrantD {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);
        bytes32 key = KH.joinSlash(org, id);
        TokenCommitsStorage.Layout storage cl = TokenCommitsStorage.getLayout();
        TokenCommitsStorage.Commit memory commit = cl.commits[key];
        if (commit.hash == bytes32(0)) revert CommitMissing();

        address actor = _msgSenderD();
        if (!(actor == commit.committer || _canWriteToken(KH.stringHash(org), actor))) revert NotAuthorized();

        TokenCommitsStorage.clear(cl, key);
        // Token entrypoints hold nonReentrantD; feed/signature checks are STATICCALLs and remaining helpers write
        // local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TokenCommitCancelled(key, actor);
    }

    /// @notice Remove a token commitment after its reveal deadline.
    /// @dev Expiry remains permissionless and available while paused because it
    ///      can only remove an unusable commitment.
    function expireTokenCommit(string calldata org, string calldata id) external nonReentrantD {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);
        bytes32 key = KH.joinSlash(org, id);
        TokenCommitsStorage.Layout storage cl = TokenCommitsStorage.getLayout();
        TokenCommitsStorage.Commit memory commit = cl.commits[key];
        if (commit.hash == bytes32(0)) revert CommitMissing();
        // Permissionless cleanup starts only after the same reveal window has closed.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp <= commit.deadline) revert CommitNotExpired();
        TokenCommitsStorage.clear(cl, key);
        // Token entrypoints hold nonReentrantD; feed/signature checks are STATICCALLs and remaining helpers write
        // local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TokenCommitExpired(key, _msgSenderD());
    }

    /// @notice Reveal and install committed token metadata and flags.
    /// @dev The token submitter remains the committer, not a relayer or current
    ///      writer that sponsors publication, matching private interaction provenance.
    function revealTokenCommit(ERCToken calldata data, uint256 flags, bytes32 salt, bytes calldata actorSignature)
        external
        whenNotPausedD
        nonReentrantD
    {
        if (bytes(data.org).length == 0 || bytes(data.id).length == 0) revert EmptyId();
        if (data.decimals > 36) revert TokenDecimalsTooHigh(data.decimals);
        _requireLowercase(data.org);
        _requireLowercase(data.id);
        _validateTokenFlags(flags);

        bytes32 key = KH.joinSlash(data.org, data.id);
        bytes32 orgHash = KH.stringHash(data.org);
        TokenCommitsStorage.Layout storage cl = TokenCommitsStorage.getLayout();
        TokenCommitsStorage.Commit memory commit = cl.commits[key];
        if (commit.hash == bytes32(0)) revert CommitMissing();
        // Chain time bounds reveal validity; commitment and current writer authorization are checked below.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > commit.deadline) revert CommitExpired();

        bytes32 expectedCommit = SecretCommitLib.computeTokenCommit(key, data, flags, salt);
        if (expectedCommit != commit.hash) revert CommitHashMismatch();

        address actor = _msgSenderD();
        bool currentActorAuthorized = _canWriteToken(orgHash, actor);
        if (!_canWriteToken(orgHash, commit.committer) && !currentActorAuthorized) {
            revert CommitterNoLongerAuthorized();
        }
        bool needsSignature =
            _tokenRevealNeedsSignature(commit, actor, currentActorAuthorized, actorSignature.length != 0);
        if (needsSignature) {
            if (actorSignature.length == 0) revert RevealSignatureRequired();
            _verifyTokenRevealSignature(commit.committer, key, expectedCommit, salt, actor, actorSignature);
        } else if (actorSignature.length != 0) {
            _verifyTokenRevealSignature(commit.committer, key, expectedCommit, salt, actor, actorSignature);
        }

        TokenCommitsStorage.clear(cl, key);
        _recordToken(data, flags, commit.committer);
        // Token entrypoints hold nonReentrantD; feed/signature checks are STATICCALLs and remaining helpers write
        // local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TokenCommitRevealed(key, actor, expectedCommit);
    }

    /// @notice Fetch a token commitment by its canonical org/id key.
    function getTokenCommitByKey(bytes32 key) external view returns (TokenCommitsStorage.Commit memory commit) {
        commit = TokenCommitsStorage.getLayout().commits[key];
    }

    /// @notice Return a page of keys with active token commitments.
    function getTokenCommitKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return TokenCommitsStorage.getLayout().commitKeys.page(start, count);
    }

    function _recordToken(ERCToken calldata data, uint256 flags, address submitter) private {
        bytes32 key = KH.joinSlash(data.org, data.id);
        if (!ContractsStorage.exists(ContractsStorage.getLayout(), key)) {
            revert("Contract not found for token");
        }
        _validateTokenFeed(data.price, data.priceFeedDecimals);

        address actor = _msgSenderD();
        TokensStorage.Layout storage tl = TokensStorage.getLayout();
        ERCToken storage token = tl.tokens[key];
        bool fresh = bytes(token.id).length == 0;
        token.org = data.org;
        token.id = data.id;
        token.symbol = data.symbol;
        token.decimals = data.decimals;
        token.price = data.price;
        token.priceFeedDecimals = data.priceFeedDecimals;
        TokensStorage.setFlags(tl, key, flags);
        // Token entrypoints hold nonReentrantD; feed/signature checks are STATICCALLs and remaining helpers write
        // local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TokenFlagsSet(key, flags, actor);

        if (fresh) tl.tokenKeys.insert(key);
        bytes32 submitterKey = KH.tokenAuthKey(data.org, data.id);
        // Token submitter is immutable provenance. Updates preserve the first
        // publisher instead of attempting to overwrite the locked authority slot.
        if (Authority._getSubmitter(submitterKey) == address(0)) {
            Authority._setSubmitterIfUnset(submitterKey, submitter);
        }
        SyncStorage.clearActiveTokenImport(SyncStorage.getLayout(), key);
        // Token entrypoints hold nonReentrantD; feed/signature checks are STATICCALLs and remaining helpers write
        // local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TokenUpsert(data.org, data.id, actor);
    }

    function _requireLowercase(string memory value) private pure {
        bytes memory chars = bytes(value);
        for (uint256 i = 0; i < chars.length;) {
            bytes1 char = chars[i];
            // All identifier bytes must be lowercase; skipping uppercase bytes would admit a noncanonical key.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (char >= 0x41 && char <= 0x5A) revert("Identifier must be lowercase");
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
        if (feed.code.length == 0 || expectedDecimals > 36) revert TokenFeedInvalid();
        uint8 actual = AggregatorV3Interface(feed).decimals();
        if (actual > 36 || actual != expectedDecimals) revert TokenFeedInvalid();
    }

    function _validateTokenFlags(uint256 flags) private pure {
        if (flags & ~EntityFlags.MASK != 0) revert InvalidTokenFlags();
    }

    function _tokenRevealNeedsSignature(
        TokenCommitsStorage.Commit memory commit,
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

    function _verifyTokenRevealSignature(
        address committer,
        bytes32 key,
        bytes32 commitHash,
        bytes32 salt,
        address forwarder,
        bytes calldata actorSignature
    ) private view {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("RevealToken(bytes32 key,bytes32 commitHash,bytes32 salt,uint256 chainId,address forwarder)"),
                key,
                commitHash,
                salt,
                block.chainid,
                forwarder
            )
        );
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        if (!SignatureChecker.isValidSignatureNow(committer, ethHash, actorSignature)) {
            revert RevealSignatureInvalid();
        }
    }

    function _canWriteToken(bytes32 orgHash, address actor) private view returns (bool) {
        if (OrgsStorage.hasCatalogAuthority(OrgsStorage.getLayout(), orgHash, actor)) return true;
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.REGISTRY_MANAGER)) return true;
        return CapabilitiesLib.hasCapability(actor, CapabilityIds.TOKEN_MANAGER);
    }
}
