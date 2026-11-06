// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {EntityFlags} from "../../EntityFlags.sol";
import {PagedIndex} from "../../PagedIndex.sol";
import {AggregatorV3Interface, PriceModule} from "../../PriceModule.sol";
import {ERCToken} from "../../RegistryTypes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {KeccakHelpers as KH} from "../../registry/Hashing.sol";
import {
    Authority,
    ContractsStorage,
    ExecutionCatalogStorage,
    OrgsStorage,
    SyncStorage,
    TokensStorage
} from "../../registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/**
 * @title RegistryTokensFacet
 * @notice ERC token registry under org/id keys.
 * @dev Requires the corresponding contract key to exist; tracks submitter on a namespaced key.
 *      Organization owners/members are writers only after governance explicitly
 *      enables catalog delegation and while their organization is unsuspended.
 *      Token entries let runtime code map a symbolic token id to its decimals and optional Chainlink feed so valuation,
 *      quoting, and UI layers can agree on the same metadata.
 *      The facet also owns the Registry price API. PriceModule shares its namespaced
 *      oracle configuration across facet replacements.
 */
contract RegistryTokensFacet is FacetGuard, PriceModule {
    using PagedIndex for PagedIndex.Index;

    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    error EmptyId();
    error IdentifierNotLowercase();
    error NotAuthorized();
    error TokenContractMissing();
    error TokenFeedInvalid();
    error TokenMissing();
    error InvalidTokenFlags();
    error TokenDecimalsTooHigh(uint8 decimals);

    event TokenUpsert(string indexed org, string indexed id, address indexed operator);
    event TokenFlagsSet(bytes32 indexed key, uint256 flags, address indexed operator);

    /// @notice Creates or updates an ERC token record.
    /// @dev Requires the matching contract key to already exist in the registry.
    /// @param data Token struct including symbol, decimals and Chainlink price feed.
    function upsertToken(ERCToken memory data) external whenNotPausedD nonReentrantD {
        _upsertToken(data, 0, false);
    }

    /// @notice Creates or updates an ERC token record with explicit token-level flags.
    /// @dev Pass `EntityFlags.INACTIVE` to create the record inactive after the write timelock executes.
    function upsertTokenWithFlags(ERCToken memory data, uint256 flags) external whenNotPausedD nonReentrantD {
        _upsertToken(data, flags, true);
    }

    function _upsertToken(ERCToken memory data, uint256 flags, bool updateFlags) private {
        if (bytes(data.org).length == 0 || bytes(data.id).length == 0) revert EmptyId();
        if (data.decimals > 36) revert TokenDecimalsTooHigh(data.decimals);
        _requireLowercase(data.org);
        _requireLowercase(data.id);
        if (updateFlags) {
            _validateTokenFlags(flags);
        }
        bytes32 orgHash = KH.stringHash(data.org);
        address actor = _msgSenderD();
        if (!_canWriteToken(orgHash, actor)) {
            revert NotAuthorized();
        }
        bytes32 key = KH.joinSlash(data.org, data.id);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryToken(), scope: key, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            updateFlags
                ? abi.encodeWithSelector(this.upsertTokenWithFlags.selector, data, flags)
                : abi.encodeWithSelector(this.upsertToken.selector, data)
        );
        if (!executing) {
            return;
        }
        _recordToken(data, flags, updateFlags);
    }

    function _recordToken(ERCToken memory data, uint256 flags, bool updateFlags) private {
        bytes32 key = KH.joinSlash(data.org, data.id);
        address actor = _msgSenderD();
        // must have a corresponding contract entry
        if (!ContractsStorage.exists(ContractsStorage.getLayout(), key)) revert TokenContractMissing();
        _validateTokenFeed(data.price, data.priceFeedDecimals);
        TokensStorage.Layout storage tl = TokensStorage.getLayout();
        ERCToken storage t = tl.tokens[key];
        bool fresh = bytes(t.id).length == 0;
        t.org = data.org;
        t.id = data.id;
        t.symbol = data.symbol;
        t.decimals = data.decimals;
        t.price = data.price;
        t.priceFeedDecimals = data.priceFeedDecimals;
        if (updateFlags) {
            TokensStorage.setFlags(tl, key, flags);
            // Token writes hold nonReentrantD; feed validation is STATICCALL and catalog/index helpers have no
            // external callbacks.
            // forge-lint: disable-next-line(reentrancy-events)
            emit TokenFlagsSet(key, flags, actor);
        } else {
            ExecutionCatalogStorage.bump();
        }
        if (fresh) {
            tl.tokenKeys.insert(key);
        } else if (!updateFlags) {
            // setFlags already records the semantic update for flagged writes.
            TokensStorage.touchIndex(tl, key);
        }
        // becomes token key
        key = KH.tokenAuthKey(data.org, data.id);
        if (Authority._getSubmitter(key) == address(0)) {
            Authority._setSubmitterIfUnset(key, actor);
        }
        SyncStorage.clearActiveTokenImport(SyncStorage.getLayout(), KH.joinSlash(data.org, data.id));
        // Token writes hold nonReentrantD; feed validation is STATICCALL and catalog/index helpers have no external
        // callbacks.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TokenUpsert(data.org, data.id, actor);
    }

    /// @notice Activates or deactivates an existing token record through the activation timelock category.
    function setTokenActive(string calldata org, string calldata id, bool active)
        external
        whenNotPausedD
        nonReentrantD
    {
        if (bytes(org).length == 0 || bytes(id).length == 0) revert EmptyId();
        _requireLowercase(org);
        _requireLowercase(id);
        bytes32 orgHash = KH.stringHash(org);
        address actor = _msgSenderD();
        if (!_canWriteToken(orgHash, actor)) {
            revert NotAuthorized();
        }
        bytes32 key = KH.joinSlash(org, id);
        if (!TokensStorage.exists(TokensStorage.getLayout(), key)) revert TokenMissing();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryActivation(), scope: key, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setTokenActive.selector, org, id, active)
        );
        if (!executing) {
            return;
        }
        _setTokenActive(key, active);
    }

    /// @notice Returns a token by org/id.
    function getToken(string calldata org, string calldata id) external view returns (ERCToken memory) {
        return TokensStorage.getLayout().tokens[KH.joinSlash(org, id)];
    }

    /// @notice Returns a token by its precomputed contract hash.
    function getTokenByHash(bytes32 h) external view returns (ERCToken memory) {
        return TokensStorage.getLayout().tokens[h];
    }

    /// @notice Return whether a local token record exists for a precomputed contract key.
    /// @dev Activation does not affect classification: inactive token contracts
    ///      still need residual-balance protection during MiniScript execution.
    function isTokenByHash(bytes32 h) external view returns (bool) {
        return TokensStorage.exists(TokensStorage.getLayout(), h);
    }

    /// @notice Returns token-level flags by org/id.
    function getTokenFlags(string calldata org, string calldata id) external view returns (uint256) {
        return TokensStorage.getFlags(TokensStorage.getLayout(), KH.joinSlash(org, id));
    }

    /// @notice Returns token-level flags by precomputed key.
    function getTokenFlagsByHash(bytes32 key) external view returns (uint256) {
        return TokensStorage.getFlags(TokensStorage.getLayout(), key);
    }

    /// @notice Returns the Authority submitter tracked for a token key.
    function getTokenSubmitter(string calldata org, string calldata id) external view returns (address) {
        return Authority._getSubmitter(KH.tokenAuthKey(org, id));
    }

    // Index views
    /// @notice Returns number of token keys.
    function getTokenCount() external view returns (uint256) {
        return TokensStorage.getLayout().tokenKeys.length();
    }

    /// @notice Returns token key at index.
    function getTokenKeyAt(uint256 index) external view returns (bytes32) {
        return TokensStorage.getLayout().tokenKeys.valueAt(index);
    }

    /// @notice Returns page of token keys for pagination.
    function getTokenKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return TokensStorage.getLayout().tokenKeys.page(start, count);
    }

    function getTokenIndexNextId() external view returns (uint256) {
        return TokensStorage.getLayout().tokenKeys.nextId();
    }

    function getTokenIndexCurrentEpoch() external view returns (uint64) {
        return TokensStorage.getLayout().tokenKeys.currentEpoch;
    }

    function getTokenIndexAlivePage(uint256 pageIndex) external view returns (uint256) {
        return TokensStorage.getLayout().tokenKeys.alivePage(pageIndex);
    }

    function getTokenIndexValues(uint256[] calldata ids) external view returns (bytes32[] memory) {
        return TokensStorage.getLayout().tokenKeys.getValues(ids);
    }

    function getTokenIndexEpochPageCount(uint64 epoch) external view returns (uint256) {
        return TokensStorage.getLayout().tokenKeys.epochPageCount(epoch);
    }

    function getTokenIndexEpochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return TokensStorage.getLayout().tokenKeys.epochPageAt(epoch, i);
    }

    function getTokenIndexJournal(uint64 epoch, uint128 pageIndex)
        external
        view
        returns (uint256 updates, uint256 deletes)
    {
        return TokensStorage.getLayout().tokenKeys.journal(epoch, pageIndex);
    }

    // Helpers
    function _requireLowercase(string memory s) private pure {
        bytes memory b = bytes(s);
        for (uint256 i = 0; i < b.length;) {
            bytes1 c = b[i];
            // All identifier bytes must be lowercase; skipping uppercase bytes would admit a noncanonical key.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (c >= 0x41 && c <= 0x5A) revert IdentifierNotLowercase();
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

    function _setTokenActive(bytes32 key, bool active) private {
        address actor = _msgSenderD();
        TokensStorage.Layout storage tl = TokensStorage.getLayout();
        uint256 flags = EntityFlags.setActive(TokensStorage.getFlags(tl, key), active);
        TokensStorage.setFlags(tl, key, flags);
        SyncStorage.clearActiveTokenImport(SyncStorage.getLayout(), key);
        // Token writes hold nonReentrantD; feed validation is STATICCALL and catalog/index helpers have no external
        // callbacks.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TokenFlagsSet(key, flags, actor);
    }

    function _validateTokenFlags(uint256 flags) private pure {
        if (flags & ~EntityFlags.MASK != 0) revert InvalidTokenFlags();
    }

    function _canWriteToken(bytes32 orgHash, address actor) private view returns (bool) {
        if (OrgsStorage.hasCatalogAuthority(OrgsStorage.getLayout(), orgHash, actor)) return true;
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.REGISTRY_MANAGER)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.TOKEN_MANAGER)) return true;
        return false;
    }

    function _getTokenByHash(bytes32 h) internal view override returns (ERCToken memory) {
        return TokensStorage.getLayout().tokens[h];
    }

    function _isTokenActiveByHash(bytes32 h) internal view override returns (bool) {
        if (EntityFlags.isInactive(TokensStorage.getLayout().flags[h])) return false;
        return !EntityFlags.isInactive(ContractsStorage.getLayout().flags[h]);
    }

    function _requirePriceAdmin() internal view override {
        _onlyRoleD(ADMIN_ROLE);
    }
}
