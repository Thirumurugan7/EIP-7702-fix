// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ProductRatioMath} from "./ProductRatioMath.sol";
import {ERCToken, ValueTokenV1b} from "./RegistryTypes.sol";
import {ExecutionCatalogStorage} from "./registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "./registry/TimelockLib.sol";

/// @title AggregatorV3Interface
/// @notice Minimal Chainlink-compatible feed interface used by `PriceModule`.
interface AggregatorV3Interface {
    /// @notice Return the latest round data from the feed.
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

    /// @notice Return the decimals used by the feed answer.
    function decimals() external view returns (uint8);
}

/// @dev Namespaced oracle configuration shared by the Registry's pricing surfaces.
library OracleSafetyStorage {
    bytes32 internal constant SLOT = keccak256("okc.storage.price.oracle.safety");

    struct Layout {
        mapping(address feed => uint64 maxAge) feedMaxAge;
        address sequencerUptimeFeed;
        uint64 sequencerGracePeriod;
        bool configured;
        bool sequencerRequired;
        // Optional Chainlink proxy address for the native token (e.g., ETH/USD, AVAX/USD).
        address nativeUsdFeed;
        uint8 nativeUsdFeedDecimals;
        uint256 maxFeedStaleness;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly ("memory-safe") {
            l.slot := slot
        }
    }
}

/// @title IRegistryPrice
/// @notice Pricing surface routed through `RegistryTokensFacet` by RegistryDiamond.
interface IRegistryPrice {
    /// @notice Configure the optional global feed-age ceiling in seconds.
    /// @param seconds_ Global maximum feed age, or zero to disable the global bound.
    function setMaxFeedStaleness(uint256 seconds_) external;
    /// @notice Set the mandatory reviewed heartbeat for one price feed.
    /// @param feed Chainlink-compatible price feed.
    /// @param maxAge Maximum accepted feed age, or zero to disable price reads from this feed.
    function setFeedMaxAge(address feed, uint64 maxAge) external;
    /// @notice Return the mandatory reviewed heartbeat for one price feed.
    /// @param feed Chainlink-compatible price feed.
    /// @return Maximum accepted feed age, or zero when the feed is disabled.
    function getFeedMaxAge(address feed) external view returns (uint64);
    /// @notice Select L1 or sequencer-protected L2 oracle semantics.
    /// @param sequencerRequired Whether every price read must first validate sequencer uptime.
    /// @param sequencerUptimeFeed Chainlink-compatible sequencer uptime feed in L2 mode.
    /// @param recoveryGracePeriod Required post-recovery delay in L2 mode.
    function setOracleEnvironment(bool sequencerRequired, address sequencerUptimeFeed, uint64 recoveryGracePeriod)
        external;
    /// @notice Return the configured oracle environment.
    function getOracleEnvironment()
        external
        view
        returns (bool configured, bool sequencerRequired, address sequencerUptimeFeed, uint64 recoveryGracePeriod);
    /// @notice Value an encoded multi-asset interaction in USD18.
    /// @param spec ABI-encoded token valuation list and native-inclusion flag.
    /// @param nativeAmountWei Native amount included when requested by `spec`.
    /// @param maxAge Optional per-call freshness bound.
    /// @return usdValue1e18 Sum of individually ceiling-rounded USD18 token and native components.
    /// @return oldestUpdateAt Oldest feed timestamp used by the valuation.
    function computeInteractionUsdValue(bytes calldata spec, uint256 nativeAmountWei, uint256 maxAge)
        external
        view
        returns (uint256 usdValue1e18, uint256 oldestUpdateAt);
    /// @notice Return a token USD price scaled to caller-selected decimals.
    /// @param h Precomputed token key.
    /// @param outDecimals Desired result decimals.
    /// @return price Scaled positive price.
    /// @return updatedAt Accepted feed update timestamp.
    function getTokenUsdPriceScaled(bytes32 h, uint8 outDecimals)
        external
        view
        returns (uint256 price, uint256 updatedAt);
    /// @notice Return a token USD price with caller-selected scaling and freshness.
    /// @param h Precomputed token key.
    /// @param outDecimals Desired result decimals.
    /// @param maxAge Optional caller-selected freshness bound.
    /// @return price Scaled positive price.
    function getTokenUsdPriceScaledFresh(bytes32 h, uint8 outDecimals, uint256 maxAge)
        external
        view
        returns (uint256 price);
    /// @notice Return the raw answer, bound decimals, and update time for a token feed.
    /// @param h Precomputed token key.
    /// @return answer Strictly positive raw feed answer.
    /// @return decimals Registry-bound feed decimal count.
    /// @return updatedAt Accepted feed update timestamp.
    function getTokenUsdPriceRaw(bytes32 h) external view returns (int256 answer, uint8 decimals, uint256 updatedAt);
    /// @notice Return the conservative exact-ceiling USD18 value of a token amount.
    /// @param tokenHash Precomputed active token key.
    /// @param amount Amount in the token's native decimals.
    /// @param maxAge Required nonzero freshness bound in seconds.
    /// @return Exact-ceiling USD value scaled to 18 decimals.
    function getTokenUsdValue18Ceil(bytes32 tokenHash, uint256 amount, uint256 maxAge) external view returns (uint256);
    /// @notice Return the conservative exact-ceiling USD18 value of native wei.
    /// @param amountWei Native value in wei.
    /// @param maxAge Required nonzero freshness bound in seconds.
    /// @return Exact-ceiling USD value scaled to 18 decimals.
    function getNativeUsdValue18Ceil(uint256 amountWei, uint256 maxAge) external view returns (uint256);
    /// @notice Configure the native USD feed and bind its decimal count.
    /// @param feed Chainlink-compatible native/USD feed, or zero to clear it.
    /// @param priceFeedDecimals Expected live `decimals()` value.
    function setNativeUsdFeed(address feed, uint8 priceFeedDecimals) external;
    /// @notice Return the native USD feed and its bound decimal count.
    /// @return feed Configured feed, or zero when unset.
    /// @return priceFeedDecimals Decimal count governance bound to `feed`.
    function getNativeUsdFeedConfig() external view returns (address feed, uint8 priceFeedDecimals);
    /// @notice Return the optional global feed-age ceiling in seconds.
    /// @return Maximum age in seconds, or zero when globally disabled.
    function getMaxFeedStaleness() external view returns (uint256);
    /// @notice Return the raw answer, bound decimals, and update time for the native feed.
    /// @return answer Strictly positive raw feed answer.
    /// @return decimals Governance-bound feed decimal count.
    /// @return updatedAt Accepted feed update timestamp.
    function getNativeUsdPriceRaw() external view returns (int256 answer, uint8 decimals, uint256 updatedAt);
    /// @notice Return the native USD price scaled to caller-selected decimals.
    /// @param outDecimals Desired result decimals.
    /// @return price Scaled positive price.
    /// @return updatedAt Accepted feed update timestamp.
    function getNativeUsdPriceScaled(uint8 outDecimals) external view returns (uint256 price, uint256 updatedAt);
}

/// @title PriceModule
/// @notice Shared token and native-asset USD valuation helpers used by the registry.
/// @dev This module lets policy programs and off-chain tooling ask the registry
///      "what is this interaction worth in USD right now?" without embedding feed
///      logic in every facet. RegistryTokensFacet inherits this module and executes
///      it by delegatecall, using namespaced oracle storage.
///
///      Example:
///      - a policy program can encode `(ValueTokenV1b[] tokens, bool includeNative)`
///        and call {computeInteractionUsdValue}
///      - the registry resolves token metadata and Chainlink feeds
///      - the result can then be used to enforce value-based approval or budget rules
abstract contract PriceModule {
    // --- Native token price feed configuration ---
    /// @notice Emitted when governance binds a native USD feed and decimal count.
    /// @param feed New Chainlink-compatible feed, or zero to clear configuration.
    /// @param priceFeedDecimals Expected live `decimals()` value for `feed`.
    event NativeUsdFeedUpdated(address indexed feed, uint8 priceFeedDecimals);
    /// @notice Emitted when governance changes a feed's mandatory heartbeat.
    event FeedMaxAgeUpdated(address indexed feed, uint64 maxAge);
    /// @notice Emitted when governance selects L1 or sequencer-protected L2 oracle semantics.
    event OracleEnvironmentUpdated(
        bool sequencerRequired, address indexed sequencerUptimeFeed, uint64 recoveryGracePeriod
    );

    /// @notice Maximum per-valuation freshness bound accepted by VALUEUSD.
    uint32 public constant MAX_VALUATION_FEED_AGE = 2 days;
    /// @dev Maximum decimal exponent supported by exact valuation arithmetic.
    uint8 internal constant MAX_PRICE_DECIMALS = 36;

    /// @notice Thrown when a feed address or decimal configuration is invalid.
    error InvalidFeedConfiguration();
    /// @notice Thrown when a live feed changes its Registry-bound decimal count.
    error FeedDecimalsMismatch(uint8 expected, uint8 actual);
    /// @notice Thrown when a feed answer is zero or negative.
    error InvalidPriceAnswer();
    /// @notice Thrown when the reported answer predates the requested round.
    error IncompletePriceRound();
    /// @notice Thrown when the price timestamp is zero or in the future.
    error InvalidPriceTimestamp();
    /// @notice Thrown when a price exceeds any applicable freshness bound.
    error StalePrice();
    /// @notice Thrown when exact valuation requests zero or excessive freshness.
    error InvalidValuationFeedAge(uint256 maxAge);
    /// @notice Thrown when exact product-ratio inputs are malformed.
    error PriceRatioInvalid();
    /// @notice Thrown when an exact USD18 value does not fit in uint256.
    error PriceRatioOverflow();
    /// @notice Thrown when a multi-asset USD18 sum does not fit in uint256.
    error PriceSumOverflow();
    /// @notice Thrown when a feed has no mandatory reviewed heartbeat.
    error FeedMaxAgeRequired(address feed);
    /// @notice Thrown when a feed heartbeat configuration is invalid.
    error FeedConfigurationInvalid(address feed);
    /// @notice Thrown when L1 or L2 oracle environment arguments are inconsistent.
    error OracleEnvironmentInvalid();
    /// @notice Thrown until governance explicitly selects the oracle environment.
    error OracleEnvironmentUnconfigured();
    /// @notice Thrown while the configured L2 sequencer is down.
    error SequencerUnavailable();
    /// @notice Thrown when the configured L2 sequencer feed returns an invalid round.
    error SequencerRoundInvalid();
    /// @notice Thrown until the full post-recovery grace period has elapsed.
    error SequencerGracePeriodActive(uint256 elapsed, uint256 required);

    bytes32 internal constant _NATIVE_FEED_SCOPE = keccak256("price.native.usd.feed");
    bytes32 internal constant _NATIVE_STALENESS_SCOPE = keccak256("price.native.usd.staleness");
    bytes32 internal constant _FEED_MAX_AGE_SCOPE_PREFIX = keccak256("price.feed.max-age");
    bytes32 internal constant _ORACLE_ENVIRONMENT_SCOPE = keccak256("price.oracle.environment");

    /// @notice Set an optional global ceiling applied in addition to every feed's mandatory max age.
    /// @dev Zero removes only the global ceiling. It never disables the per-feed freshness check.
    /// @param seconds_ Global maximum feed age, or zero to rely on the mandatory per-feed bound.
    function setMaxFeedStaleness(uint256 seconds_) external {
        _requirePriceAdmin();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryToken(),
                scope: _NATIVE_STALENESS_SCOPE,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setMaxFeedStaleness.selector, seconds_)
        );
        if (!executing) {
            return;
        }
        OracleSafetyStorage.getLayout().maxFeedStaleness = seconds_;
        ExecutionCatalogStorage.bumpRuntime();
    }

    /// @notice Return the optional global maximum feed staleness.
    /// @return Maximum age in seconds, or zero when globally disabled.
    function getMaxFeedStaleness() external view returns (uint256) {
        return OracleSafetyStorage.getLayout().maxFeedStaleness;
    }

    /// @notice Set the reviewed heartbeat/max age for one price feed.
    /// @dev A zero value disables that feed for price reads. This setting is
    ///      mandatory even when the caller supplies a stricter `maxAge`.
    function setFeedMaxAge(address feed, uint64 maxAge) external {
        _requirePriceAdmin();
        if (feed == address(0) || (maxAge != 0 && feed.code.length == 0)) {
            revert FeedConfigurationInvalid(feed);
        }
        bytes32 scope = keccak256(abi.encode(_FEED_MAX_AGE_SCOPE_PREFIX, feed));
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryToken(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setFeedMaxAge.selector, feed, maxAge)
        );
        if (!executing) {
            return;
        }
        OracleSafetyStorage.getLayout().feedMaxAge[feed] = maxAge;
        // Complete public programs bind only the heartbeats of feeds they can
        // read. The full catalog revision remains conservative for hidden or
        // incomplete dependency graphs.
        ExecutionCatalogStorage.bump();
        // Timelock queueing and revision updates are internal storage operations; feed introspection is
        // STATICCALL-only.
        // forge-lint: disable-next-line(reentrancy-events)
        emit FeedMaxAgeUpdated(feed, maxAge);
    }

    /// @notice Return the reviewed heartbeat/max age for one price feed.
    function getFeedMaxAge(address feed) external view returns (uint64) {
        return OracleSafetyStorage.getLayout().feedMaxAge[feed];
    }

    /// @notice Declare whether this registry executes on an L2 that requires a sequencer uptime feed.
    /// @dev This must be called explicitly for every deployment. L1 mode requires
    ///      a zero feed and zero grace period; L2 mode requires deployed feed code
    ///      and a nonzero post-recovery grace period.
    function setOracleEnvironment(bool sequencerRequired, address sequencerUptimeFeed, uint64 recoveryGracePeriod)
        external
    {
        _requirePriceAdmin();
        if (sequencerRequired
                ? sequencerUptimeFeed == address(0) || sequencerUptimeFeed.code.length == 0 || recoveryGracePeriod == 0
                : sequencerUptimeFeed != address(0) || recoveryGracePeriod != 0) {
            revert OracleEnvironmentInvalid();
        }
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryToken(),
                scope: _ORACLE_ENVIRONMENT_SCOPE,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(
                this.setOracleEnvironment.selector, sequencerRequired, sequencerUptimeFeed, recoveryGracePeriod
            )
        );
        if (!executing) {
            return;
        }

        OracleSafetyStorage.Layout storage oracle = OracleSafetyStorage.getLayout();
        oracle.configured = true;
        oracle.sequencerRequired = sequencerRequired;
        oracle.sequencerUptimeFeed = sequencerUptimeFeed;
        oracle.sequencerGracePeriod = recoveryGracePeriod;
        ExecutionCatalogStorage.bumpRuntime();
        // Timelock queueing and revision updates are internal storage operations; feed introspection is
        // STATICCALL-only.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OracleEnvironmentUpdated(sequencerRequired, sequencerUptimeFeed, recoveryGracePeriod);
    }

    /// @notice Return the configured oracle environment.
    function getOracleEnvironment()
        external
        view
        returns (bool configured, bool sequencerRequired, address sequencerUptimeFeed, uint64 recoveryGracePeriod)
    {
        OracleSafetyStorage.Layout storage oracle = OracleSafetyStorage.getLayout();
        return (oracle.configured, oracle.sequencerRequired, oracle.sequencerUptimeFeed, oracle.sequencerGracePeriod);
    }

    /// @dev Role used for admin gating in modules; resolves to keccak256("ADMIN_ROLE").
    function _adminRole() internal pure virtual returns (bytes32) {
        // forge-lint: disable-next-line(asm-keccak256)
        return keccak256("ADMIN_ROLE");
    }

    /// @dev Authorize price configuration in the caller's native authority model.
    function _requirePriceAdmin() internal view virtual;

    /// @dev Hook for fetching token metadata by its precomputed hash. Implemented in the inheriting registry.
    function _getTokenByHash(bytes32 h) internal view virtual returns (ERCToken memory);

    /// @dev Hook for token activation state. Inheritors that do not track flags default to active.
    function _isTokenActiveByHash(bytes32) internal view virtual returns (bool) {
        return true;
    }

    // --- Price helpers (Chainlink) ---

    /// @dev Fail closed until governance explicitly selects L1 or L2 behavior.
    function _checkOracleEnvironment() private view {
        OracleSafetyStorage.Layout storage oracle = OracleSafetyStorage.getLayout();
        // Oracle environment must be configured before any valuation; no component may bypass this fail-closed
        // gate.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (!oracle.configured) revert OracleEnvironmentUnconfigured();
        if (!oracle.sequencerRequired) return;

        (
            uint80 roundId,
            int256 status,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
            // Each asset requires its own oracle STATICCALL and validity checks; incomplete valuation is rejected
            // atomically.
            // forge-lint: disable-next-line(calls-loop)
        ) = AggregatorV3Interface(oracle.sequencerUptimeFeed).latestRoundData();
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (status != 0) revert SequencerUnavailable();
        uint256 currentTimestamp = block.timestamp;
        if (
            // Chain time bounds oracle freshness and sequencer recovery; invalid/future rounds fail closed and
            // never provide authorization.
            // forge-lint: disable-next-line(block-timestamp)
            answeredInRound < roundId || startedAt == 0 || startedAt > currentTimestamp || updatedAt == 0
                // Chain time bounds oracle freshness and sequencer recovery; invalid/future rounds fail closed and
                // never provide authorization.
                // forge-lint: disable-next-line(block-timestamp)
                || updatedAt > currentTimestamp
        ) {
            // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
            // value.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert SequencerRoundInvalid();
        }

        // Chainlink's recovery guidance treats the entire grace boundary as
        // unsafe, so execution resumes only after strictly more time elapsed.
        uint256 elapsed = currentTimestamp - startedAt;
        // Chain time bounds oracle freshness and sequencer recovery; invalid/future rounds fail closed and never
        // provide authorization.
        // forge-lint: disable-next-line(block-timestamp)
        if (elapsed <= oracle.sequencerGracePeriod) {
            // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
            // value.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert SequencerGracePeriodActive(elapsed, oracle.sequencerGracePeriod);
        }
    }

    /// @dev Read and validate the latest round from a Chainlink-compatible feed.
    /// @param feed Feed proxy or aggregator address.
    /// @param expectedDecimals Decimal count bound in Registry state.
    /// @param maxAge Additional per-call freshness bound when `requirePerCallFreshness` is true.
    /// @param requirePerCallFreshness Whether to enforce `maxAge` in addition to Registry feed bounds.
    /// @return answer Strictly positive raw feed answer.
    /// @return dec Live decimal count, proven equal to `expectedDecimals`.
    /// @return updatedAt Timestamp of the accepted feed round.
    function _readFeed(address feed, uint8 expectedDecimals, uint256 maxAge, bool requirePerCallFreshness)
        internal
        view
        returns (int256 answer, uint8 dec, uint256 updatedAt)
    {
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (feed.code.length == 0 || expectedDecimals > MAX_PRICE_DECIMALS) revert InvalidFeedConfiguration();
        _checkOracleEnvironment();
        uint64 feedMaxAge = OracleSafetyStorage.getLayout().feedMaxAge[feed];
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (feedMaxAge == 0) revert FeedMaxAgeRequired(feed);
        // Freshness uses updatedAt; answer, round completion, age, and decimals are checked below, not round start time.
        // forge-lint: disable-start(unused-return)
        (
            uint80 roundId,
            int256 ans,,
            uint256 updAt,
            uint80 answeredInRound
            // Each asset requires its own oracle STATICCALL and validity checks; incomplete valuation is rejected
            // atomically.
            // forge-lint: disable-next-line(calls-loop)
        ) = AggregatorV3Interface(feed).latestRoundData();
        // forge-lint: disable-end(unused-return)

        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (ans <= 0) revert InvalidPriceAnswer();
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (answeredInRound < roundId) revert IncompletePriceRound();
        // A future timestamp is not fresh data. Reject it at the shared feed boundary so callers cannot treat it as
        // age zero or underflow while computing `block.timestamp - updatedAt`. Aggregate valuation must reject any
        // invalid component or oracle round; skipping one would understate value.
        // forge-lint: disable-next-line(block-timestamp, require-revert-in-loop)
        if (updAt == 0 || updAt > block.timestamp) revert InvalidPriceTimestamp();

        uint256 age = block.timestamp - updAt;
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value. Chain time bounds oracle freshness and sequencer recovery;
        // invalid/future rounds fail closed and never provide authorization.
        // forge-lint: disable-next-line(require-revert-in-loop, block-timestamp)
        if (age > feedMaxAge) revert StalePrice();
        uint256 maxFeedStaleness = OracleSafetyStorage.getLayout().maxFeedStaleness;
        if (maxFeedStaleness != 0) {
            // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
            // value. Chain time bounds oracle freshness and sequencer recovery;
            // invalid/future rounds fail closed and never provide authorization.
            // forge-lint: disable-next-line(require-revert-in-loop, block-timestamp)
            if (age > maxFeedStaleness) revert StalePrice();
        }
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value. Chain time bounds oracle freshness and sequencer recovery;
        // invalid/future rounds fail closed and never provide authorization.
        // forge-lint: disable-next-line(require-revert-in-loop, block-timestamp)
        if (requirePerCallFreshness && age > maxAge) revert StalePrice();

        // Each asset requires its own oracle STATICCALL and validity checks; incomplete valuation is rejected
        // atomically.
        // forge-lint: disable-next-line(calls-loop)
        uint8 d = AggregatorV3Interface(feed).decimals();
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (d > MAX_PRICE_DECIMALS) revert InvalidFeedConfiguration();
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (d != expectedDecimals) revert FeedDecimalsMismatch(expectedDecimals, d);

        answer = ans;
        dec = d;
        updatedAt = updAt;
    }

    /// @dev Validate a feed at configuration time and bind its current decimals.
    function _validateFeedConfiguration(address feed, uint8 expectedDecimals) internal view {
        if (feed == address(0)) {
            if (expectedDecimals != 0) revert InvalidFeedConfiguration();
            return;
        }
        if (feed.code.length == 0 || expectedDecimals > MAX_PRICE_DECIMALS) revert InvalidFeedConfiguration();
        uint8 actual = AggregatorV3Interface(feed).decimals();
        if (actual > MAX_PRICE_DECIMALS) revert InvalidFeedConfiguration();
        if (actual != expectedDecimals) revert FeedDecimalsMismatch(expectedDecimals, actual);
    }

    /// @dev Require a meaningful nonzero freshness bound within the protocol maximum.
    function _validateValuationAge(uint256 maxAge) internal pure {
        if (maxAge == 0 || maxAge > MAX_VALUATION_FEED_AGE) revert InvalidValuationFeedAge(maxAge);
    }

    /// @dev Compute `ceil(amount * rawAnswer * 1e18 / 10^assetDecimals / 10^feedDecimals)` once.
    function _exactUsdValue18(uint256 amount, uint256 rawAnswer, uint8 assetDecimals, uint8 feedDecimals)
        internal
        pure
        returns (uint256 value)
    {
        uint256[] memory factors = new uint256[](5);
        factors[0] = amount;
        factors[1] = rawAnswer;
        factors[2] = 1e18;
        factors[3] = 10 ** assetDecimals;
        factors[4] = 10 ** feedDecimals;
        (ProductRatioMath.RatioStatus status, uint256 result) = ProductRatioMath.tryCeil(factors, 0x18);
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (status == ProductRatioMath.RatioStatus.Invalid) revert PriceRatioInvalid();
        // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
        // value.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (status == ProductRatioMath.RatioStatus.Overflow) revert PriceRatioOverflow();
        return result;
    }

    /// @dev Scale a number from `fromDec` decimals to `toDec` decimals.
    function _scalePrice(uint256 price, uint8 fromDec, uint8 toDec) internal pure returns (uint256) {
        require(fromDec <= 36 && toDec <= 36, "dec out of range");
        if (fromDec == toDec) return price;
        if (fromDec > toDec) {
            return price / (10 ** (fromDec - toDec));
        } else {
            uint256 factor = 10 ** (toDec - fromDec);
            uint256 scaled = price * factor;
            require(scaled / factor == price, "overflow");
            return scaled;
        }
    }

    /// @notice Compute the USD value for a list of tokens and optional native amount.
    /// @dev The `spec` must be encoded with `abi.encode(ValueTokenV1b[] tokens, bool includeNative)`.
    ///      Each token and optional native component is converted to USD18 with exact ceiling division, then the
    ///      individually rounded terms are summed.
    /// @param spec ABI-encoded `(ValueTokenV1b[] tokens, bool includeNative)`.
    /// @param nativeAmountWei Native amount (e.g., `msg.value`) to include when `includeNative` is true.
    /// @param maxAge Additional per-call freshness bound; zero relies on Registry feed bounds.
    /// @return usdValue1e18 Sum of individually ceiling-rounded USD values, scaled to 1e18.
    /// @return oldestUpdateAt The oldest (minimum) `updatedAt` among all price feeds used.
    function computeInteractionUsdValue(
        bytes calldata spec,
        uint256 nativeAmountWei,
        uint256 maxAge // seconds, 0 to use only Registry feed bounds
    )
        external
        view
        returns (uint256 usdValue1e18, uint256 oldestUpdateAt)
    {
        (ValueTokenV1b[] memory tokens, bool includeNative) = abi.decode(spec, (ValueTokenV1b[], bool));

        oldestUpdateAt = type(uint256).max;

        // Sum token components
        for (uint256 i = 0; i < tokens.length; i++) {
            ERCToken memory t = _getTokenByHash(tokens[i].contractHash);
            // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
            // value.
            // forge-lint: disable-next-line(require-revert-in-loop)
            require(_isTokenActiveByHash(tokens[i].contractHash), "token inactive");
            // Aggregate valuation must reject any invalid component or oracle round; skipping one would understate
            // value.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (t.decimals > MAX_PRICE_DECIMALS) revert InvalidFeedConfiguration();
            (int256 raw,, uint256 ts) = _readFeed(t.price, t.priceFeedDecimals, maxAge, maxAge != 0);
            // forge-lint: disable-next-line(unsafe-typecast)
            uint256 term = _exactUsdValue18(tokens[i].amount, uint256(raw), t.decimals, t.priceFeedDecimals);
            // Every component must fit the aggregate; skipping an overflowing term would understate valuation.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (term > type(uint256).max - usdValue1e18) revert PriceSumOverflow();
            usdValue1e18 += term;
            if (ts < oldestUpdateAt) oldestUpdateAt = ts;
        }

        // Include native component if requested
        if (includeNative) {
            (int256 raw, uint8 dec, uint256 nts) = _readNativeFeed(maxAge, maxAge != 0);
            // forge-lint: disable-next-line(unsafe-typecast)
            uint256 term = _exactUsdValue18(nativeAmountWei, uint256(raw), 18, dec);
            if (term > type(uint256).max - usdValue1e18) revert PriceSumOverflow();
            usdValue1e18 += term;
            if (nts < oldestUpdateAt) oldestUpdateAt = nts;
        }

        if (oldestUpdateAt == type(uint256).max) {
            oldestUpdateAt = 0;
        }
    }

    /// @notice Returns the USD price for a token scaled to a target number of decimals.
    /// @param h Precomputed hash of the token (e.g., keccak256(org + id)).
    /// @param outDecimals Target decimals for the returned price (e.g., 18).
    /// @return price Scaled unsigned price (e.g., 1e18-based if outDecimals = 18)
    /// @return updatedAt Last update timestamp from the feed
    function _getTokenUsdPriceScaled(bytes32 h, uint8 outDecimals)
        internal
        view
        returns (uint256 price, uint256 updatedAt)
    {
        (int256 raw, uint8 dec, uint256 ts) = _getTokenUsdPriceRaw(h);
        // casting to 'uint256' is safe because Chainlink USD price is guaranteed > 0 and fits into uint256 range
        // forge-lint: disable-next-line(unsafe-typecast)
        price = _scalePrice(uint256(raw), dec, outDecimals);
        updatedAt = ts;
    }

    /// @notice Return a token USD price scaled to caller-selected decimals.
    /// @param h Precomputed token key.
    /// @param outDecimals Desired result decimals.
    /// @return price Scaled positive price.
    /// @return updatedAt Accepted feed update timestamp.
    function getTokenUsdPriceScaled(bytes32 h, uint8 outDecimals)
        external
        view
        returns (uint256 price, uint256 updatedAt)
    {
        return _getTokenUsdPriceScaled(h, outDecimals);
    }

    /// @notice Returns the USD price scaled to `outDecimals` and enforces a freshness bound.
    /// @dev `maxAge` of 0 adds no caller-specific ceiling; the mandatory per-feed max age still applies.
    /// @param h Precomputed token key.
    /// @param outDecimals Desired result decimals.
    /// @param maxAge Optional caller-selected freshness bound.
    /// @return price Scaled positive price.
    function getTokenUsdPriceScaledFresh(bytes32 h, uint8 outDecimals, uint256 maxAge)
        external
        view
        returns (uint256 price)
    {
        uint256 updatedAt;
        (price, updatedAt) = _getTokenUsdPriceScaled(h, outDecimals);
        if (maxAge != 0) {
            // forge-lint: disable-next-line(block-timestamp)
            if (block.timestamp - updatedAt > maxAge) revert StalePrice();
        }
    }

    /// @notice Returns the raw USD price for a token using its configured Chainlink feed.
    /// @dev Price is returned with the feed's native decimals (typically 8).
    /// @return answer Signed integer price as returned by the feed (must be > 0)
    /// @return decimals Number of decimals of the returned price
    /// @return updatedAt Last update timestamp from the feed
    function _getTokenUsdPriceRaw(bytes32 h) internal view returns (int256 answer, uint8 decimals, uint256 updatedAt) {
        // Resolve the locally stored token record and read its configured USD feed.
        require(_isTokenActiveByHash(h), "token inactive");
        ERCToken memory token = _getTokenByHash(h);
        (answer, decimals, updatedAt) = _readFeed(token.price, token.priceFeedDecimals, 0, false);
    }

    /// @notice Return a token feed's raw positive answer, bound decimals, and update timestamp.
    /// @param h Precomputed token key.
    function getTokenUsdPriceRaw(bytes32 h) external view returns (int256 answer, uint8 decimals, uint256 updatedAt) {
        return _getTokenUsdPriceRaw(h);
    }

    /// @notice Return the exact conservative USD18 value of a token amount.
    /// @dev Reads the raw answer and rounds only once after multiplying all numerator factors.
    /// @param tokenHash Precomputed active token key.
    /// @param amount Amount in the token's native decimals.
    /// @param maxAge Required nonzero feed freshness bound in seconds.
    /// @return Exact-ceiling USD value scaled to 18 decimals.
    function getTokenUsdValue18Ceil(bytes32 tokenHash, uint256 amount, uint256 maxAge) external view returns (uint256) {
        _validateValuationAge(maxAge);
        require(_isTokenActiveByHash(tokenHash), "token inactive");
        ERCToken memory token = _getTokenByHash(tokenHash);
        if (token.decimals > MAX_PRICE_DECIMALS) revert InvalidFeedConfiguration();
        (int256 raw,,) = _readFeed(token.price, token.priceFeedDecimals, maxAge, true);
        // _readFeed guarantees a strictly positive answer.
        // forge-lint: disable-next-line(unsafe-typecast)
        return _exactUsdValue18(amount, uint256(raw), token.decimals, token.priceFeedDecimals);
    }

    // --- Public/API: Native token USD price ---

    /// @notice Admin setter for the native-token USD feed proxy address (per chain).
    /// @param feed Chainlink aggregator/proxy address for the native token/USD pair.
    /// @param priceFeedDecimals Expected live `decimals()` value bound by governance.
    function setNativeUsdFeed(address feed, uint8 priceFeedDecimals) external {
        _requirePriceAdmin();
        _validateFeedConfiguration(feed, priceFeedDecimals);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryToken(),
                scope: _NATIVE_FEED_SCOPE,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setNativeUsdFeed.selector, feed, priceFeedDecimals)
        );
        if (!executing) {
            return;
        }
        _validateFeedConfiguration(feed, priceFeedDecimals);
        OracleSafetyStorage.Layout storage oracle = OracleSafetyStorage.getLayout();
        oracle.nativeUsdFeed = feed;
        oracle.nativeUsdFeedDecimals = priceFeedDecimals;
        ExecutionCatalogStorage.bumpRuntime();
        // Timelock queueing and revision updates are internal storage operations; feed introspection is
        // STATICCALL-only.
        // forge-lint: disable-next-line(reentrancy-events)
        emit NativeUsdFeedUpdated(feed, priceFeedDecimals);
    }

    /// @notice Return the native USD feed and its governance-bound decimal count.
    /// @return feed Configured Chainlink-compatible feed, or zero when unset.
    /// @return priceFeedDecimals Expected live decimal count for `feed`.
    function getNativeUsdFeedConfig() external view returns (address feed, uint8 priceFeedDecimals) {
        OracleSafetyStorage.Layout storage oracle = OracleSafetyStorage.getLayout();
        return (oracle.nativeUsdFeed, oracle.nativeUsdFeedDecimals);
    }

    /// @dev Read the configured native feed using the shared oracle validation.
    function _readNativeFeed(uint256 maxAge, bool requirePerCallFreshness)
        internal
        view
        returns (int256 answer, uint8 decimals, uint256 updatedAt)
    {
        OracleSafetyStorage.Layout storage oracle = OracleSafetyStorage.getLayout();
        return _readFeed(oracle.nativeUsdFeed, oracle.nativeUsdFeedDecimals, maxAge, requirePerCallFreshness);
    }

    /// @notice Returns the raw native-token/USD price from the configured feed.
    /// @dev Price is returned with the feed's native decimals (typically 8).
    /// @return answer Signed price as reported by the feed (> 0 expected).
    /// @return decimals Number of decimals used by the feed.
    /// @return updatedAt Last update timestamp from the feed.
    function _getNativeUsdPriceRaw() internal view returns (int256 answer, uint8 decimals, uint256 updatedAt) {
        return _readNativeFeed(0, false);
    }

    /// @notice Return the native feed's raw positive answer, bound decimals, and update timestamp.
    function getNativeUsdPriceRaw() external view returns (int256 answer, uint8 decimals, uint256 updatedAt) {
        return _getNativeUsdPriceRaw();
    }

    /// @notice Returns the native-token/USD price scaled to a target decimals (e.g., 18).
    /// @param outDecimals Target decimals for the returned price.
    /// @return price Scaled unsigned price.
    /// @return updatedAt Last update timestamp from the feed.
    function _getNativeUsdPriceScaled(uint8 outDecimals) internal view returns (uint256 price, uint256 updatedAt) {
        (int256 raw, uint8 dec, uint256 ts) = _getNativeUsdPriceRaw();
        // casting to 'uint256' is safe because Chainlink USD price is guaranteed > 0 and fits into uint256 range
        // forge-lint: disable-next-line(unsafe-typecast)
        price = _scalePrice(uint256(raw), dec, outDecimals);
        updatedAt = ts;
    }

    /// @notice Return the native USD price scaled to caller-selected decimals.
    /// @param outDecimals Desired result decimals.
    /// @return price Scaled positive price.
    /// @return updatedAt Accepted feed update timestamp.
    function getNativeUsdPriceScaled(uint8 outDecimals) external view returns (uint256 price, uint256 updatedAt) {
        return _getNativeUsdPriceScaled(outDecimals);
    }

    /// @notice Return the exact conservative USD18 value of native wei.
    /// @dev Reads the raw answer and rounds only once after multiplying all numerator factors.
    /// @param amountWei Native value in wei.
    /// @param maxAge Required nonzero feed freshness bound in seconds.
    /// @return Exact-ceiling USD value scaled to 18 decimals.
    function getNativeUsdValue18Ceil(uint256 amountWei, uint256 maxAge) external view returns (uint256) {
        _validateValuationAge(maxAge);
        (int256 raw, uint8 dec,) = _readNativeFeed(maxAge, true);
        // _readFeed guarantees a strictly positive answer.
        // forge-lint: disable-next-line(unsafe-typecast)
        return _exactUsdValue18(amountWei, uint256(raw), 18, dec);
    }
}
