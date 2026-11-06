// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {ERCToken} from "@chainwall/interfaces/RegistryTypes.sol";

import {TenantFixture} from "./TenantFixture.sol";

/// @notice Minimal Chainlink-shaped feed: enough to pass Registry token-feed registration.
contract FakeFeed {
    function ping() external {}

    function decimals() external pure returns (uint8) {
        return 8;
    }
}

interface IConfigView {
    function REGISTRY_IMPL() external view returns (address);
    function ACCOUNT_ENGINE() external view returns (address);
}

/// @notice Step 6 beyond the engine: places that used to accept "any code" as proof of a contract.
///         In each test the delegated EOA points at GENUINE code of the expected kind, so every later
///         check (decimals, component id, ...) would pass. Only the contract-code check stops it.
contract Contractness7702Test is TenantFixture {
    address internal eoa;
    uint256 internal eoaPk;

    function setUp() public {
        _setUpTenant();
        _configureTenant();
        (eoa, eoaPk) = makeAddrAndKey("chainwall-test impostor");
        _requirePlainEOA(eoa);
    }

    // ------------------------------------------------------------------ price feeds

    function _usdcToken(address feed) internal pure returns (ERCToken memory) {
        return ERCToken("circle", "usdc", "USDC", 6, feed, 8);
    }

    /// @notice Control: a real contract with the right decimals is accepted as a feed.
    function test_feed_realContractAccepted() public {
        address feed = address(new FakeFeed());
        vm.prank(tenantOwner);
        reg.upsertToken(_usdcToken(feed));
    }

    /// @notice A delegated EOA answering `decimals()` through its delegate is refused as a price feed.
    function test_feed_delegatedEOARefused() public {
        FakeFeed impl = new FakeFeed();
        _delegate(eoaPk, eoa, address(impl));
        assertEq(FakeFeed(eoa).decimals(), 8, "the delegated EOA does answer like a feed");

        vm.prank(tenantOwner);
        vm.expectRevert(bytes4(keccak256("TokenFeedInvalid()")));
        reg.upsertToken(_usdcToken(eoa));
    }

    // ------------------------------------------------------------------ sync sources

    function test_syncSource_delegatedEOARefused() public {
        // delegate to this tenant's own registry code path: any code will do for the old check
        _delegate(eoaPk, eoa, address(new FakeFeed()));
        vm.prank(tenantOwner);
        vm.expectRevert(bytes4(keccak256("SourceRegistryNotContract()")));
        reg.setSyncSourceAllowed(eoa, true);
    }

    // ------------------------------------------------------------------ passkey factory allowlist

    function test_authFactory_delegatedEOARefused() public {
        _delegate(eoaPk, eoa, address(new FakeFeed()));
        vm.prank(tenantOwner);
        vm.expectRevert(abi.encodeWithSignature("AuthAccountFactoryNotDeployed(address)", eoa));
        reg.setAuthAccountFactory(eoa, true);
    }

    // ------------------------------------------------------------------ upgrades and releases

    /// @notice An EOA delegated to the genuine Registry implementation reports the right component id,
    ///         but must not be accepted as an upgrade implementation.
    function test_upgrade_delegatedEOARefusedAsImplementation() public {
        address realImpl = IConfigView(address(config)).REGISTRY_IMPL();
        vm7702.signAndAttachDelegation(realImpl, eoaPk);
        vm.prank(attacker);
        (bool ok,) = eoa.call(abi.encodeWithSignature("paused()"));
        assertTrue(ok, "delegation carrier call failed");
        assertEq(eoa.code, abi.encodePacked(hex"ef0100", realImpl), "not delegated to the registry implementation");

        vm.prank(tenantOwner);
        vm.expectRevert(abi.encodeWithSignature("UpgradeImplementationInvalid(address)", eoa));
        reg.upgradeRegistry(eoa, "");
    }

    /// @notice A delegated EOA must not be accepted as the component whose engine is being replaced.
    function test_release_delegatedEOARefusedAsTarget() public {
        _delegate(eoaPk, eoa, address(new FakeFeed()));
        address currentEngine = IConfigView(address(config)).ACCOUNT_ENGINE();
        vm.prank(tenantOwner);
        vm.expectRevert(abi.encodeWithSignature("ReleaseTargetInvalid(address)", eoa));
        reg.replaceEngine(eoa, currentEngine);
    }
}
