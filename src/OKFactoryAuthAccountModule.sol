// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {OKFactoryConfig} from "./OKFactoryConfig.sol";
import {OKFactoryModuleBase} from "./OKFactoryModuleBase.sol";
import {WebAuthnAuthAccountFactory} from "./WebAuthnAuthAccountFactory.sol";
import {RegistryAuthFacet} from "./registry/facets/RegistryAuthFacet.sol";

/// @title OKFactoryAuthAccountModule
/// @notice Delegatecall module that deploys and trusts a tenant WebAuthn AuthAccount factory.
/// @dev Kept separate from stage 1 so the large AuthAccount factory initcode does not bloat stage-1 runtime bytecode.
contract OKFactoryAuthAccountModule is OKFactoryModuleBase {
    /// @notice Deploy the tenant AuthAccount factory and trust it on the tenant registry.
    /// @param config Immutable factory config mirrored from the wrapper.
    /// @param registryAddr Tenant registry receiving the trusted factory entry.
    /// @param interact Bootstrap-frozen Interact address bound into AuthAccounts.
    /// @param safeFactory Bootstrap-frozen SafeFactory whose OKModule AuthAccounts may call.
    /// @param deploymentKey Domain-separated component salt key committed during stage-1 bootstrap.
    function deployAuthAccountFactory(
        OKFactoryConfig config,
        address registryAddr,
        address interact,
        address safeFactory,
        bytes32 deploymentKey
    ) external onlyDelegateCall returns (address deployedAuthFactory) {
        bytes memory initData = abi.encodeCall(
            WebAuthnAuthAccountFactory.initialize,
            (
                registryAddr,
                interact,
                safeFactory,
                config.WEB_AUTHN_ENTRY_POINT(),
                config.WEB_AUTHN_ACCOUNT_IMPL(),
                config.WEB_AUTHN_RP_ID_HASH(),
                config.WEB_AUTHN_ORIGIN(),
                config.WEB_AUTHN_REQUIRE_USER_VERIFICATION()
            )
        );
        deployedAuthFactory = address(
            new ERC1967Proxy{salt: _deploymentSalt(8, deploymentKey)}(config.WEB_AUTHN_FACTORY_IMPL(), initData)
        );
        _pendingAuthAccountFactories[registryAddr] = deployedAuthFactory;
        RegistryAuthFacet(registryAddr).setAuthAccountFactory(deployedAuthFactory, true);
    }
}
