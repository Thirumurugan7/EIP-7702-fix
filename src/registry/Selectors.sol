// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {PriceModule} from "../PriceModule.sol";
import {IRegistryTerms} from "./Terms.sol";
import {RegistryAccountsFacet} from "./facets/RegistryAccountsFacet.sol";
import {RegistryAuthFacet} from "./facets/RegistryAuthFacet.sol";
import {RegistryCapabilitiesFacet} from "./facets/RegistryCapabilitiesFacet.sol";
import {RegistryContractsFacet} from "./facets/RegistryContractsFacet.sol";
import {RegistryInteractionSyncFacet} from "./facets/RegistryInteractionSyncFacet.sol";
import {RegistryInteractionsFacet} from "./facets/RegistryInteractionsFacet.sol";
import {RegistryMetadataFacet} from "./facets/RegistryMetadataFacet.sol";
import {RegistryOrgsFacet} from "./facets/RegistryOrgsFacet.sol";
import {RegistryPoliciesFacet} from "./facets/RegistryPoliciesFacet.sol";
import {RegistryPolicyStateFacet} from "./facets/RegistryPolicyStateFacet.sol";
import {RegistrySyncFacet} from "./facets/RegistrySyncFacet.sol";
import {RegistrySyncQueryFacet} from "./facets/RegistrySyncQueryFacet.sol";
import {RegistryTimelockFacet} from "./facets/RegistryTimelockFacet.sol";
import {RegistryTimelockReleaseFacet} from "./facets/RegistryTimelockReleaseFacet.sol";
import {RegistryTimelockUpgradeFacet} from "./facets/RegistryTimelockUpgradeFacet.sol";
import {RegistryTokenCommitsFacet} from "./facets/RegistryTokenCommitsFacet.sol";
import {RegistryTokensFacet} from "./facets/RegistryTokensFacet.sol";
import {RegistryUsersFacet} from "./facets/RegistryUsersFacet.sol";

/// @title Selectors
/// @notice Canonical selector bundles installed by `OKFactoryConfig` on tenant registries.
/// @dev Centralizing these arrays keeps registry wiring deterministic across deployments.
///      The factory, tests, and loupe views can all reason about the same selector groups.
///      Function references keep each selector checked against its implementing facet ABI.
library Selectors {
    /// @notice Return the selector set for `RegistryUsersFacet`.
    function users() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](31);
        uint256 i = 0;
        sels[i++] = RegistryUsersFacet.addUser.selector;
        sels[i++] = RegistryUsersFacet.removeUser.selector;
        sels[i++] = RegistryUsersFacet.isUser.selector;
        sels[i++] = RegistryUsersFacet.getUserCount.selector;
        sels[i++] = RegistryUsersFacet.getUserAt.selector;
        sels[i++] = RegistryUsersFacet.createGroup.selector;
        sels[i++] = RegistryUsersFacet.deleteGroup.selector;
        sels[i++] = RegistryUsersFacet.addGroupMember.selector;
        sels[i++] = RegistryUsersFacet.removeGroupMember.selector;
        sels[i++] = RegistryUsersFacet.getGroupInfo.selector;
        sels[i++] = RegistryUsersFacet.getGroupMembershipRevision.selector;
        sels[i++] = RegistryUsersFacet.getGroupCount.selector;
        sels[i++] = RegistryUsersFacet.getGroupKeyAt.selector;
        sels[i++] = RegistryUsersFacet.getGroupKeysPage.selector;
        sels[i++] = RegistryUsersFacet.getGroupIndexNextId.selector;
        sels[i++] = RegistryUsersFacet.getGroupIndexCurrentEpoch.selector;
        sels[i++] = RegistryUsersFacet.getGroupIndexAlivePage.selector;
        sels[i++] = RegistryUsersFacet.getGroupIndexValues.selector;
        sels[i++] = RegistryUsersFacet.getGroupIndexEpochPageCount.selector;
        sels[i++] = RegistryUsersFacet.getGroupIndexEpochPageAt.selector;
        sels[i++] = RegistryUsersFacet.getGroupIndexJournal.selector;
        sels[i++] = RegistryUsersFacet.isGroupMemberByHash.selector;
        sels[i++] = RegistryUsersFacet.getGroupMembers.selector;
        sels[i++] = RegistryUsersFacet.allowDelegate.selector;
        sels[i++] = RegistryUsersFacet.disallowDelegate.selector;
        sels[i++] = RegistryUsersFacet.isDelegateAllowed.selector;
        sels[i++] = RegistryUsersFacet.getAllowedDelegateCount.selector;
        sels[i++] = RegistryUsersFacet.getAllowedDelegateAt.selector;
        sels[i++] = RegistryUsersFacet.delegateOf.selector;
        sels[i++] = RegistryUsersFacet.isActorUsable.selector;
        sels[i++] = RegistryUsersFacet.requireActorUsable.selector;
    }

    /// @notice Return the selector set for `RegistryAccountsFacet`.
    function accounts() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](27);
        uint256 i = 0;
        sels[i++] = RegistryAccountsFacet.addSafe.selector;
        sels[i++] = RegistryAccountsFacet.removeSafe.selector;
        sels[i++] = RegistryAccountsFacet.isSafeAllowed.selector;
        sels[i++] = RegistryAccountsFacet.isSafeExecutionAuthorityAllowed.selector;
        sels[i++] = RegistryAccountsFacet.getSafeCount.selector;
        sels[i++] = RegistryAccountsFacet.getSafeAt.selector;
        sels[i++] = RegistryAccountsFacet.getSafePage.selector;
        sels[i++] = RegistryAccountsFacet.getSafeIndexNextId.selector;
        sels[i++] = RegistryAccountsFacet.getSafeIndexCurrentEpoch.selector;
        sels[i++] = RegistryAccountsFacet.getSafeIndexAlivePage.selector;
        sels[i++] = RegistryAccountsFacet.getSafeIndexValues.selector;
        sels[i++] = RegistryAccountsFacet.getSafeIndexEpochPageCount.selector;
        sels[i++] = RegistryAccountsFacet.getSafeIndexEpochPageAt.selector;
        sels[i++] = RegistryAccountsFacet.getSafeIndexJournal.selector;
        sels[i++] = RegistryAccountsFacet.addAccount.selector;
        sels[i++] = RegistryAccountsFacet.removeAccount.selector;
        sels[i++] = RegistryAccountsFacet.isAccountAllowed.selector;
        sels[i++] = RegistryAccountsFacet.getAccountCount.selector;
        sels[i++] = RegistryAccountsFacet.getAccountAt.selector;
        sels[i++] = RegistryAccountsFacet.getAccountPage.selector;
        sels[i++] = RegistryAccountsFacet.getAccountIndexNextId.selector;
        sels[i++] = RegistryAccountsFacet.getAccountIndexCurrentEpoch.selector;
        sels[i++] = RegistryAccountsFacet.getAccountIndexAlivePage.selector;
        sels[i++] = RegistryAccountsFacet.getAccountIndexValues.selector;
        sels[i++] = RegistryAccountsFacet.getAccountIndexEpochPageCount.selector;
        sels[i++] = RegistryAccountsFacet.getAccountIndexEpochPageAt.selector;
        sels[i++] = RegistryAccountsFacet.getAccountIndexJournal.selector;
    }

    /// @notice Return the selector set for `RegistryOrgsFacet`.
    function orgs() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](23);
        uint256 i = 0;
        sels[i++] = RegistryOrgsFacet.upsertOrg.selector;
        sels[i++] = RegistryOrgsFacet.addOrgMember.selector;
        sels[i++] = RegistryOrgsFacet.removeOrgMember.selector;
        sels[i++] = RegistryOrgsFacet.setOrgCatalogDelegationEnabled.selector;
        sels[i++] = RegistryOrgsFacet.isOrgCatalogDelegationEnabled.selector;
        sels[i++] = RegistryOrgsFacet.setOrgSuspended.selector;
        sels[i++] = RegistryOrgsFacet.isOrgSuspended.selector;
        sels[i++] = RegistryOrgsFacet.proposeOrgOwner.selector;
        sels[i++] = RegistryOrgsFacet.acceptOrgOwner.selector;
        sels[i++] = RegistryOrgsFacet.getPendingOrgOwner.selector;
        sels[i++] = RegistryOrgsFacet.getOrg.selector;
        sels[i++] = RegistryOrgsFacet.getOrgByHash.selector;
        sels[i++] = RegistryOrgsFacet.getOrgMembers.selector;
        sels[i++] = RegistryOrgsFacet.getOrgCount.selector;
        sels[i++] = RegistryOrgsFacet.getOrgKeyAt.selector;
        sels[i++] = RegistryOrgsFacet.getOrgKeysPage.selector;
        sels[i++] = RegistryOrgsFacet.getOrgIndexNextId.selector;
        sels[i++] = RegistryOrgsFacet.getOrgIndexCurrentEpoch.selector;
        sels[i++] = RegistryOrgsFacet.getOrgIndexAlivePage.selector;
        sels[i++] = RegistryOrgsFacet.getOrgIndexValues.selector;
        sels[i++] = RegistryOrgsFacet.getOrgIndexEpochPageCount.selector;
        sels[i++] = RegistryOrgsFacet.getOrgIndexEpochPageAt.selector;
        sels[i++] = RegistryOrgsFacet.getOrgIndexJournal.selector;
    }

    /// @notice Return the selector set for `RegistryContractsFacet`.
    function contractsFacet() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](29);
        uint256 i = 0;
        sels[i++] = RegistryContractsFacet.addContractVersion.selector;
        sels[i++] = RegistryContractsFacet.addContractVersionWithFlags.selector;
        sels[i++] = RegistryContractsFacet.getContractMetadata.selector;
        sels[i++] = RegistryContractsFacet.getContractByHash.selector;
        sels[i++] = RegistryContractsFacet.getContractFlags.selector;
        sels[i++] = RegistryContractsFacet.getContractFlagsByHash.selector;
        sels[i++] = RegistryContractsFacet.setContractActive.selector;
        sels[i++] = RegistryContractsFacet.contractExists.selector;
        sels[i++] = RegistryContractsFacet.getContractVersion.selector;
        sels[i++] = RegistryContractsFacet.getAddress.selector;
        sels[i++] = RegistryContractsFacet.getAddressAt.selector;
        sels[i++] = RegistryContractsFacet.getAddressByLabel.selector;
        sels[i++] = RegistryContractsFacet.getContractByLabel.selector;
        sels[i++] = RegistryContractsFacet.getContractCount.selector;
        sels[i++] = RegistryContractsFacet.getContractKeyAt.selector;
        sels[i++] = RegistryContractsFacet.getContractKeysPage.selector;
        sels[i++] = RegistryContractsFacet.getContractIndexNextId.selector;
        sels[i++] = RegistryContractsFacet.getContractIndexCurrentEpoch.selector;
        sels[i++] = RegistryContractsFacet.getContractIndexAlivePage.selector;
        sels[i++] = RegistryContractsFacet.getContractIndexValues.selector;
        sels[i++] = RegistryContractsFacet.getContractIndexEpochPageCount.selector;
        sels[i++] = RegistryContractsFacet.getContractIndexEpochPageAt.selector;
        sels[i++] = RegistryContractsFacet.getContractIndexJournal.selector;
        sels[i++] = RegistryContractsFacet.commitContractPrivate.selector;
        sels[i++] = RegistryContractsFacet.cancelContractCommit.selector;
        sels[i++] = RegistryContractsFacet.expireContractCommit.selector;
        sels[i++] = RegistryContractsFacet.revealContractCommit.selector;
        sels[i++] = RegistryContractsFacet.getContractCommitByKey.selector;
        sels[i++] = RegistryContractsFacet.getContractCommitKeysPage.selector;
    }

    /// @notice Return the selector set for `RegistryInteractionsFacet`.
    function interactions() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](26);
        uint256 i = 0;
        sels[i++] = RegistryInteractionsFacet.upsertInteractionBundle.selector;
        sels[i++] = RegistryInteractionsFacet.setInteractionActive.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionScript.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionBindingHash.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionFlags.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionBundle.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionContentHash.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionBundleHash.selector;
        sels[i++] = RegistryInteractionsFacet.getLinkedArtifact.selector;
        sels[i++] = RegistryInteractionsFacet.getLinkedArtifactRelations.selector;
        sels[i++] = RegistryInteractionsFacet.getLinkedArtifactBindingHash.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionCount.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionKeyAt.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionKeysPage.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionIndexNextId.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionIndexCurrentEpoch.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionIndexAlivePage.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionIndexValues.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionIndexEpochPageCount.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionIndexEpochPageAt.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionIndexJournal.selector;
        sels[i++] = RegistryInteractionsFacet.commitInteractionPrivate.selector;
        sels[i++] = RegistryInteractionsFacet.cancelInteractionCommit.selector;
        sels[i++] = RegistryInteractionsFacet.revealInteractionCommit.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionCommit.selector;
        sels[i++] = RegistryInteractionsFacet.getInteractionCommitKeysPage.selector;
    }

    /// @notice Return the selector set for `RegistryMetadataFacet`.
    function metadata() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](9);
        uint256 i = 0;
        sels[i++] = RegistryMetadataFacet.setMeta.selector;
        sels[i++] = RegistryMetadataFacet.getMeta.selector;
        sels[i++] = RegistryMetadataFacet.deleteMeta.selector;
        sels[i++] = RegistryMetadataFacet.setImage.selector;
        sels[i++] = RegistryMetadataFacet.getImage.selector;
        sels[i++] = RegistryMetadataFacet.getChannels.selector;
        sels[i++] = RegistryMetadataFacet.getForeignIds.selector;
        sels[i++] = RegistryMetadataFacet.getDoc.selector;
        sels[i++] = RegistryMetadataFacet.getMetaIndexPage.selector;
    }

    /// @notice Return the selector set for `RegistryPolicyStateFacet`.
    function policyState() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](8);
        uint256 i = 0;
        sels[i++] = RegistryPolicyStateFacet.beginPolicyStateExecution.selector;
        sels[i++] = RegistryPolicyStateFacet.endPolicyStateExecution.selector;
        sels[i++] = RegistryPolicyStateFacet.currentPolicyStateExecution.selector;
        sels[i++] = RegistryPolicyStateFacet.setPolicyUint.selector;
        sels[i++] = RegistryPolicyStateFacet.getPolicyUint.selector;
        sels[i++] = RegistryPolicyStateFacet.consumePolicyMeter.selector;
        sels[i++] = RegistryPolicyStateFacet.getPolicyMeter.selector;
        sels[i++] = RegistryPolicyStateFacet.getPolicyMeterBucket.selector;
    }

    /// @notice Return the selector set for `RegistryPoliciesFacet`.
    function policies() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](19);
        uint256 i = 0;
        sels[i++] = RegistryPoliciesFacet.createPolicy.selector;
        sels[i++] = RegistryPoliciesFacet.setPolicy.selector;
        sels[i++] = RegistryPoliciesFacet.setPolicyProgram.selector;
        sels[i++] = RegistryPoliciesFacet.clearPolicyProgram.selector;
        sels[i++] = RegistryPoliciesFacet.deletePolicy.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyCount.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyKeyAt.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyKeysPage.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyIndexNextId.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyIndexCurrentEpoch.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyIndexAlivePage.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyIndexValues.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyIndexEpochPageCount.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyIndexEpochPageAt.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyIndexJournal.selector;
        sels[i++] = RegistryPoliciesFacet.policyExists.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyCriteria.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicyProgram.selector;
        sels[i++] = RegistryPoliciesFacet.getPolicy.selector;
    }

    /// @notice Return the selector set for `RegistryTokensFacet`.
    function tokens() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](36);
        uint256 i = 0;
        sels[i++] = RegistryTokensFacet.upsertToken.selector;
        sels[i++] = RegistryTokensFacet.upsertTokenWithFlags.selector;
        sels[i++] = RegistryTokensFacet.setTokenActive.selector;
        sels[i++] = RegistryTokensFacet.getToken.selector;
        sels[i++] = RegistryTokensFacet.getTokenByHash.selector;
        sels[i++] = RegistryTokensFacet.isTokenByHash.selector;
        sels[i++] = RegistryTokensFacet.getTokenFlags.selector;
        sels[i++] = RegistryTokensFacet.getTokenFlagsByHash.selector;
        sels[i++] = RegistryTokensFacet.getTokenSubmitter.selector;
        sels[i++] = RegistryTokensFacet.getTokenCount.selector;
        sels[i++] = RegistryTokensFacet.getTokenKeyAt.selector;
        sels[i++] = RegistryTokensFacet.getTokenKeysPage.selector;
        sels[i++] = RegistryTokensFacet.getTokenIndexNextId.selector;
        sels[i++] = RegistryTokensFacet.getTokenIndexCurrentEpoch.selector;
        sels[i++] = RegistryTokensFacet.getTokenIndexAlivePage.selector;
        sels[i++] = RegistryTokensFacet.getTokenIndexValues.selector;
        sels[i++] = RegistryTokensFacet.getTokenIndexEpochPageCount.selector;
        sels[i++] = RegistryTokensFacet.getTokenIndexEpochPageAt.selector;
        sels[i++] = RegistryTokensFacet.getTokenIndexJournal.selector;
        sels[i++] = PriceModule.setMaxFeedStaleness.selector;
        sels[i++] = PriceModule.setFeedMaxAge.selector;
        sels[i++] = PriceModule.getFeedMaxAge.selector;
        sels[i++] = PriceModule.setOracleEnvironment.selector;
        sels[i++] = PriceModule.getOracleEnvironment.selector;
        sels[i++] = PriceModule.computeInteractionUsdValue.selector;
        sels[i++] = PriceModule.getTokenUsdPriceScaled.selector;
        sels[i++] = PriceModule.getTokenUsdPriceScaledFresh.selector;
        sels[i++] = PriceModule.getTokenUsdPriceRaw.selector;
        sels[i++] = PriceModule.setNativeUsdFeed.selector;
        sels[i++] = PriceModule.getNativeUsdPriceRaw.selector;
        sels[i++] = PriceModule.getNativeUsdPriceScaled.selector;
        sels[i++] = PriceModule.getTokenUsdValue18Ceil.selector;
        sels[i++] = PriceModule.getNativeUsdValue18Ceil.selector;
        sels[i++] = PriceModule.getNativeUsdFeedConfig.selector;
        sels[i++] = PriceModule.getMaxFeedStaleness.selector;
        sels[i++] = PriceModule(address(0)).MAX_VALUATION_FEED_AGE.selector;
    }

    /// @notice Return the private token publication selectors for `RegistryTokenCommitsFacet`.
    function tokenCommits() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](6);
        uint256 i = 0;
        sels[i++] = RegistryTokenCommitsFacet.commitTokenPrivate.selector;
        sels[i++] = RegistryTokenCommitsFacet.cancelTokenCommit.selector;
        sels[i++] = RegistryTokenCommitsFacet.expireTokenCommit.selector;
        sels[i++] = RegistryTokenCommitsFacet.revealTokenCommit.selector;
        sels[i++] = RegistryTokenCommitsFacet.getTokenCommitByKey.selector;
        sels[i++] = RegistryTokenCommitsFacet.getTokenCommitKeysPage.selector;
    }

    /// @notice Return the selector set for `RegistryAuthFacet`.
    function auth() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](9);
        uint256 i = 0;
        sels[i++] = RegistryAuthFacet.setAuthAccountFactory.selector;
        sels[i++] = RegistryAuthFacet.isAuthAccountFactoryAllowed.selector;
        sels[i++] = RegistryAuthFacet.linkAuthCredential.selector;
        sels[i++] = RegistryAuthFacet.revokeAuthCredential.selector;
        sels[i++] = RegistryAuthFacet.getAuthAccount.selector;
        sels[i++] = RegistryAuthFacet.getAuthCredentialLink.selector;
        sels[i++] = RegistryAuthFacet.getAuthCredentialCount.selector;
        sels[i++] = RegistryAuthFacet.getAuthCredentialAt.selector;
        sels[i++] = RegistryAuthFacet.getAuthCredentialPage.selector;
    }

    /// @notice Return the selector set for the timelock queue/configuration surface.
    function timelock() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](29);
        uint256 i = 0;
        sels[i++] = RegistryTimelockFacet.setCategoryConfig.selector;
        sels[i++] = RegistryTimelockFacet.setScopeOverride.selector;
        sels[i++] = RegistryTimelockFacet.clearScopeOverride.selector;
        sels[i++] = RegistryTimelockFacet.getCategoryConfig.selector;
        sels[i++] = RegistryTimelockFacet.hasCategoryConfig.selector;
        sels[i++] = RegistryTimelockFacet.getScopeOverride.selector;
        sels[i++] = RegistryTimelockFacet.setTimelockPolicyRunner.selector;
        sels[i++] = RegistryTimelockFacet.getTimelockPolicyRunner.selector;
        sels[i++] = RegistryTimelockFacet.getAction.selector;
        sels[i++] = RegistryTimelockFacet.getActionApprovalState.selector;
        sels[i++] = RegistryTimelockFacet.getActionSummary.selector;
        sels[i++] = RegistryTimelockFacet.getActionBundle.selector;
        sels[i++] = RegistryTimelockFacet.getActionPayloadWord.selector;
        sels[i++] = RegistryTimelockFacet.enableIndexing.selector;
        sels[i++] = RegistryTimelockFacet.indexingEnabled.selector;
        sels[i++] = RegistryTimelockFacet.indexingStartBlock.selector;
        sels[i++] = RegistryTimelockFacet.getPendingActionIds.selector;
        sels[i++] = RegistryTimelockFacet.getPendingActionCount.selector;
        sels[i++] = RegistryTimelockFacet.getPendingActionSummaries.selector;
        sels[i++] = RegistryTimelockFacet.getExecutedActionIds.selector;
        sels[i++] = RegistryTimelockFacet.getExecutedActionCount.selector;
        sels[i++] = RegistryTimelockFacet.getExecutedActionSummaries.selector;
        sels[i++] = RegistryTimelockFacet.approveAction.selector;
        sels[i++] = RegistryTimelockFacet.cancelAction.selector;
        sels[i++] = RegistryTimelockFacet.expireAction.selector;
        sels[i++] = RegistryTimelockFacet.executeAction.selector;
        sels[i++] = RegistryTimelockFacet.executeActions.selector;
        sels[i++] = RegistryTimelockFacet.getActionSemantics.selector;
        sels[i++] = RegistryTimelockFacet.actionSemanticsGeneration.selector;
    }

    /// @notice Return the selector set for timelock-controlled upgrade entrypoints.
    function timelockUpgrade() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](21);
        uint256 i = 0;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeRegistry.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeRegistryExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeInteract.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeInteractExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeMiniScript.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeMiniScriptExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeAuthAccountFactory.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeAuthAccountFactoryExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeAuthAccount.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeAuthAccountExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeSafeFactory.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeSafeFactoryExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeAccountFactory.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeAccountFactoryExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeOkAccount.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeOkAccountExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeOkGuard.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeOkGuardExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.upgradeOkModule.selector;
        sels[i++] = RegistryTimelockUpgradeFacet._upgradeOkModuleExecute.selector;
        sels[i++] = RegistryTimelockUpgradeFacet.getActionUpgradeCodeHash.selector;
    }

    /// @notice Return selectors for timelocked future-deployment release defaults.
    function timelockRelease() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](16);
        uint256 i = 0;
        sels[i++] = RegistryTimelockReleaseFacet.replaceEngine.selector;
        sels[i++] = RegistryTimelockReleaseFacet._replaceEngineExecute.selector;
        sels[i++] = RegistryTimelockReleaseFacet.setAccountImplementation.selector;
        sels[i++] = RegistryTimelockReleaseFacet._setAccountImplementationExecute.selector;
        sels[i++] = RegistryTimelockReleaseFacet.setAuthAccountImplementation.selector;
        sels[i++] = RegistryTimelockReleaseFacet._setAuthAccountImplementationExecute.selector;
        sels[i++] = RegistryTimelockReleaseFacet.setSafeProxyFactory.selector;
        sels[i++] = RegistryTimelockReleaseFacet._setSafeProxyFactoryExecute.selector;
        sels[i++] = RegistryTimelockReleaseFacet.setSafeSingleton.selector;
        sels[i++] = RegistryTimelockReleaseFacet._setSafeSingletonExecute.selector;
        sels[i++] = RegistryTimelockReleaseFacet.replaceSafeSingletonMigrator.selector;
        sels[i++] = RegistryTimelockReleaseFacet._replaceSafeSingletonMigratorExecute.selector;
        sels[i++] = RegistryTimelockReleaseFacet.replaceSafeConfigurator.selector;
        sels[i++] = RegistryTimelockReleaseFacet._replaceSafeConfiguratorExecute.selector;
        sels[i++] = RegistryTimelockReleaseFacet.migrateSafeSingleton.selector;
        sels[i++] = RegistryTimelockReleaseFacet._migrateSafeSingletonExecute.selector;
    }

    /// @notice Return the selector set for `RegistryCapabilitiesFacet`.
    function capabilities() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](11);
        uint256 i = 0;
        sels[i++] = RegistryCapabilitiesFacet.grantCapabilityGroup.selector;
        sels[i++] = RegistryCapabilitiesFacet.revokeCapabilityGroup.selector;
        sels[i++] = RegistryCapabilitiesFacet.grantCapabilityActor.selector;
        sels[i++] = RegistryCapabilitiesFacet.revokeCapabilityActor.selector;
        sels[i++] = RegistryCapabilitiesFacet.getCapabilityGroups.selector;
        sels[i++] = RegistryCapabilitiesFacet.getCapabilityActors.selector;
        sels[i++] = RegistryCapabilitiesFacet.hasCapability.selector;
        sels[i++] = RegistryCapabilitiesFacet.lockCapabilityActors.selector;
        sels[i++] = RegistryCapabilitiesFacet.finalizeOwnerBootstrap.selector;
        sels[i++] = RegistryCapabilitiesFacet.ownershipHandoverCompleted.selector;
        sels[i++] = RegistryCapabilitiesFacet.ownerBootstrapFinalized.selector;
    }

    /// @notice Return the selector set for RegistryTermsFacet.
    function terms() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](7);
        sels[0] = IRegistryTerms.acceptTerms.selector;
        sels[1] = IRegistryTerms.initializeTermsContext.selector;
        sels[2] = IRegistryTerms.getTermsContext.selector;
        sels[3] = IRegistryTerms.getTermsAcceptance.selector;
        sels[4] = IRegistryTerms.hasAcceptedTerms.selector;
        sels[5] = IRegistryTerms.instanceHasAcceptedInitialTerms.selector;
        sels[6] = IRegistryTerms.getTermsDocument.selector;
    }

    /// @notice Return the selector set for `RegistrySyncFacet`.
    function syncFacet() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](5);
        uint256 i = 0;
        sels[i++] = RegistrySyncFacet.setSyncSourceAllowed.selector;
        sels[i++] = RegistrySyncFacet.importContract.selector;
        sels[i++] = RegistrySyncFacet.importContractWithFlags.selector;
        sels[i++] = RegistrySyncFacet.importToken.selector;
        sels[i++] = RegistrySyncFacet.importTokenWithFlags.selector;
    }

    /// @notice Return the selector set for `RegistryInteractionSyncFacet`.
    function interactionSync() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](1);
        sels[0] = RegistryInteractionSyncFacet.importInteractionBundle.selector;
    }

    /// @notice Return the selector set for `RegistrySyncQueryFacet`.
    function syncQueries() internal pure returns (bytes4[] memory sels) {
        sels = new bytes4[](15);
        uint256 i = 0;
        sels[i++] = RegistrySyncQueryFacet.isSyncSourceAllowed.selector;
        sels[i++] = RegistrySyncQueryFacet.getSyncSourceCount.selector;
        sels[i++] = RegistrySyncQueryFacet.getSyncSourceAt.selector;
        sels[i++] = RegistrySyncQueryFacet.getSyncSourcesPage.selector;
        sels[i++] = RegistrySyncQueryFacet.getActiveContractImport.selector;
        sels[i++] = RegistrySyncQueryFacet.getContractImportHistoryCount.selector;
        sels[i++] = RegistrySyncQueryFacet.getContractImportHistoryAt.selector;
        sels[i++] = RegistrySyncQueryFacet.getActiveTokenImport.selector;
        sels[i++] = RegistrySyncQueryFacet.getTokenImportHistoryCount.selector;
        sels[i++] = RegistrySyncQueryFacet.getTokenImportHistoryAt.selector;
        sels[i++] = RegistrySyncQueryFacet.getActiveInteractionImport.selector;
        sels[i++] = RegistrySyncQueryFacet.getInteractionImportHistoryCount.selector;
        sels[i++] = RegistrySyncQueryFacet.getInteractionImportHistoryAt.selector;
        sels[i++] = RegistrySyncQueryFacet.getIndexEpochRollConfig.selector;
        sels[i++] = RegistrySyncQueryFacet.rollIndexEpochs.selector;
    }
}
