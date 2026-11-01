// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {AcceptanceRecord, TermsDocument} from "./TermsTypes.sol";

/// @notice Instance-local initial terms and append-only document acceptance.
interface IRegistryTerms {
    function initializeTermsContext() external;
    function getTermsContext() external view returns (address factory, TermsDocument memory initialTerms);
    function getTermsDocument(bytes32 documentHash) external view returns (TermsDocument memory);
    function acceptTerms(bytes32 documentHash) external;
    function getTermsAcceptance(bytes32 documentHash) external view returns (AcceptanceRecord memory);
    function hasAcceptedTerms(bytes32 documentHash) external view returns (bool);
    function instanceHasAcceptedInitialTerms() external view returns (bool);
}
