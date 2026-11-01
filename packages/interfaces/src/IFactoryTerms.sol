// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {TermsDocument} from "./TermsTypes.sol";

interface IFactoryTerms {
    function getTerms() external view returns (TermsDocument memory);
    function getTermsDocument(bytes32 documentHash) external view returns (TermsDocument memory);
}
