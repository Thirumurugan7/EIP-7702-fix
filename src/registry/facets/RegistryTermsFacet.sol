// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "../../Delegation7702.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {ExecutionCatalogStorage} from "../RegistryShared.sol";
import {
    AcceptanceRecord,
    IFactoryTerms,
    IRegistryTerms,
    TermsDocument,
    TermsDocumentLib,
    TermsStorage
} from "../Terms.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";

/// @notice Local initial-document snapshot and explicit, append-only terms acceptance.
contract RegistryTermsFacet is FacetGuard, IRegistryTerms {
    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    error TermsContextUninitialized();
    error TermsContextAlreadyInitialized(address factory);
    error TermsFactoryInvalid(address factory);
    error TermsDocumentMismatch(bytes32 documentHash);

    event TermsContextInitialized(address indexed factory, string ipfsUri, bytes32 documentHash);
    event TermsAccepted(bytes32 indexed documentHash, address indexed acceptedBy, uint64 acceptedAt, string ipfsUri);

    /// @notice Snapshot the owning factory exactly once in the atomic setup window.
    /// @dev Use the direct caller, never a logical actor supplied by a governance replay.
    function initializeTermsContext() external whenNotPausedD nonReentrantD onlyRoleD(ADMIN_ROLE) {
        TermsStorage.Layout storage l = TermsStorage.getLayout();
        if (l.factory != address(0)) revert TermsContextAlreadyInitialized(l.factory);
        if (msg.sender != _ownerD() || !Delegation7702.hasContractCode(msg.sender)) revert TermsFactoryInvalid(msg.sender);
        TermsDocument memory document = IFactoryTerms(msg.sender).getTerms();
        TermsDocumentLib.validate(document.ipfsUri, document.documentHash);
        l.factory = msg.sender;
        l.initialTerms = document;
        ExecutionCatalogStorage.bumpSemantics();
        // Terms writes hold nonReentrantD; factory document reads are STATICCALLs before acceptance is stored and
        // emitted.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TermsContextInitialized(msg.sender, document.ipfsUri, document.documentHash);
    }

    function getTermsContext() external view returns (address factory, TermsDocument memory initialTerms) {
        TermsStorage.Layout storage l = TermsStorage.getLayout();
        return (l.factory, l.initialTerms);
    }

    /// @notice Acceptance remains immediate even when ordinary execution is blocked or timelocked.
    /// @dev Repeated digests preserve the first URI, actor and timestamp without changing execution semantics.
    function acceptTerms(bytes32 documentHash) external whenNotPausedD nonReentrantD onlyRoleD(ADMIN_ROLE) {
        TermsStorage.Layout storage l = TermsStorage.getLayout();
        if (l.factory == address(0)) revert TermsContextUninitialized();
        if (TermsStorage.hasAcceptedTerms(l, documentHash)) return;
        TermsDocument memory document = getTermsDocument(documentHash);
        address actor = _msgSenderD();
        uint64 acceptedAt = SafeCast.toUint64(block.timestamp);
        l.acceptedTerms[documentHash] = AcceptanceRecord(actor, acceptedAt, document.ipfsUri);
        ExecutionCatalogStorage.bumpSemantics();
        // Terms writes hold nonReentrantD; factory document reads are STATICCALLs before acceptance is stored and
        // emitted.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TermsAccepted(documentHash, actor, acceptedAt, document.ipfsUri);
    }

    /// @notice Resolve the original snapshot or an authenticated, published update.
    /// @dev Initial acceptance and execution do not depend on publisher availability.
    function getTermsDocument(bytes32 documentHash) public view returns (TermsDocument memory) {
        TermsStorage.Layout storage l = TermsStorage.getLayout();
        if (l.factory == address(0)) revert TermsContextUninitialized();
        if (documentHash == l.initialTerms.documentHash) return l.initialTerms;
        TermsDocument memory document = IFactoryTerms(l.factory).getTermsDocument(documentHash);
        if (document.documentHash != documentHash) revert TermsDocumentMismatch(documentHash);
        TermsDocumentLib.validate(document.ipfsUri, documentHash);
        return document;
    }

    function getTermsAcceptance(bytes32 documentHash) external view returns (AcceptanceRecord memory) {
        return TermsStorage.getLayout().acceptedTerms[documentHash];
    }

    function hasAcceptedTerms(bytes32 documentHash) external view returns (bool) {
        return TermsStorage.hasAcceptedTerms(TermsStorage.getLayout(), documentHash);
    }

    function instanceHasAcceptedInitialTerms() external view returns (bool) {
        TermsStorage.Layout storage l = TermsStorage.getLayout();
        return l.factory != address(0) && TermsStorage.hasAcceptedTerms(l, l.initialTerms.documentHash);
    }
}
