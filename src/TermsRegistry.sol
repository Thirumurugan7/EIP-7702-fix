// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
import {TermsDocument, TermsDocumentLib} from "./registry/Terms.sol";
import {IChainwallRegistry} from "@chainwall/interfaces/IChainwallRegistry.sol";

/// @notice Append-only licensing documents. Publication never changes an instance's execution requirement.
contract TermsRegistry {
    address public owner;
    IChainwallRegistry public registry;
    bytes32[] public documentHashes;
    mapping(bytes32 => string) private _uris;

    error Unauthorized(address caller);
    error InvalidOwner();
    error InvalidController();
    error ChainwallAlreadyConfigured();
    error ChainwallPaused();
    error TermsAlreadyPublished(bytes32 documentHash);
    error TermsNotPublished(bytes32 documentHash);

    event TermsPublished(uint256 indexed index, bytes32 indexed documentHash, string ipfsUri);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ChainwallConfigured(address indexed registry, address indexed controller);

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert InvalidOwner();
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
        TermsDocument memory initial = TermsDocumentLib.initial();
        _publish(initial.ipfsUri, initial.documentHash);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        if (address(registry) != address(0)) {
            if (!registry.isAccountAllowed(owner)) revert Unauthorized(msg.sender);
            if (registry.paused()) revert ChainwallPaused();
        }
        _;
    }

    /// @notice Permanently hand publication to one managed Chainwall account.
    /// @dev Configure the account's interactions and policies before handing over. Deployment must authenticate
    ///      the managed account; admission alone does not prove its bindings.
    // The controller must have deployed code and Registry admission below; zero cannot satisfy the code check.
    // forge-lint: disable-next-line(missing-zero-check)
    function transferToChainwall(IChainwallRegistry registry_, address controller) external onlyOwner {
        if (address(registry) != address(0)) revert ChainwallAlreadyConfigured();
        if (
            !Delegation7702.hasContractCode(address(registry_)) || !Delegation7702.hasContractCode(controller)
                || !registry_.isAccountAllowed(controller) || registry_.paused()
        ) revert InvalidController();
        address previousOwner = owner;
        registry = registry_;
        owner = controller;
        emit OwnershipTransferred(previousOwner, controller);
        emit ChainwallConfigured(address(registry_), controller);
    }

    function publishTerms(string calldata ipfsUri, bytes32 documentHash) external onlyOwner {
        TermsDocumentLib.validate(ipfsUri, documentHash);
        _publish(ipfsUri, documentHash);
    }

    function documentCount() external view returns (uint256) {
        return documentHashes.length;
    }

    function getTermsDocument(bytes32 documentHash) external view returns (TermsDocument memory) {
        string memory uri = _uris[documentHash];
        if (bytes(uri).length == 0) revert TermsNotPublished(documentHash);
        return TermsDocument(uri, documentHash);
    }

    function _publish(string memory ipfsUri, bytes32 documentHash) private {
        if (bytes(_uris[documentHash]).length != 0) revert TermsAlreadyPublished(documentHash);
        _uris[documentHash] = ipfsUri;
        uint256 index = documentHashes.length;
        documentHashes.push(documentHash);
        emit TermsPublished(index, documentHash, ipfsUri);
    }
}
