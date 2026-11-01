// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IAccount, PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ChainwallUpgradeHash} from "./ChainwallUpgradeable.sol";
import {StoredBundleRevealPayload} from "./RegistryTypes.sol";
import {WebAuthnAuthAccountProxyStorage} from "./WebAuthnAuthAccountProxy.sol";
import {WebAuthnEntryPoint} from "./WebAuthnEntryPoint.sol";

interface IWebAuthnAuthAccountRegistry {
    function isAccountAllowed(address account) external view returns (bool);
    function isAuthAccountFactoryAllowed(address factory) external view returns (bool);
    function getExecutionRuntimeVersion() external view returns (uint64);
}

interface IWebAuthnAuthAccountInteract {
    function propose(bytes32 payloadHash, bytes32 policyId, uint256 deadline, uint256 nativeValue, address safe)
        external
        returns (uint256 operationId);

    function proposeWithExecutor(
        bytes32 payloadHash,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe,
        address executor
    ) external returns (uint256 operationId);

    function approveOperation(uint256 operationId) external returns (bool);
    function withdrawOperation(uint256 operationId) external;
    function getOperationSafe(uint256 operationId) external view returns (address);
    function getOperationPolicyId(uint256 operationId) external view returns (bytes32);

    function executeFromAccount(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        returns (uint256 stackTop);

    function executePrivateFromAccount(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        StoredBundleRevealPayload calldata reveal
    ) external returns (uint256 stackTop);

    function approveAndExecuteFromAccount(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        returns (uint256 stackTop);

    function approveAndExecutePrivateFromAccount(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        StoredBundleRevealPayload calldata reveal
    ) external returns (uint256 stackTop);

    function directExecuteFromAccount(
        address account,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature
    ) external returns (uint256 stackTop);

    function directExecutePrivateFromAccount(
        address account,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature,
        StoredBundleRevealPayload calldata reveal
    ) external returns (uint256 stackTop);
}

interface IWebAuthnAuthAccountFactoryProtocol {
    function REGISTRY() external view returns (address);
    function INTERACT() external view returns (address);
    function ENTRY_POINT() external view returns (address);
    function SAFE_FACTORY() external view returns (address);
    function isAuthAccount(address account) external view returns (bool);
}

interface IWebAuthnAuthAccountSafeFactory {
    function INTERACT_CONTRACT() external view returns (address);
    function MODULE_CONTRACT() external view returns (address);
}

interface IWebAuthnAuthAccountSafeModule {
    function INTERACTION() external view returns (address);
}

/// @title WebAuthnAuthAccount
/// @notice Protocol-user account that verifies P-256 WebAuthn assertions and forwards narrow protocol calls.
/// @dev This is not an asset vault. It rejects native value and only forwards tenant registry calls or selected
///      Interact calls. Account-vault direct execution is additionally scoped by account, policy, and interaction.
contract WebAuthnAuthAccount is Initializable, ReentrancyGuardUpgradeable, IERC1271, IAccount {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    bytes32 private constant _CHAINWALL_COMPONENT_ID = keccak256("Chainwall.WebAuthnAuthAccount");
    uint256 private constant _CHAINWALL_UPGRADE_PROTOCOL_VERSION = 1;

    struct Credential {
        bytes32 qx;
        bytes32 qy;
        uint32 signCount;
        bool active;
        bool exists;
    }

    struct CredentialView {
        bytes32 credHash;
        bytes32 qx;
        bytes32 qy;
        uint32 signCount;
        bool active;
        bool exists;
    }

    struct WebAuthnAssertion {
        bytes32 credHash;
        bytes authenticatorData;
        bytes clientDataJson;
        uint256 typeIndex;
        uint256 challengeIndex;
        uint256 originIndex;
        bytes32 r;
        bytes32 s;
    }

    struct ClientDataParserState {
        uint256 requiredFields;
        uint256 depth;
        uint256 arrayDepths;
        bool inString;
        bool escaped;
        bool rootSeen;
        bool rootClosed;
        bool expectingRootKey;
        bool afterRootComma;
    }

    struct DirectExecuteScope {
        address account;
        bytes32 policyId;
        bytes32 interactionId;
        bool active;
    }

    address public entryPoint;
    bytes32 public rpIdHash;
    uint256 public nextNonce;

    string private _origin;
    mapping(bytes32 => Credential) private _credentials;
    EnumerableSet.Bytes32Set private _credentialIds;
    mapping(bytes32 => bool) private _directExecuteScopes;

    bytes32 private constant PROTOCOL_CALL_TYPEHASH = keccak256(
        "AuthAccountProtocolCall(uint256 chainId,address account,bytes32 authorizationRevision,uint64 executionRuntime,address target,bytes32 dataHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant USER_OPERATION_TYPEHASH = keccak256(
        "AuthAccountUserOperation(uint256 chainId,address account,bytes32 authorizationRevision,address entryPoint,address factory,bytes32 userOpHash,uint256 deadline)"
    );
    bytes32 private constant ADD_CREDENTIAL_TYPEHASH = keccak256(
        "AuthAccountAddCredential(uint256 chainId,address account,bytes32 authorizationRevision,bytes32 credHash,bytes32 qx,bytes32 qy,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant NEW_CREDENTIAL_PROOF_TYPEHASH = keccak256(
        "AuthAccountNewCredentialProof(uint256 chainId,address account,bytes32 authorizationRevision,bytes32 credHash,bytes32 qx,bytes32 qy)"
    );
    bytes32 private constant REVOKE_CREDENTIAL_TYPEHASH = keccak256(
        "AuthAccountRevokeCredential(uint256 chainId,address account,bytes32 authorizationRevision,bytes32 credHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant SET_SCOPE_TYPEHASH = keccak256(
        "AuthAccountSetDirectExecuteScope(uint256 chainId,address account,bytes32 authorizationRevision,uint64 executionRuntime,address vault,bytes32 policyId,bytes32 interactionId,bool active,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant ERC1271_TYPEHASH = keccak256(
        "AuthAccountERC1271(uint256 chainId,address account,bytes32 authorizationRevision,uint64 executionRuntime,bytes32 hash)"
    );
    /// @dev Exact signature bytes used only by the transient UserOperation actor bridge.
    bytes32 private constant _USER_OP_ACTOR_MARKER = keccak256("ChainwallUserOpActorAuthorizationV1");

    bytes4 private constant _ERC1271_INVALID = 0xffffffff;
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _NEW_AUTH_ACCOUNT_SELECTOR = bytes4(
        keccak256("newAuthAccount(bytes32,bytes32,bytes32,bytes32,address,bytes32,(address,bytes32,bytes32,bool)[])")
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _CREATE_AUTH_ACCOUNT_SELECTOR =
        bytes4(keccak256("createAuthAccount(bytes32,bytes32,bytes32,bytes32,address,bytes32)"));
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _MODULE_EXECUTE_SELECTOR =
        bytes4(keccak256("executeInteraction(address,uint256,bytes32,uint256[],uint256,uint256)"));
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _MODULE_EXECUTE_PRIVATE_SELECTOR = bytes4(
        keccak256(
            "executeInteractionPrivate(address,uint256,bytes32,uint256[],uint256,uint256,((bytes32,bytes,uint256,(bytes32,bytes)[]),bytes32[],bytes32,bytes))"
        )
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _MODULE_APPROVE_EXECUTE_SELECTOR =
        bytes4(keccak256("approveAndExecuteInteraction(address,uint256,bytes32,uint256[],uint256,uint256)"));
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _MODULE_APPROVE_EXECUTE_PRIVATE_SELECTOR = bytes4(
        keccak256(
            "approveAndExecuteInteractionPrivate(address,uint256,bytes32,uint256[],uint256,uint256,((bytes32,bytes,uint256,(bytes32,bytes)[]),bytes32[],bytes32,bytes))"
        )
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _MODULE_DIRECT_SELECTOR = bytes4(
        keccak256("directExecuteInteraction(address,bytes32,bytes32,uint256[],uint256,address,bytes,uint256,uint256)")
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _MODULE_DIRECT_PRIVATE_SELECTOR = bytes4(
        keccak256(
            "directExecuteInteractionPrivate(address,bytes32,bytes32,uint256[],uint256,address,bytes,uint256,uint256,((bytes32,bytes,uint256,(bytes32,bytes)[]),bytes32[],bytes32,bytes))"
        )
    );
    // forge-lint: disable-end(unsafe-typecast)
    bytes32 private constant _SIGNED_ACTOR_TRAILER_MAGIC = keccak256("ChainwallSignedActorTrailerV2");
    bytes32 private constant _USER_OP_ACTOR_DIGEST_SLOT =
        keccak256("chainwall.webauthn-auth-account.user-op-actor-digest.v1");
    uint256 private constant _USER_OP_ACTOR_TRAILER_LENGTH = 88;
    uint8 private constant _AUTH_DATA_FLAG_UP = 0x01;
    uint8 private constant _AUTH_DATA_FLAG_UV = 0x04;
    uint8 private constant _AUTH_DATA_FLAG_BE = 0x08;
    uint8 private constant _AUTH_DATA_FLAG_BS = 0x10;
    uint256 private constant MAX_AUTH_DEADLINE_WINDOW = 1 days;

    event CredentialAdded(bytes32 indexed credHash);
    event CredentialRevoked(bytes32 indexed credHash);
    event DirectExecuteScopeSet(
        address indexed account, bytes32 indexed policyId, bytes32 indexed interactionId, bool active
    );
    event ProtocolCallExecuted(
        address indexed relayer,
        address indexed target,
        bytes4 indexed selector,
        uint256 nonce,
        bytes32 dataHash,
        bytes32 resultHash
    );

    error RegistryZero();
    error InteractZero();
    error RegistryInteractSame();
    error RegistryNotContract(address registry);
    error InteractNotContract(address interact);
    error EntryPointZero();
    error RpIdHashZero();
    error OriginEmpty();
    error UserVerificationRequired();
    error CredentialHashZero();
    error CredentialMissing(bytes32 credHash);
    error CredentialExists(bytes32 credHash);
    error CredentialInactive(bytes32 credHash);
    error CredentialLastActive();
    error InvalidPublicKey(bytes32 qx, bytes32 qy);
    error InvalidWebAuthnAssertion();
    error NativeValueNotAccepted();
    error NonceMismatch(uint256 expected, uint256 provided);
    error DeadlineRequired();
    error DeadlineExpired();
    error DeadlineTooFar(uint256 maxDeadline);
    error ProtocolTargetNotAllowed(address target);
    error ProtocolSelectorNotAllowed(bytes4 selector);
    error ProtocolActorMismatch(address actor);
    error ProtocolExecutorMismatch(address executor);
    error ProtocolActorSignatureNotEmpty();
    error ProtocolAccountZero();
    error ProtocolAccountSelf();
    error ProtocolAccountNotAllowed(address account);
    error ProtocolCallScopeDenied(address account, bytes32 policyId, bytes32 interactionId);
    error ProtocolCallFailed(bytes returnData);
    error ProtocolFactoryInvalid(address factory);
    error EntryPointUnauthorized(address caller);
    error UserOperationSenderMismatch(address expected, address actual);
    error UserOperationFactoryMismatch(address expected, address actual);
    error UserOperationFactorySelectorNotAllowed(bytes4 selector);
    error UserOperationDeadlineTooLarge(uint256 deadline);
    error UserOperationCallSelectorNotAllowed(bytes4 selector);
    error UserOperationCredentialMismatch(bytes32 expected, bytes32 provided);
    error UserOperationInteractDigestZero();
    error UserOperationExpectedModuleZero();
    error UserOperationModuleMismatch(address expected, address actual);
    error UserOperationModuleInvalid(address module);
    error UserOperationModuleCallInvalid(bytes4 selector);
    error UserOperationActorContextActive();
    error UserOperationSignatureMalformed();
    error UserOperationPaymasterMissing();
    error UserOperationMissingAccountFunds(uint256 missingAccountFunds);
    error UserOperationAuthorizationRevisionMismatch();
    error ExecutionRuntimeMismatch();

    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize a deterministic account proxy with the first WebAuthn credential.
    /// @dev The supported deployment paths are `WebAuthnAuthAccountFactory.newAuthAccount` and its EntryPoint
    ///      SenderCreator counterpart. Both deploy and initialize the stable proxy in one transaction. Any
    ///      independently deployed, uninitialized proxy must be treated as claimable by the first caller.
    function initialize(
        address registry_,
        address interact_,
        address entryPoint_,
        bytes32 rpIdHash_,
        string calldata origin_,
        bool requireUserVerification_,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        DirectExecuteScope[] calldata initialScopes
    ) external initializer {
        if (registry_ == address(0)) revert RegistryZero();
        if (interact_ == address(0)) revert InteractZero();
        if (entryPoint_ == address(0)) revert EntryPointZero();
        WebAuthnEntryPoint.requireAddress(entryPoint_);
        if (registry_ == interact_) revert RegistryInteractSame();
        if (registry_.code.length == 0) revert RegistryNotContract(registry_);
        if (interact_.code.length == 0) revert InteractNotContract(interact_);
        if (rpIdHash_ == bytes32(0)) revert RpIdHashZero();
        if (bytes(origin_).length == 0) revert OriginEmpty();
        if (!requireUserVerification_) revert UserVerificationRequired();
        // Leave OpenZeppelin's guard status at zero during deployment. Its
        // modifier rejects only ENTERED (2), then writes ENTERED and finally
        // NOT_ENTERED (1), so zero is an unlocked initial state. Deferring this
        // normalization keeps counterfactual deployment inside ERC-7562's
        // 500k verification-gas ceiling without weakening reentrancy checks.
        address proxyFactory = WebAuthnAuthAccountProxyStorage.factory();
        if (proxyFactory == address(0) || msg.sender != proxyFactory) {
            revert ProtocolFactoryInvalid(msg.sender);
        }
        entryPoint = entryPoint_;
        rpIdHash = rpIdHash_;
        _origin = origin_;
        _addCredential(initialCredHash, initialQx, initialQy, 0);
        for (uint256 i; i < initialScopes.length; i++) {
            _setDirectExecuteScope(
                initialScopes[i].account,
                initialScopes[i].policyId,
                initialScopes[i].interactionId,
                initialScopes[i].active
            );
        }
    }

    receive() external payable {
        revert NativeValueNotAccepted();
    }

    function origin() external view returns (string memory) {
        return _origin;
    }

    function registry() public view returns (address) {
        return IWebAuthnAuthAccountFactoryProtocol(factory()).REGISTRY();
    }

    function interact() public view returns (address) {
        return IWebAuthnAuthAccountFactoryProtocol(factory()).INTERACT();
    }

    function factory() public view returns (address) {
        return WebAuthnAuthAccountProxyStorage.factory();
    }

    /// @notice Current tenant execution-semantics revision bound into protocol authorization.
    function executionRuntimeVersion() public view returns (uint64) {
        return IWebAuthnAuthAccountRegistry(registry()).getExecutionRuntimeVersion();
    }

    function chainwallComponentId() external pure returns (bytes32) {
        return _CHAINWALL_COMPONENT_ID;
    }

    function chainwallUpgradeProtocolVersion() external pure returns (uint256) {
        return _CHAINWALL_UPGRADE_PROTOCOL_VERSION;
    }

    /// @notice Expose the protocol-v1 account trust-root schema for implementation compatibility checks.
    /// @dev Dispatcher-backed accounts answer this selector in the stable dispatcher itself. This implementation
    ///      view remains available so a candidate can prove that it understands the required upgrade protocol.
    function chainwallSecurityBindingsHash() external view returns (bytes32) {
        return ChainwallUpgradeHash.hash(
            abi.encode(WebAuthnAuthAccountProxyStorage.factory(), entryPoint, rpIdHash, keccak256(bytes(_origin)))
        );
    }

    function activeCredentialCount() public view returns (uint256) {
        return _credentialIds.length();
    }

    function getCredentialKeyAt(uint256 index) external view returns (bytes32) {
        return _credentialIds.at(index);
    }

    function getCredentialKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        uint256 credentialLength = _credentialIds.length();
        if (start >= credentialLength || count == 0) return new bytes32[](0);
        uint256 resultLength = credentialLength - start;
        if (count < resultLength) resultLength = count;

        bytes32[] memory result = new bytes32[](resultLength);
        for (uint256 i = 0; i < resultLength;) {
            result[i] = _credentialIds.at(start + i);
            unchecked {
                ++i;
            }
        }
        return result;
    }

    function getCredential(bytes32 credHash) external view returns (CredentialView memory view_) {
        Credential storage credential = _credentials[credHash];
        view_ = CredentialView({
            credHash: credHash,
            qx: credential.qx,
            qy: credential.qy,
            signCount: credential.signCount,
            active: credential.active,
            exists: credential.exists
        });
    }

    function isDirectExecuteScopeAllowed(address account, bytes32 policyId, bytes32 interactionId)
        external
        view
        returns (bool)
    {
        return _directExecuteScopes[_scopeKey(account, policyId, interactionId)];
    }

    function protocolCallChallenge(address target, bytes32 dataHash, uint256 nonce, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _hashEncoded(
            abi.encode(
                PROTOCOL_CALL_TYPEHASH,
                block.chainid,
                address(this),
                _authorizationRevision(),
                executionRuntimeVersion(),
                target,
                dataHash,
                nonce,
                deadline
            )
        );
    }

    function userOperationChallenge(bytes32 userOpHash, uint256 deadline) public view returns (bytes32) {
        return _hashEncoded(
            abi.encode(
                USER_OPERATION_TYPEHASH,
                block.chainid,
                address(this),
                _authorizationRevision(),
                entryPoint,
                factory(),
                userOpHash,
                deadline
            )
        );
    }

    function addCredentialChallenge(bytes32 credHash, bytes32 qx, bytes32 qy, uint256 nonce, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _hashEncoded(
            abi.encode(
                ADD_CREDENTIAL_TYPEHASH,
                block.chainid,
                address(this),
                _authorizationRevision(),
                credHash,
                qx,
                qy,
                nonce,
                deadline
            )
        );
    }

    /// @notice Challenge proving possession of a credential added by a signed UserOperation.
    /// @dev Replay of this proof cannot authorize the addition: the active credential's
    ///      chain-bound UserOperation signature separately binds the exact account call.
    function newCredentialProofChallenge(bytes32 credHash, bytes32 qx, bytes32 qy) public view returns (bytes32) {
        return _hashEncoded(
            abi.encode(
                NEW_CREDENTIAL_PROOF_TYPEHASH, block.chainid, address(this), _authorizationRevision(), credHash, qx, qy
            )
        );
    }

    function revokeCredentialChallenge(bytes32 credHash, uint256 nonce, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _hashEncoded(
            abi.encode(
                REVOKE_CREDENTIAL_TYPEHASH,
                block.chainid,
                address(this),
                _authorizationRevision(),
                credHash,
                nonce,
                deadline
            )
        );
    }

    function setDirectExecuteScopeChallenge(
        address account,
        bytes32 policyId,
        bytes32 interactionId,
        bool active,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        return _hashEncoded(
            abi.encode(
                SET_SCOPE_TYPEHASH,
                block.chainid,
                address(this),
                _authorizationRevision(),
                executionRuntimeVersion(),
                account,
                policyId,
                interactionId,
                active,
                nonce,
                deadline
            )
        );
    }

    function erc1271Challenge(bytes32 hash) public view returns (bytes32) {
        return _hashEncoded(
            abi.encode(
                ERC1271_TYPEHASH,
                block.chainid,
                address(this),
                _authorizationRevision(),
                executionRuntimeVersion(),
                hash
            )
        );
    }

    /// @notice ERC-1271 validation for WebAuthn assertions over the AuthAccount ERC-1271 challenge for `hash`.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue) {
        if (_isUserOpActorMarker(signature)) {
            bytes32 activeDigest = _activeUserOpActorDigest();
            return msg.sender == interact() && hash != bytes32(0) && hash == activeDigest
                ? IERC1271.isValidSignature.selector
                : _ERC1271_INVALID;
        }
        try this.isValidWebAuthnSignature(hash, signature) returns (bool ok) {
            return ok ? IERC1271.isValidSignature.selector : _ERC1271_INVALID;
        } catch {
            return _ERC1271_INVALID;
        }
    }

    /// @notice Public non-mutating verifier for WebAuthn assertions over the AuthAccount ERC-1271 challenge.
    function isValidWebAuthnSignature(bytes32 hash, bytes calldata signature) external view returns (bool) {
        return _validateWebAuthnSignature(erc1271Challenge(hash), signature).ok;
    }

    /// @dev External only so callers inside this contract can catch malformed ABI.
    ///      `withDeadline` selects the direct-signature or UserOperation envelope.
    function decodeWebAuthnEnvelope(bytes calldata signature, bool withDeadline)
        external
        pure
        returns (uint256 deadline, WebAuthnAssertion memory assertion)
    {
        if (withDeadline) return abi.decode(signature, (uint256, WebAuthnAssertion));
        assertion = abi.decode(signature, (WebAuthnAssertion));
    }

    /// @notice Add a new WebAuthn credential after authorization by an active credential.
    function addCredential(
        bytes32 credHash,
        bytes32 qx,
        bytes32 qy,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature,
        bytes calldata newCredentialSignature
    ) external nonReentrant {
        if (_credentials[credHash].exists) revert CredentialExists(credHash);
        if (!P256.isValidPublicKey(qx, qy)) revert InvalidPublicKey(qx, qy);
        bytes32 challenge = addCredentialChallenge(credHash, qx, qy, nonce, deadline);
        ValidationResult memory newCredentialProof =
            _validateWebAuthnSignatureForPublicKey(challenge, newCredentialSignature, credHash, qx, qy);
        if (!newCredentialProof.ok) revert InvalidWebAuthnAssertion();
        _consumeAuthorizedNonce(challenge, nonce, deadline, signature);
        _addCredential(credHash, qx, qy, newCredentialProof.signCount);
    }

    /// @notice Revoke an active credential after authorization by another active credential.
    function revokeCredential(bytes32 credHash, uint256 nonce, uint256 deadline, bytes calldata signature)
        external
        nonReentrant
    {
        _requireCredentialRevocable(credHash);
        _consumeAuthorizedNonce(revokeCredentialChallenge(credHash, nonce, deadline), nonce, deadline, signature);
        _revokeCredential(credHash);
    }

    /// @notice Configure an exact account-mode direct-execute scope.
    function setDirectExecuteScope(
        address account,
        bytes32 policyId,
        bytes32 interactionId,
        bool active,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        bytes32 challenge = setDirectExecuteScopeChallenge(account, policyId, interactionId, active, nonce, deadline);
        _consumeAuthorizedNonce(challenge, nonce, deadline, signature);
        _setDirectExecuteScope(account, policyId, interactionId, active);
    }

    /// @notice Add a credential through a paymaster-backed UserOperation.
    /// @dev `authorizingCredHash` is signed as part of UserOperation calldata and is
    ///      rechecked at execution time. This prevents an earlier operation in the same
    ///      EntryPoint batch from revoking the credential after validation but before use.
    ///      `newCredentialSignature` independently proves possession of the new key.
    function addCredentialFromUserOp(
        bytes32 authorizingCredHash,
        bytes32 expectedAuthorizationRevision,
        bytes32 credHash,
        bytes32 qx,
        bytes32 qy,
        bytes calldata newCredentialSignature
    ) external nonReentrant {
        _requireEntryPointCaller();
        _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
        _requireActiveCredential(authorizingCredHash);
        if (_credentials[credHash].exists) revert CredentialExists(credHash);
        if (!P256.isValidPublicKey(qx, qy)) revert InvalidPublicKey(qx, qy);
        ValidationResult memory newCredentialProof = _validateWebAuthnSignatureForPublicKey(
            newCredentialProofChallenge(credHash, qx, qy), newCredentialSignature, credHash, qx, qy
        );
        if (!newCredentialProof.ok) revert InvalidWebAuthnAssertion();
        _addCredential(credHash, qx, qy, newCredentialProof.signCount);
    }

    /// @notice Revoke a credential through a paymaster-backed UserOperation.
    function revokeCredentialFromUserOp(
        bytes32 authorizingCredHash,
        bytes32 expectedAuthorizationRevision,
        bytes32 credHash
    ) external nonReentrant {
        _requireEntryPointCaller();
        _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
        _requireActiveCredential(authorizingCredHash);
        _revokeCredential(credHash);
    }

    /// @notice Configure an account execution scope through a paymaster-backed UserOperation.
    function setDirectExecuteScopeFromUserOp(
        bytes32 authorizingCredHash,
        bytes32 expectedAuthorizationRevision,
        uint64 expectedExecutionRuntime,
        address account,
        bytes32 policyId,
        bytes32 interactionId,
        bool active
    ) external nonReentrant {
        _requireEntryPointCaller();
        _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
        _requireActiveCredential(authorizingCredHash);
        _requireExecutionRuntime(expectedExecutionRuntime);
        _setDirectExecuteScope(account, policyId, interactionId, active);
    }

    /// @notice Relay a WebAuthn-authorized protocol call through this account.
    /// @dev Registry calls are forwarded without selector filtering because the tenant registry remains the
    ///      authorization boundary: facets see this account as `msg.sender` and enforce their normal role,
    ///      capability, ownership, pause, and timelock checks. `Interact` calls stay selector/argument-gated
    ///      because they can reach account-vault execution outside the registry write surface.
    function executeProtocolCall(
        // _validateProtocolCall admits only the initialized nonzero Registry, Interact, or factory bindings.
        // forge-lint: disable-next-line(missing-zero-check)
        address target,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external payable nonReentrant returns (bytes memory result) {
        if (msg.value != 0) revert NativeValueNotAccepted();
        bytes32 dataHash = _hashCalldataBytes(data);
        bytes32 challenge = protocolCallChallenge(target, dataHash, nonce, deadline);
        bytes4 selector = _validateProtocolCall(target, data);
        _consumeAuthorizedNonce(challenge, nonce, deadline, signature);

        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) revert ProtocolCallFailed(ret);
        result = ret;
        // Credential helpers make only local/precompile changes; protocol execution holds nonReentrant through its
        // completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ProtocolCallExecuted(msg.sender, target, selector, nonce, dataHash, _hashEncoded(result));
    }

    /// @notice Execute a validated ERC-4337 protocol call through the trusted EntryPoint.
    /// @dev The live credential check is deliberately repeated after validateUserOp.
    ///      EntryPoint validates all operations in a bundle before executing them.
    function executeUserOpProtocolCall(
        bytes32 authorizingCredHash,
        bytes32 expectedAuthorizationRevision,
        uint64 expectedExecutionRuntime,
        // _validateProtocolCall admits only the initialized nonzero Registry, Interact, or factory bindings.
        // forge-lint: disable-next-line(missing-zero-check)
        address target,
        bytes calldata data
    ) external payable nonReentrant returns (bytes memory result) {
        _requireEntryPointCaller();
        _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
        _requireActiveCredential(authorizingCredHash);
        _requireExecutionRuntime(expectedExecutionRuntime);
        if (msg.value != 0) revert NativeValueNotAccepted();
        bytes4 selector = _validateProtocolCall(target, data);

        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) revert ProtocolCallFailed(ret);
        result = ret;
        // Credential helpers make only local/precompile changes; protocol execution holds nonReentrant through its
        // completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ProtocolCallExecuted(msg.sender, target, selector, 0, _hashCalldataBytes(data), _hashEncoded(result));
    }

    /// @notice Execute one exact Safe/OKModule action under the current sponsored UserOperation.
    /// @dev The passkey-signed UserOperation commits `expectedModule`, `expectedInteractDigest`, and the complete
    ///      module calldata. During this one non-reentrant frame, Interact may validate only that exact digest by
    ///      calling this account through ERC-1271 with the fixed UserOperation actor marker. The authorization is
    ///      explicitly cleared on success and is rolled back automatically on revert.
    function executeUserOpSafeModuleCall(
        bytes32 authorizingCredHash,
        bytes32 expectedAuthorizationRevision,
        uint64 expectedExecutionRuntime,
        address expectedModule,
        bytes32 expectedInteractDigest,
        bytes calldata moduleCall
    ) external payable nonReentrant {
        _requireEntryPointCaller();
        _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
        _requireActiveCredential(authorizingCredHash);
        _requireExecutionRuntime(expectedExecutionRuntime);
        if (msg.value != 0) revert NativeValueNotAccepted();
        if (expectedInteractDigest == bytes32(0)) revert UserOperationInteractDigestZero();

        bytes memory callData = moduleCall;
        _validateSafeModuleCall(callData);
        address module = _resolveSafeModule();
        if (module != expectedModule) revert UserOperationModuleMismatch(expectedModule, module);
        if (_activeUserOpActorDigest() != bytes32(0)) revert UserOperationActorContextActive();

        _setActiveUserOpActorDigest(expectedInteractDigest);
        (bool ok, bytes memory ret) = module.call(callData);
        // ERC-4337 explicitly warns that transient access-control state must be
        // cleared because multiple UserOperations execute in one transaction.
        _setActiveUserOpActorDigest(bytes32(0));
        if (!ok) revert ProtocolCallFailed(ret);
    }

    /// @inheritdoc IAccount
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        // ERC-7562 validation may inspect only the account's own state and
        // explicitly allowed precompiles. Canonical runtime verification and
        // tenant-contract reads are repeated in the execution methods instead.
        _requireEntryPointAddress();
        if (userOp.sender != address(this)) revert UserOperationSenderMismatch(address(this), userOp.sender);
        _validateUserOperationFactory(userOp);
        if (missingAccountFunds != 0) revert UserOperationMissingAccountFunds(missingAccountFunds);
        _requireUserOperationPaymaster(userOp);

        (uint256 deadline, WebAuthnAssertion memory assertion) = _decodeUserOperationSignature(userOp.signature);
        uint48 validUntil = _validateUserOperationDeadline(deadline);
        _validateUserOperationCall(userOp.callData, assertion.credHash);

        Credential storage credential = _credentials[assertion.credHash];
        if (!credential.exists || !credential.active) {
            return ERC4337Utils.packValidationData(false, 0, validUntil);
        }

        ValidationResult memory result = _validateDecodedWebAuthnSignature(
            userOperationChallenge(userOpHash, deadline),
            assertion,
            credential.signCount,
            credential.qx,
            credential.qy,
            true
        );
        if (!result.ok) {
            return ERC4337Utils.packValidationData(false, 0, validUntil);
        }
        if (result.signCount != 0) {
            credential.signCount = result.signCount;
        }
        return ERC4337Utils.packValidationData(true, 0, validUntil);
    }

    function _consumeAuthorizedNonce(bytes32 challenge, uint256 nonce, uint256 deadline, bytes calldata signature)
        private
    {
        _validateDeadline(deadline);
        uint256 expected = nextNonce;
        if (nonce != expected) revert NonceMismatch(expected, nonce);
        ValidationResult memory result = _validateWebAuthnSignature(challenge, signature);
        if (!result.ok) revert InvalidWebAuthnAssertion();
        if (result.signCount != 0) {
            _credentials[result.credHash].signCount = result.signCount;
        }
        unchecked {
            nextNonce = expected + 1;
        }
    }

    function _validateDeadline(uint256 deadline) private view {
        if (deadline == 0) revert DeadlineRequired();
        // The signed validity window uses chain time; credential and nonce checks still authorize the call.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > deadline) revert DeadlineExpired();
        uint256 maxDeadline = block.timestamp + MAX_AUTH_DEADLINE_WINDOW;
        // This caps the signed validity window; nonce and credential proof independently authorize the call.
        // forge-lint: disable-next-line(block-timestamp)
        if (deadline > maxDeadline) revert DeadlineTooFar(maxDeadline);
    }

    /// @dev EntryPoint enforces `validUntil`. Reading block.timestamp here would
    ///      make account validation non-compliant with ERC-7562 and canonical
    ///      bundlers. The SDK and paymaster may impose a shorter issuance window.
    function _validateUserOperationDeadline(uint256 deadline) private pure returns (uint48 validUntil) {
        if (deadline == 0) revert DeadlineRequired();
        if (deadline > type(uint48).max) revert UserOperationDeadlineTooLarge(deadline);
        assembly ("memory-safe") {
            validUntil := deadline
        }
    }

    function _addCredential(bytes32 credHash, bytes32 qx, bytes32 qy, uint32 signCount) private {
        if (credHash == bytes32(0)) revert CredentialHashZero();
        if (!P256.isValidPublicKey(qx, qy)) revert InvalidPublicKey(qx, qy);
        _credentials[credHash] = Credential({qx: qx, qy: qy, signCount: signCount, active: true, exists: true});
        if (!_credentialIds.add(credHash)) revert CredentialExists(credHash);
        // Credential helpers make only local/precompile changes; protocol execution holds nonReentrant through its
        // completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit CredentialAdded(credHash);
    }

    function _requireCredentialRevocable(bytes32 credHash) private view {
        Credential storage credential = _credentials[credHash];
        if (!credential.exists) revert CredentialMissing(credHash);
        if (!credential.active) revert CredentialInactive(credHash);
        if (_credentialIds.length() <= 1) revert CredentialLastActive();
    }

    function _requireActiveCredential(bytes32 credHash) private view {
        Credential storage credential = _credentials[credHash];
        if (!credential.exists) revert CredentialMissing(credHash);
        if (!credential.active) revert CredentialInactive(credHash);
    }

    function _revokeCredential(bytes32 credHash) private {
        _requireCredentialRevocable(credHash);
        _credentials[credHash].active = false;
        _credentialIds.remove(credHash);
        // Credential helpers make only local/precompile changes; protocol execution holds nonReentrant through its
        // completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit CredentialRevoked(credHash);
    }

    function _setDirectExecuteScope(address account, bytes32 policyId, bytes32 interactionId, bool active) private {
        _requireDirectExecuteScopeAccount(account);
        _directExecuteScopes[_scopeKey(account, policyId, interactionId)] = active;
        // Credential helpers make only local/precompile changes; protocol execution holds nonReentrant through its
        // completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit DirectExecuteScopeSet(account, policyId, interactionId, active);
    }

    function _requireDirectExecuteScopeAccount(address account) private view {
        // Every direct-execution scope must name a nonzero account other than this authenticator.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (account == address(0)) revert ProtocolAccountZero();
        // Every direct-execution scope must name a nonzero account other than this authenticator.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (account == address(this)) revert ProtocolAccountSelf();
    }

    function _requireEntryPointCaller() private view {
        _requireEntryPointAddress();
        WebAuthnEntryPoint.requireCanonical(entryPoint);
    }

    function _requireEntryPointAddress() private view {
        if (msg.sender != entryPoint) revert EntryPointUnauthorized(msg.sender);
    }

    function _validateProtocolCall(address target, bytes memory data) private view returns (bytes4 selector) {
        return _validateProtocolCall(target, data, true);
    }

    /// @dev During ERC-4337 validation, `validateLiveState` is false so this
    ///      parser limits the signed call using account-owned configuration only.
    ///      Execution repeats this function with live tenant and factory checks.
    function _validateProtocolCall(address target, bytes memory data, bool validateLiveState)
        private
        view
        returns (bytes4 selector)
    {
        address factory_ = factory();
        if (data.length < 4) revert ProtocolSelectorNotAllowed(bytes4(0));
        assembly ("memory-safe") {
            selector := mload(add(data, 0x20))
        }
        if (!validateLiveState) {
            // ERC-7562 account validation cannot read the factory's tenant
            // configuration. The signed UserOperation still binds target and
            // calldata exactly; execution resolves the current Registry and
            // Interact bindings and applies every selector and scope check.
            if (target == factory_ && selector != _NEW_AUTH_ACCOUNT_SELECTOR) {
                revert ProtocolSelectorNotAllowed(selector);
            }
            return selector;
        }

        address registry_ = registry();
        address interact_ = interact();
        if (target == registry_) {
            return selector;
        }
        if (target == factory_) {
            if (selector != _NEW_AUTH_ACCOUNT_SELECTOR) revert ProtocolSelectorNotAllowed(selector);
            _validateStoredFactory();
            return selector;
        }
        if (target != interact_) revert ProtocolTargetNotAllowed(target);
        if (selector == IWebAuthnAuthAccountInteract.propose.selector) {
            // Proposal creation is intentionally delegated to Interact's policy, deadline, and target checks.
            _requireProtocolHead(data, 5, selector);
            return selector;
        }
        if (selector == IWebAuthnAuthAccountInteract.proposeWithExecutor.selector) {
            _requireProtocolHead(data, 6, selector);
            address executor = _protocolAddress(data, 5, selector);
            if (executor != address(this)) revert ProtocolExecutorMismatch(executor);
            return selector;
        }
        if (
            selector == IWebAuthnAuthAccountInteract.approveOperation.selector
                || selector == IWebAuthnAuthAccountInteract.withdrawOperation.selector
        ) {
            _requireProtocolHead(data, 1, selector);
            return selector;
        }
        if (selector == IWebAuthnAuthAccountInteract.directExecuteFromAccount.selector) {
            _validateDirectExecuteFromAccount(data, false, true);
            return selector;
        }
        if (selector == IWebAuthnAuthAccountInteract.directExecutePrivateFromAccount.selector) {
            _validateDirectExecuteFromAccount(data, true, true);
            return selector;
        }
        if (
            selector == IWebAuthnAuthAccountInteract.executeFromAccount.selector
                || selector == IWebAuthnAuthAccountInteract.approveAndExecuteFromAccount.selector
        ) {
            _requireProtocolHead(data, 4, selector);
            uint256 operationId = uint256(_protocolWord(data, 0));
            bytes32 interactionId = _protocolWord(data, 1);
            _validateOperationAccountScope(operationId, interactionId);
            return selector;
        }
        if (
            selector == IWebAuthnAuthAccountInteract.executePrivateFromAccount.selector
                || selector == IWebAuthnAuthAccountInteract.approveAndExecutePrivateFromAccount.selector
        ) {
            _requireProtocolHead(data, 5, selector);
            uint256 operationId = uint256(_protocolWord(data, 0));
            bytes32 interactionId = _protocolWord(data, 1);
            _validateOperationAccountScope(operationId, interactionId);
            return selector;
        }
        revert ProtocolSelectorNotAllowed(selector);
    }

    function _validateDirectExecuteFromAccount(bytes memory data, bool privateInteraction, bool validateLiveState)
        private
        view
    {
        bytes4 selector = privateInteraction
            ? IWebAuthnAuthAccountInteract.directExecutePrivateFromAccount.selector
            : IWebAuthnAuthAccountInteract.directExecuteFromAccount.selector;
        _requireProtocolHead(data, privateInteraction ? 10 : 9, selector);
        address account = _protocolAddress(data, 0, selector);
        bytes32 policyId = _protocolWord(data, 1);
        bytes32 interactionId = _protocolWord(data, 2);
        address actor = _protocolAddress(data, 7, selector);

        if (actor != address(this)) revert ProtocolActorMismatch(actor);
        if (_protocolDynamicBytesLength(data, 8, selector) != 0) revert ProtocolActorSignatureNotEmpty();
        _validateScopedAccount(account, policyId, interactionId, validateLiveState);
    }

    function _validateOperationAccountScope(uint256 operationId, bytes32 interactionId) private view {
        IWebAuthnAuthAccountInteract interact_ = IWebAuthnAuthAccountInteract(interact());
        address account = interact_.getOperationSafe(operationId);
        bytes32 policyId = interact_.getOperationPolicyId(operationId);
        _validateScopedAccount(account, policyId, interactionId);
    }

    function _validateScopedAccount(address account, bytes32 policyId, bytes32 interactionId) private view {
        _validateScopedAccount(account, policyId, interactionId, true);
    }

    function _validateScopedAccount(address account, bytes32 policyId, bytes32 interactionId, bool validateLiveState)
        private
        view
    {
        _requireDirectExecuteScopeAccount(account);
        if (validateLiveState && !IWebAuthnAuthAccountRegistry(registry()).isAccountAllowed(account)) {
            revert ProtocolAccountNotAllowed(account);
        }
        if (!_directExecuteScopes[_scopeKey(account, policyId, interactionId)]) {
            revert ProtocolCallScopeDenied(account, policyId, interactionId);
        }
    }

    function _validateUserOperationCall(bytes calldata callData, bytes32 expectedCredHash) private view {
        if (callData.length < 4) revert UserOperationCallSelectorNotAllowed(bytes4(0));
        bytes4 selector;
        assembly {
            selector := calldataload(callData.offset)
        }
        if (selector == this.executeUserOpProtocolCall.selector) {
            (bytes32 authorizingCredHash, bytes32 expectedAuthorizationRevision,, address target, bytes memory data) =
                abi.decode(callData[4:], (bytes32, bytes32, uint64, address, bytes));
            _requireUserOperationCredential(expectedCredHash, authorizingCredHash);
            _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
            _validateProtocolCall(target, data, false);
            return;
        }
        if (selector == this.executeUserOpSafeModuleCall.selector) {
            (
                bytes32 authorizingCredHash,
                bytes32 expectedAuthorizationRevision,,
                address expectedModule,
                bytes32 expectedInteractDigest,
                bytes memory moduleCall
            ) = abi.decode(callData[4:], (bytes32, bytes32, uint64, address, bytes32, bytes));
            _requireUserOperationCredential(expectedCredHash, authorizingCredHash);
            _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
            if (expectedModule == address(0)) revert UserOperationExpectedModuleZero();
            if (expectedInteractDigest == bytes32(0)) revert UserOperationInteractDigestZero();
            _validateSafeModuleCall(moduleCall);
            return;
        }
        if (selector == this.addCredentialFromUserOp.selector) {
            (
                bytes32 authorizingCredHash,
                bytes32 expectedAuthorizationRevision,
                bytes32 credHash,
                bytes32 qx,
                bytes32 qy,
            ) = abi.decode(callData[4:], (bytes32, bytes32, bytes32, bytes32, bytes32, bytes));
            _requireUserOperationCredential(expectedCredHash, authorizingCredHash);
            _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
            if (_credentials[credHash].exists) revert CredentialExists(credHash);
            if (!P256.isValidPublicKey(qx, qy)) revert InvalidPublicKey(qx, qy);
            return;
        }
        if (selector == this.revokeCredentialFromUserOp.selector) {
            (bytes32 authorizingCredHash, bytes32 expectedAuthorizationRevision, bytes32 credHash) =
                abi.decode(callData[4:], (bytes32, bytes32, bytes32));
            _requireUserOperationCredential(expectedCredHash, authorizingCredHash);
            _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
            _requireCredentialRevocable(credHash);
            return;
        }
        if (selector == this.setDirectExecuteScopeFromUserOp.selector) {
            (bytes32 authorizingCredHash, bytes32 expectedAuthorizationRevision,, address account,,,) =
                abi.decode(callData[4:], (bytes32, bytes32, uint64, address, bytes32, bytes32, bool));
            _requireUserOperationCredential(expectedCredHash, authorizingCredHash);
            _requireUserOperationAuthorizationRevision(expectedAuthorizationRevision);
            _requireDirectExecuteScopeAccount(account);
            return;
        }
        revert UserOperationCallSelectorNotAllowed(selector);
    }

    function _requireUserOperationCredential(bytes32 expected, bytes32 provided) private pure {
        if (provided != expected) revert UserOperationCredentialMismatch(expected, provided);
    }

    /// @dev EntryPoint validates an entire bundle before executing any operation.
    ///      The signed calldata carries this expected revision so an earlier operation
    ///      cannot rotate account code after validation and reinterpret this call.
    function _requireUserOperationAuthorizationRevision(bytes32 expected) private view {
        bytes32 actual = _authorizationRevision();
        if (expected != actual) revert UserOperationAuthorizationRevisionMismatch();
    }

    /// @dev Read tenant state only during execution, never during ERC-7562 account validation.
    function _requireExecutionRuntime(uint64 expected) private view {
        uint64 actual = executionRuntimeVersion();
        if (expected != actual) revert ExecutionRuntimeMismatch();
    }

    function _requireUserOperationPaymaster(PackedUserOperation calldata userOp) private pure {
        if (ERC4337Utils.paymaster(userOp) == address(0)) revert UserOperationPaymasterMissing();
    }

    function _validateUserOperationFactory(PackedUserOperation calldata userOp) private view {
        address userOpFactory = ERC4337Utils.factory(userOp);
        if (userOpFactory == address(0)) return;
        address factory_ = factory();
        if (userOpFactory != factory_) revert UserOperationFactoryMismatch(factory_, userOpFactory);

        bytes calldata factoryData = ERC4337Utils.factoryData(userOp);
        bytes4 selector = bytes4(0);
        if (factoryData.length >= 4) {
            assembly {
                selector := calldataload(factoryData.offset)
            }
        }
        if (selector != _CREATE_AUTH_ACCOUNT_SELECTOR) revert UserOperationFactorySelectorNotAllowed(selector);
        // EntryPoint has already required this factory call to return `userOp.sender`.
        // The signed userOpHash binds the complete factory calldata, so validation
        // does not need an external factory read or a second address derivation.
    }

    function _decodeUserOperationSignature(bytes calldata signature)
        private
        view
        returns (uint256 deadline, WebAuthnAssertion memory assertion)
    {
        try this.decodeWebAuthnEnvelope(signature, true) returns (
            uint256 decodedDeadline, WebAuthnAssertion memory decodedAssertion
        ) {
            return (decodedDeadline, decodedAssertion);
        } catch {
            revert UserOperationSignatureMalformed();
        }
    }

    function _validateStoredFactory() private view returns (IWebAuthnAuthAccountFactoryProtocol factoryContract) {
        address factory_ = factory();
        if (factory_ == address(0) || factory_.code.length == 0) revert ProtocolFactoryInvalid(factory_);
        factoryContract = IWebAuthnAuthAccountFactoryProtocol(factory_);

        address registry_ = registry();
        address interact_ = interact();
        address factoryRegistry = factoryContract.REGISTRY();
        if (factoryRegistry != registry_) revert ProtocolFactoryInvalid(factory_);

        address factoryInteract = factoryContract.INTERACT();
        if (factoryInteract != interact_) revert ProtocolFactoryInvalid(factory_);

        address factoryEntryPoint = factoryContract.ENTRY_POINT();
        if (factoryEntryPoint != entryPoint) revert ProtocolFactoryInvalid(factory_);

        if (!IWebAuthnAuthAccountRegistry(registry_).isAuthAccountFactoryAllowed(factory_)) {
            revert ProtocolFactoryInvalid(factory_);
        }
        if (!factoryContract.isAuthAccount(address(this))) {
            revert ProtocolFactoryInvalid(factory_);
        }
    }

    function _resolveSafeModule() private view returns (address module) {
        IWebAuthnAuthAccountFactoryProtocol factoryContract = _validateStoredFactory();
        address safeFactory = factoryContract.SAFE_FACTORY();
        if (safeFactory.code.length == 0) {
            revert ProtocolFactoryInvalid(factory());
        }

        address interact_ = interact();
        IWebAuthnAuthAccountSafeFactory safeFactoryContract = IWebAuthnAuthAccountSafeFactory(safeFactory);
        if (safeFactoryContract.INTERACT_CONTRACT() != interact_) revert ProtocolFactoryInvalid(factory());
        module = safeFactoryContract.MODULE_CONTRACT();
        if (module.code.length == 0 || IWebAuthnAuthAccountSafeModule(module).INTERACTION() != interact_) {
            revert UserOperationModuleInvalid(module);
        }
    }

    /// @dev Validate the fixed-marker actor trailer and restrict execution to the
    ///      six OKModule execution selectors. OKModule performs the canonical ABI
    ///      decode and rejects mixed explicit/trailer actors during execution.
    function _validateSafeModuleCall(bytes memory data) private view {
        uint256 length = data.length;
        if (length < 4 + _USER_OP_ACTOR_TRAILER_LENGTH) revert UserOperationModuleCallInvalid(bytes4(0));

        bytes4 selector;
        bytes32 magic;
        bytes32 marker;
        uint256 signatureLength;
        address actor;
        assembly ("memory-safe") {
            let start := add(data, 0x20)
            let end := add(start, length)
            selector := mload(start)
            magic := mload(sub(end, 32))
            signatureLength := shr(224, mload(sub(end, 36)))
            actor := shr(96, mload(sub(end, 56)))
            marker := mload(sub(end, 88))
        }
        if (
            magic != _SIGNED_ACTOR_TRAILER_MAGIC || signatureLength != 32 || actor != address(this)
                || marker != _USER_OP_ACTOR_MARKER
        ) {
            revert UserOperationModuleCallInvalid(selector);
        }

        if (
            selector != _MODULE_EXECUTE_SELECTOR && selector != _MODULE_EXECUTE_PRIVATE_SELECTOR
                && selector != _MODULE_APPROVE_EXECUTE_SELECTOR && selector != _MODULE_APPROVE_EXECUTE_PRIVATE_SELECTOR
                && selector != _MODULE_DIRECT_SELECTOR && selector != _MODULE_DIRECT_PRIVATE_SELECTOR
        ) {
            revert UserOperationModuleCallInvalid(selector);
        }
    }

    function _isUserOpActorMarker(bytes calldata signature) private pure returns (bool matches) {
        if (signature.length != 32) return false;
        bytes32 marker;
        assembly ("memory-safe") {
            marker := calldataload(signature.offset)
        }
        return marker == _USER_OP_ACTOR_MARKER;
    }

    function _activeUserOpActorDigest() private view returns (bytes32 digest) {
        bytes32 slot = _USER_OP_ACTOR_DIGEST_SLOT;
        assembly ("memory-safe") {
            digest := tload(slot)
        }
    }

    function _setActiveUserOpActorDigest(bytes32 digest) private {
        bytes32 slot = _USER_OP_ACTOR_DIGEST_SLOT;
        assembly ("memory-safe") {
            tstore(slot, digest)
        }
    }

    function _requireProtocolHead(bytes memory data, uint256 words, bytes4 selector) private pure {
        if (data.length < 4 + words * 32) revert ProtocolSelectorNotAllowed(selector);
    }

    function _protocolWord(bytes memory data, uint256 wordIndex) private pure returns (bytes32 value) {
        assembly ("memory-safe") {
            value := mload(add(add(data, 0x24), mul(wordIndex, 0x20)))
        }
    }

    function _protocolAddress(bytes memory data, uint256 wordIndex, bytes4 selector)
        private
        pure
        returns (address value)
    {
        uint256 encoded = uint256(_protocolWord(data, wordIndex));
        if (encoded >> 160 != 0) revert ProtocolSelectorNotAllowed(selector);
        assembly ("memory-safe") {
            value := encoded
        }
    }

    function _protocolDynamicBytesLength(bytes memory data, uint256 wordIndex, bytes4 selector)
        private
        pure
        returns (uint256 length)
    {
        uint256 relativeOffset = uint256(_protocolWord(data, wordIndex));
        if (relativeOffset > data.length - 36) revert ProtocolSelectorNotAllowed(selector);
        assembly ("memory-safe") {
            length := mload(add(add(data, 0x24), relativeOffset))
        }
        if (length > data.length - 36 - relativeOffset) revert ProtocolSelectorNotAllowed(selector);
    }

    struct ValidationResult {
        bool ok;
        bytes32 credHash;
        uint32 signCount;
    }

    function _validateWebAuthnSignature(bytes32 challenge, bytes calldata signature)
        private
        view
        returns (ValidationResult memory result)
    {
        (bool decoded, WebAuthnAssertion memory assertion) = _tryDecodeWebAuthnAssertion(signature);
        if (!decoded) {
            return result;
        }
        Credential storage credential = _credentials[assertion.credHash];
        if (!credential.exists || !credential.active) {
            return result;
        }
        return _validateDecodedWebAuthnSignature(
            challenge, assertion, credential.signCount, credential.qx, credential.qy, false
        );
    }

    function _validateWebAuthnSignatureForPublicKey(
        bytes32 challenge,
        bytes calldata signature,
        bytes32 credHash,
        bytes32 qx,
        bytes32 qy
    ) private view returns (ValidationResult memory result) {
        (bool decoded, WebAuthnAssertion memory assertion) = _tryDecodeWebAuthnAssertion(signature);
        if (!decoded || assertion.credHash != credHash) {
            return result;
        }
        return _validateDecodedWebAuthnSignature(challenge, assertion, 0, qx, qy, false);
    }

    function _tryDecodeWebAuthnAssertion(bytes calldata signature)
        private
        view
        returns (bool ok, WebAuthnAssertion memory assertion)
    {
        if (signature.length == 0) {
            return (false, assertion);
        }
        try this.decodeWebAuthnEnvelope(signature, false) returns (uint256, WebAuthnAssertion memory decoded) {
            return (true, decoded);
        } catch {
            return (false, assertion);
        }
    }

    function _validateDecodedWebAuthnSignature(
        bytes32 challenge,
        WebAuthnAssertion memory assertion,
        uint32 previousSignCount,
        bytes32 qx,
        bytes32 qy,
        bool nativeOnly
    ) private view returns (ValidationResult memory result) {
        if (!_validateAuthenticatorData(assertion.authenticatorData, previousSignCount, result)) {
            return result;
        }
        if (!_validateClientData(
                assertion.clientDataJson,
                assertion.typeIndex,
                assertion.challengeIndex,
                assertion.originIndex,
                challenge
            )) {
            return result;
        }

        bytes32 clientDataHash = sha256(assertion.clientDataJson);
        bytes32 signedHash = sha256(bytes.concat(assertion.authenticatorData, clientDataHash));
        // ERC-7562 validation must use the audited precompile available on every
        // release chain. Other signature surfaces retain OpenZeppelin's fallback
        // so local tooling can still exercise real P-256 verification.
        bool valid = nativeOnly
            ? P256.verifyNative(signedHash, assertion.r, assertion.s, qx, qy)
            : P256.verify(signedHash, assertion.r, assertion.s, qx, qy);
        if (!valid) {
            return result;
        }
        result.ok = true;
        result.credHash = assertion.credHash;
    }

    function _validateAuthenticatorData(
        bytes memory authenticatorData,
        uint32 previousSignCount,
        ValidationResult memory result
    ) private view returns (bool) {
        if (authenticatorData.length < 37) {
            return false;
        }
        bytes32 gotRpIdHash;
        assembly ("memory-safe") {
            gotRpIdHash := mload(add(authenticatorData, 0x20))
        }
        if (gotRpIdHash != rpIdHash) {
            return false;
        }
        uint8 flags = uint8(authenticatorData[32]);
        if (flags & _AUTH_DATA_FLAG_UP == 0) {
            return false;
        }
        if (flags & _AUTH_DATA_FLAG_UV == 0) {
            return false;
        }
        if (flags & _AUTH_DATA_FLAG_BS != 0 && flags & _AUTH_DATA_FLAG_BE == 0) {
            return false;
        }
        uint32 signCount = _readUint32Be(authenticatorData, 33);
        if ((signCount != 0 || previousSignCount != 0) && signCount <= previousSignCount) {
            return false;
        }
        result.signCount = signCount;
        return true;
    }

    function _validateClientData(
        bytes memory clientDataJson,
        uint256 typeIndex,
        uint256 challengeIndex,
        uint256 originIndex,
        bytes32 challenge
    ) private view returns (bool) {
        // Use the optimized encoder to preserve counterfactual verification gas
        // for deployment and JSON validation under the shared ERC-7562 ceiling.
        bytes memory challengeValue = bytes(Base64.encodeURL(abi.encodePacked(challenge)));
        bytes memory originValue = bytes(_origin);
        ClientDataParserState memory state;

        // Parse the signed JSON once. Re-scanning from the root for every byte is
        // quadratic and cannot fit ERC-7562's 500k verification-gas ceiling.
        for (uint256 i = 0; i < clientDataJson.length;) {
            bytes1 c = clientDataJson[i];
            if (state.inString) {
                if (state.escaped) {
                    state.escaped = false;
                } else if (c == 0x5c) {
                    state.escaped = true;
                } else if (c == 0x22) {
                    state.inString = false;
                }
                unchecked {
                    ++i;
                }
                continue;
            }

            if (state.depth == 0 && state.rootClosed) {
                if (!_isJsonWhitespace(c)) return false;
                unchecked {
                    ++i;
                }
                continue;
            }

            if (c == 0x22) {
                if (state.depth == 1 && state.expectingRootKey) {
                    (uint256 keyEnd, bool keyEscaped) = _jsonStringEnd(clientDataJson, i + 1);
                    if (keyEnd == type(uint256).max || keyEscaped) return false;
                    uint256 colonIndex = _skipJsonWhitespace(clientDataJson, keyEnd + 1);
                    if (colonIndex >= clientDataJson.length || clientDataJson[colonIndex] != 0x3a) return false;
                    uint256 valueStart = _skipJsonWhitespace(clientDataJson, colonIndex + 1);
                    if (valueStart >= clientDataJson.length) return false;

                    uint256 fieldKind = _clientDataFieldKind(clientDataJson, i + 1, keyEnd);
                    if (fieldKind == 1) {
                        if ((state.requiredFields & 1) != 0) return false;
                        if (!_matchesJsonStringValue(clientDataJson, valueStart, typeIndex, bytes("webauthn.get"))) {
                            return false;
                        }
                        state.requiredFields |= 1;
                    } else if (fieldKind == 2) {
                        if ((state.requiredFields & 2) != 0) return false;
                        if (!_matchesJsonStringValue(clientDataJson, valueStart, challengeIndex, challengeValue)) {
                            return false;
                        }
                        state.requiredFields |= 2;
                    } else if (fieldKind == 3) {
                        if ((state.requiredFields & 4) != 0) return false;
                        if (!_matchesJsonStringValue(clientDataJson, valueStart, originIndex, originValue)) {
                            return false;
                        }
                        state.requiredFields |= 4;
                    } else if (fieldKind == 4) {
                        if ((state.requiredFields & 8) != 0 || !_matchesJsonFalse(clientDataJson, valueStart)) {
                            return false;
                        }
                        state.requiredFields |= 8;
                    } else if (fieldKind == 5) {
                        return false;
                    }

                    state.expectingRootKey = false;
                    state.afterRootComma = false;
                    i = keyEnd + 1;
                    continue;
                }
                state.inString = true;
            } else if (c == 0x7b || c == 0x5b) {
                if (state.depth == 0) {
                    if (state.rootSeen || c != 0x7b) return false;
                    state.rootSeen = true;
                    state.expectingRootKey = true;
                }
                if (state.depth == 256) return false;
                uint256 depthBit = uint256(1) << state.depth;
                if (c == 0x5b) {
                    state.arrayDepths |= depthBit;
                } else {
                    state.arrayDepths &= ~depthBit;
                }
                ++state.depth;
            } else if (c == 0x7d || c == 0x5d) {
                if (state.depth == 0) return false;
                uint256 closingDepth = state.depth - 1;
                bool closesArray = c == 0x5d;
                if ((((state.arrayDepths >> closingDepth) & 1) != 0) != closesArray) return false;
                if (state.depth == 1) {
                    if (state.afterRootComma) return false;
                    state.rootClosed = true;
                }
                state.arrayDepths &= ~(uint256(1) << closingDepth);
                --state.depth;
            } else if (state.depth == 1 && c == 0x2c) {
                if (state.expectingRootKey) return false;
                state.expectingRootKey = true;
                state.afterRootComma = true;
            } else if (state.depth == 1 && state.expectingRootKey && !_isJsonWhitespace(c)) {
                return false;
            } else if (state.depth == 0 && !_isJsonWhitespace(c)) {
                return false;
            }
            unchecked {
                ++i;
            }
        }
        return
            state.rootSeen && state.rootClosed && state.depth == 0 && !state.inString && (state.requiredFields & 7) == 7;
    }

    function _jsonStringEnd(bytes memory data, uint256 start) private pure returns (uint256 end, bool containedEscape) {
        bool escaped = false;
        for (uint256 i = start; i < data.length;) {
            bytes1 c = data[i];
            if (escaped) {
                escaped = false;
                containedEscape = true;
            } else if (c == 0x5c) {
                escaped = true;
            } else if (c == 0x22) {
                return (i, containedEscape);
            }
            unchecked {
                ++i;
            }
        }
        return (type(uint256).max, containedEscape);
    }

    function _clientDataFieldKind(bytes memory data, uint256 start, uint256 end) private pure returns (uint256) {
        uint256 length = end - start;
        bytes32 word;
        assembly ("memory-safe") {
            word := mload(add(add(data, 0x20), start))
        }
        uint256 prefix = uint256(word);
        if (length == 4 && prefix >> 224 == 0x74797065) return 1;
        if (length == 9 && prefix >> 184 == 0x6368616c6c656e6765) return 2;
        if (length == 6 && prefix >> 208 == 0x6f726967696e) return 3;
        if (length == 11 && prefix >> 168 == 0x63726f73734f726967696e) return 4;
        if (length == 9 && prefix >> 184 == 0x746f704f726967696e) return 5;
        return 0;
    }

    function _matchesJsonStringValue(bytes memory data, uint256 start, uint256 valueIndex, bytes memory expected)
        private
        pure
        returns (bool)
    {
        if (start >= data.length || data[start] != 0x22 || valueIndex != start + 1) return false;
        uint256 contentStart = start + 1;
        if (contentStart + expected.length >= data.length) return false;
        // The bounds check keeps this entire slice inside data. Hash only the
        // expected value's bytes; quotes and the field boundary are checked separately.
        bytes32 actualHash;
        assembly ("memory-safe") {
            actualHash := keccak256(add(add(data, 0x20), contentStart), mload(expected))
        }
        if (actualHash != _hashEncoded(expected)) return false;
        uint256 closingQuote = contentStart + expected.length;
        return data[closingQuote] == 0x22 && _isJsonFieldBoundary(data, closingQuote + 1);
    }

    function _matchesJsonFalse(bytes memory data, uint256 start) private pure returns (bool) {
        if (start + 5 > data.length) return false;
        bytes32 word;
        assembly ("memory-safe") {
            word := mload(add(add(data, 0x20), start))
        }
        return uint256(word) >> 216 == 0x66616c7365 && _isJsonFieldBoundary(data, start + 5);
    }

    function _isJsonFieldBoundary(bytes memory data, uint256 index) private pure returns (bool) {
        index = _skipJsonWhitespace(data, index);
        return index == data.length || data[index] == 0x2c || data[index] == 0x7d;
    }

    function _skipJsonWhitespace(bytes memory data, uint256 index) private pure returns (uint256) {
        while (index < data.length && _isJsonWhitespace(data[index])) {
            unchecked {
                ++index;
            }
        }
        return index;
    }

    function _isJsonWhitespace(bytes1 c) private pure returns (bool) {
        return c == 0x20 || c == 0x0a || c == 0x0d || c == 0x09;
    }

    function _readUint32Be(bytes memory data, uint256 offset) private pure returns (uint32 value) {
        value = uint32(uint8(data[offset])) << 24;
        value |= uint32(uint8(data[offset + 1])) << 16;
        value |= uint32(uint8(data[offset + 2])) << 8;
        value |= uint32(uint8(data[offset + 3]));
    }

    function _scopeKey(address account, bytes32 policyId, bytes32 interactionId) private pure returns (bytes32) {
        return _hashEncoded(abi.encode(account, policyId, interactionId));
    }

    function _authorizationRevision() private view returns (bytes32) {
        return WebAuthnAuthAccountProxyStorage.authorizationRevision();
    }

    function _hashEncoded(bytes memory data) private pure returns (bytes32 h) {
        assembly ("memory-safe") {
            h := keccak256(add(data, 0x20), mload(data))
        }
    }

    function _hashCalldataBytes(bytes calldata data) private pure returns (bytes32 h) {
        bytes memory dataCopy = data;
        assembly ("memory-safe") {
            h := keccak256(add(dataCopy, 0x20), mload(dataCopy))
        }
    }
}
