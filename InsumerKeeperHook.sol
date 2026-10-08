// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./InsumerAttestationToken.sol";

/**
 * @title InsumerKeeperHook
 * @notice Reference IKeeperHook for ERC-8191 recurring payments.
 *         Verifies an InsumerAPI attestation token before each collection cycle.
 *
 * @dev Integration flow:
 *   1. Off-chain: the keeper calls POST /v1/attest with "format": "jwt", the
 *      merchant's wallet and the subscription's condition (e.g. "holds
 *      governance token X").
 *   2. The keeper passes the returned token, bytes(response.data.jwt), as `data`.
 *   3. beforeKeep() verifies the token's signature through the P256VERIFY
 *      precompile and reads the verdict, wallet, condition and expiry from the
 *      signed payload itself (see InsumerAttestationToken).
 *   4. If any check fails, beforeKeep reverts and the collection is blocked.
 *
 * Trust model:
 *   The keeper supplies only the token, and every value beforeKeep checks is
 *   read from its signed payload, so the keeper cannot relay a verdict,
 *   wallet or condition the issuer did not sign. The token is a signed public
 *   statement, not a secret: anyone holding it can present it until it
 *   expires (30 minutes after issuance, 5 when the request includes an
 *   erc7710_delegation condition). Pin the subscription contract as
 *   keeperCaller at deployment so only it can run the hooks.
 *
 * Configuring a subscription:
 *   setConditionHash stores the 32-byte SHA-256 conditionHash InsumerAPI
 *   returns for one condition, exactly as it returns it. Pin a condition on an
 *   EVM chain (a non-EVM condition's token names a non-EVM wallet, which never
 *   equals the merchant). A v1 key and a v2 key can hash the same condition
 *   differently, so configure the hash your own key era returns.
 *
 * Post-quantum signature:
 *   Every attest response is signed twice: ES256 and a post-quantum ML-DSA-65
 *   signature (pqSig/pqKid, and pqJwt beside jwt), and the JWKS lists its key
 *   (kids insumer-attest-pq1/insumer-trust-pq1) after the three EC entries.
 *   This contract verifies the classical ES256 signature only and does not
 *   consume the post-quantum signature.
 *
 * P256VERIFY precompile (0x0100): RIP-7212 on L2s such as Base, Optimism,
 *   Arbitrum, Polygon, Scroll, ZKsync, Celo; EIP-7951 on L1. Deploy only on a
 *   chain that provides it.
 *
 * InsumerAPI public key:  https://insumermodel.com/.well-known/jwks.json
 * Verification library:   npm install insumer-verify
 * API docs:               https://insumermodel.com/developers/api-reference/
 *
 * Companion to: cadence-protocol/cadence-protocol EIPS/ikeeperhook-companion-spec.md
 * Pattern:      4.2 (Trust Gating) from the IKeeperHook companion spec
 */

/// @notice IKeeperHook interface -- beforeKeep/afterKeep naming per
///         chasseurmic + ThoughtProof consensus (cadence-protocol PR #1).
interface IKeeperHook {
    function beforeKeep(
        bytes32 subId,
        uint256 cycle,
        uint256 amount,
        address merchant,
        bytes calldata data
    ) external;

    function afterKeep(
        bytes32 subId,
        uint256 cycle,
        uint256 amount,
        address merchant,
        bytes calldata data
    ) external;
}

contract InsumerKeeperHook is IKeeperHook {

    // ─────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────

    error InvalidToken();                // signature or payload did not verify
    error AttestationFailed();           // pass != true
    error WalletMismatch();              // attested wallet != merchant
    error ConditionMismatch();           // conditionHash doesn't match expected
    error AttestationExpired();          // exp is not later than now
    error NotSubscriber();               // caller not authorized
    error NotKeeperCaller();             // hook called by other than the pinned caller

    // ─────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────

    /// @dev InsumerAPI P-256 public key coordinates.
    ///      Source: https://insumermodel.com/.well-known/jwks.json (the three
    ///      EC kids share one key). Decode JWK "x" and "y" (base64url) to uint256.
    uint256 public immutable pubKeyX;
    uint256 public immutable pubKeyY;

    /// @dev The contract allowed to call beforeKeep/afterKeep (the ERC-8191
    ///      subscription contract). Zero means any caller, which lets anyone
    ///      emit AttestationVerified for a valid token.
    address public immutable keeperCaller;

    /// @dev Subscriber who deployed this hook -- controls condition configuration.
    ///      Per companion spec Q3: subscriber sets the hook, not the merchant.
    address public immutable subscriber;

    /// @dev Expected conditionHash per subscription: the 32-byte SHA-256
    ///      conditionHash InsumerAPI returns for the condition.
    mapping(bytes32 => bytes32) public expectedConditionHash;

    // ─────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────

    event AttestationVerified(bytes32 indexed subId, uint256 cycle, address merchant);
    event ConditionHashSet(bytes32 indexed subId, bytes32 conditionHash);

    // ─────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────

    /// @param _pubKeyX      X coordinate of InsumerAPI P-256 public key (uint256)
    /// @param _pubKeyY      Y coordinate of InsumerAPI P-256 public key (uint256)
    /// @param _keeperCaller The subscription contract that calls the hooks, or
    ///                      address(0) to accept any caller
    constructor(uint256 _pubKeyX, uint256 _pubKeyY, address _keeperCaller) {
        pubKeyX = _pubKeyX;
        pubKeyY = _pubKeyY;
        keeperCaller = _keeperCaller;
        subscriber = msg.sender;
    }

    // ─────────────────────────────────────────────
    // Configuration (subscriber only)
    // ─────────────────────────────────────────────

    /// @notice Set the expected conditionHash for a subscription.
    /// @param subId            ERC-8191 subscription ID (bytes32)
    /// @param _conditionHash   The condition's conditionHash as the API returns it
    function setConditionHash(bytes32 subId, bytes32 _conditionHash) external {
        if (msg.sender != subscriber) revert NotSubscriber();
        expectedConditionHash[subId] = _conditionHash;
        emit ConditionHashSet(subId, _conditionHash);
    }

    // ─────────────────────────────────────────────
    // IKeeperHook: beforeKeep
    // ─────────────────────────────────────────────

    /// @notice Verify an InsumerAPI attestation token before allowing collection.
    /// @param data  The compact JWT from POST /v1/attest ("format": "jwt"), as ASCII bytes.
    function beforeKeep(
        bytes32 subId,
        uint256 cycle,
        uint256 /* amount */,
        address merchant,
        bytes calldata data
    ) external override {
        if (keeperCaller != address(0) && msg.sender != keeperCaller) revert NotKeeperCaller();
        (bool ok, InsumerAttestationToken.Claims memory c) = InsumerAttestationToken.read(data, pubKeyX, pubKeyY);
        if (!ok) revert InvalidToken();
        if (!c.pass) revert AttestationFailed();
        if (c.sub != merchant) revert WalletMismatch();
        if (c.conditionHash != expectedConditionHash[subId]) revert ConditionMismatch();
        if (c.exp <= block.timestamp) revert AttestationExpired();

        emit AttestationVerified(subId, cycle, merchant);
    }

    // ─────────────────────────────────────────────
    // IKeeperHook: afterKeep
    // ─────────────────────────────────────────────

    /// @notice Post-collection hook. No-op in this reference implementation.
    /// @dev Extend for pattern 4.4 (feedback loop) -- report successful payment
    ///      to a reputation system.
    function afterKeep(
        bytes32 /* subId */,
        uint256 /* cycle */,
        uint256 /* amount */,
        address /* merchant */,
        bytes calldata /* data */
    ) external view override {
        if (keeperCaller != address(0) && msg.sender != keeperCaller) revert NotKeeperCaller();
    }
}
