// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title InsumerTrustOracle
 * @notice ITrustOracle provider for ERC-8183 hooks — bridges InsumerAPI's off-chain
 *         wallet trust profiles to the on-chain getTrustScore(address) interface.
 *
 * @dev Integration flow:
 *   1. Off-chain: relayer calls POST /v1/trust with the target wallet address.
 *   2. API returns an ECDSA P-256 signed trust profile with per-dimension results.
 *   3. Relayer computes score = round(totalPassed / totalChecks * 100), clamped to [0,100].
 *   4. Relayer calls updateScore() with the wallet, score, and optionally the P-256 signature.
 *   5. Any ERC-8183 hook or evaluator calls getTrustScore() to read the cached score.
 *
 * Score derivation (off-chain, by relayer):
 *   The trust profile returns summary.totalPassed and summary.totalChecks
 *   (145 base checks across 9 dimensions since condition set "2026-10": stablecoins,
 *   governance, NFTs, staking, institutional stablecoins, tokenized treasuries,
 *   stablecoin deposits, wrapped bitcoin, names; up to 166 with the optional
 *   Solana, XRPL, Bitcoin and Tron wallets). Every check is a presence check.
 *   Score = round(totalPassed / totalChecks * 100).
 *   Example: 19/145 passed = score 13. Empty wallet = score 0.
 *   The denominator follows the signed conditionSetVersion: the 2026-10 set more than
 *   tripled it (45 -> 145), so every score computed this way is lower than it was under
 *   the previous set for the same holdings. A consumer that stored a threshold against
 *   the old set must re-derive it; do not compare scores across condition sets.
 *
 * Freshness:
 *   Scores expire after 30 minutes (matching the API's expiresAt TTL).
 *   getTrustScore() returns 0 for stale or missing scores.
 *
 * Trust model:
 *   If P-256 public key coordinates are provided at construction, updateScore()
 *   verifies the InsumerAPI signature via the RIP-7212 precompile. This proves
 *   the trust profile was produced by InsumerAPI's signing key.
 *
 *   The P-256 signature covers the full JSON trust payload (including totalPassed,
 *   totalChecks, wallet, dimensions). The relayer extracts the score from the
 *   signed payload — the signature itself does not bind directly to the uint256
 *   score posted on-chain. For tighter binding, have the relayer submit the raw
 *   signed payload and recompute the score on-chain (adds ~2000 gas per byte).
 *
 *   If no public key is provided (pubKeyX = 0, pubKeyY = 0), signature verification
 *   is skipped and the relayer is trusted to relay correct scores.
 *
 * Post-quantum companion:
 *   Since 2026-09-01 every attest and trust response also carries an ML-DSA-65
 *   post-quantum companion (pqSig/pqKid on the raw response, pqJwt beside jwt),
 *   and the JWKS carries two RFC 9964 AKP entries for its key (kids
 *   insumer-attest-pq1/insumer-trust-pq1) after the three EC entries. This
 *   contract verifies the classical ES256 signature only and does not consume
 *   the companion.
 *
 * RIP-7212 P256VERIFY precompile availability:
 *   Base, Optimism, Arbitrum, Polygon, Scroll, ZKsync, Celo, and other L2s.
 *
 * InsumerAPI public key:  https://insumermodel.com/.well-known/jwks.json
 * Verification library:   npm install insumer-verify
 * API docs:               https://insumermodel.com/developers/api-reference/
 * Trust endpoint spec:    https://insumermodel.com/openapi.yaml (POST /v1/trust)
 *
 * Companion to: erc-8183/hook-contracts providers/ directory
 * See also:     InsumerKeeperHook.sol (ERC-8191 pattern with full P-256 verification)
 */

/// @title ITrustOracle
/// @notice Vendor-neutral trust oracle interface for ERC-8183 hooks and evaluators.
/// @dev From erc-8183/hook-contracts. Any trust provider can implement this interface.
interface ITrustOracle {
    /// @notice Get the trust score for a user.
    /// @param user The address to query
    /// @return score Trust score in range [0, 100]. Returns 0 for unknown users.
    function getTrustScore(address user) external view returns (uint256 score);
}

contract InsumerTrustOracle is ITrustOracle {

    // ─────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────

    struct TrustData {
        uint256 score;
        uint256 updatedAt;
    }

    // ─────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────

    error InsumerTrustOracle__NotRelayer();
    error InsumerTrustOracle__NotOwner();
    error InsumerTrustOracle__ScoreOutOfRange();
    error InsumerTrustOracle__InvalidSignature();
    error InsumerTrustOracle__ZeroAddress();

    // ─────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────

    event ScoreUpdated(address indexed user, uint256 score, uint256 timestamp);
    event RelayerUpdated(address indexed oldRelayer, address indexed newRelayer);

    // ─────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────

    /// @dev RIP-7212 P256VERIFY precompile address
    address constant P256_VERIFIER = address(0x0100);

    /// @dev Scores older than 30 minutes are treated as stale (matching API TTL)
    uint256 public constant FRESHNESS_WINDOW = 1800;

    // ─────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────

    /// @dev InsumerAPI P-256 public key coordinates (from JWKS; the three EC kids
    ///      share these coordinates - the JWKS also carries post-quantum ML-DSA-65
    ///      entries under other kids, which this contract does not use. Trust
    ///      profiles on keys minted today carry kid "insumer-trust-v2",
    ///      pre-cutover keys "insumer-attest-v1").
    ///      If both are 0, signature verification is skipped.
    uint256 public immutable pubKeyX;
    uint256 public immutable pubKeyY;

    /// @dev Whether on-chain signature verification is enabled
    bool public immutable verifySignatures;

    /// @dev Authorized relayer address
    address public relayer;

    /// @dev Contract owner (can update relayer)
    address public owner;

    /// @dev Cached trust scores per wallet
    mapping(address => TrustData) public scores;

    // ─────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────

    /// @param _relayer  Authorized relayer address
    /// @param _pubKeyX  X coordinate of InsumerAPI P-256 public key (0 to skip verification)
    /// @param _pubKeyY  Y coordinate of InsumerAPI P-256 public key (0 to skip verification)
    constructor(address _relayer, uint256 _pubKeyX, uint256 _pubKeyY) {
        if (_relayer == address(0)) revert InsumerTrustOracle__ZeroAddress();
        relayer = _relayer;
        owner = msg.sender;
        pubKeyX = _pubKeyX;
        pubKeyY = _pubKeyY;
        verifySignatures = _pubKeyX != 0 && _pubKeyY != 0;
    }

    // ─────────────────────────────────────────────
    // ITrustOracle
    // ─────────────────────────────────────────────

    /// @inheritdoc ITrustOracle
    function getTrustScore(address user) external view override returns (uint256 score) {
        TrustData memory data = scores[user];
        if (data.updatedAt == 0) return 0;
        if (block.timestamp - data.updatedAt > FRESHNESS_WINDOW) return 0;
        return data.score;
    }

    // ─────────────────────────────────────────────
    // Relayer: update scores
    // ─────────────────────────────────────────────

    /// @notice Push a trust score on-chain from an InsumerAPI /v1/trust response.
    /// @dev The relayer computes: score = round(totalPassed / totalChecks * 100).
    ///      If verifySignatures is true, the P-256 signature is checked via RIP-7212.
    /// @param user         Wallet address that was profiled
    /// @param score        Trust score in [0, 100]
    /// @param r            P-256 signature r component (ignored if !verifySignatures)
    /// @param s            P-256 signature s component (ignored if !verifySignatures)
    /// @param messageHash  SHA-256 of the signed trust payload (ignored if !verifySignatures)
    function updateScore(
        address user,
        uint256 score,
        bytes32 r,
        bytes32 s,
        bytes32 messageHash
    ) external {
        if (msg.sender != relayer) revert InsumerTrustOracle__NotRelayer();
        if (score > 100) revert InsumerTrustOracle__ScoreOutOfRange();

        if (verifySignatures) {
            if (!_verifyP256(messageHash, r, s)) revert InsumerTrustOracle__InvalidSignature();
        }

        scores[user] = TrustData({ score: score, updatedAt: block.timestamp });
        emit ScoreUpdated(user, score, block.timestamp);
    }

    // ─────────────────────────────────────────────
    // Admin
    // ─────────────────────────────────────────────

    /// @notice Update the authorized relayer address.
    function setRelayer(address _relayer) external {
        if (msg.sender != owner) revert InsumerTrustOracle__NotOwner();
        if (_relayer == address(0)) revert InsumerTrustOracle__ZeroAddress();
        emit RelayerUpdated(relayer, _relayer);
        relayer = _relayer;
    }

    // ─────────────────────────────────────────────
    // Internal: P-256 signature verification
    // ─────────────────────────────────────────────

    /// @dev Verify P-256 signature using RIP-7212 precompile.
    ///      Input layout: messageHash || r || s || x || y (5 x 32 bytes)
    ///      Returns 1 if valid, 0 otherwise.
    function _verifyP256(bytes32 messageHash, bytes32 r, bytes32 s) internal view returns (bool) {
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(
            abi.encodePacked(messageHash, r, s, pubKeyX, pubKeyY)
        );
        return success && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }
}
