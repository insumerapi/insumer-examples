// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./InsumerAttestationToken.sol";

/// @title IWalletStateVerifier
/// @notice Minimal interface inlined from erc-8183/hook-contracts
///         (contracts/hooks/WalletStateHook.sol). Hooks read this surface to
///         answer "does this wallet satisfy the named condition set right now?"
interface IWalletStateVerifier {
    function checkWalletState(address wallet, bytes32 conditionsHash)
        external
        view
        returns (bool verified, uint256 validUntil);
}

/// @title InsumerWalletStateVerifier
/// @notice Reference IWalletStateVerifier implementation that exposes off-chain
///         InsumerAPI wallet-state attestations for ERC-8183 hooks.
///
/// @dev DEFAULT MODE: anchored verification (recommended)
///      ----------------------------------------------------------------
///      Construct with the InsumerAPI service public key (`pubKeyX`, `pubKeyY`).
///      `submitAttestation(token)` takes the attestation's Wallet Auth token
///      (the ES256 JWT `POST /v1/attest` returns with `"format": "jwt"`),
///      verifies its signature on-chain through the `P256VERIFY` precompile,
///      and stores what the signed payload itself says (see
///      `InsumerAttestationToken`):
///        wallet          <- sub            (the wallet the condition evaluated)
///        conditionsHash  <- conditionHash  (the token's single condition hash)
///        verified        <- pass
///        validUntil      <- exp
///      No stored value comes from the submitter, so anyone may submit: the
///      trust anchor is the immutable signing key and the submitter is
///      untrusted. A token replaces a stored result only if it expires later,
///      so an older token cannot overwrite a newer one. Every token for one
///      `(wallet, condition)` has the same lifetime, so a later expiry means
///      a later issuance (not necessarily a later block read); of two tokens
///      issued in the same second, the first submitted stays. Anyone can
///      store a genuine failing verdict for a wallet, since issuance does not
///      require control of the wallet; any later passing token replaces it.
///
///      `checkWalletState` returns `(true, validUntil)` only while a stored
///      passing verdict is unexpired, and `(false, 0)` otherwise.
///
///      This is the canonical configuration. The contract is a verifier, not a
///      registry: trust derives from the off-chain signature, not from the
///      stored value. The cache exists only to amortise gas across reads with
///      the same `(wallet, conditionsHash)` inside `validUntil`.
///
///      Configuring a hook: `conditionsHash` is the 32-byte SHA-256
///      `conditionHash` InsumerAPI returns for one condition, exactly as it
///      returns it. Pin a condition on an EVM chain (a non-EVM condition's
///      token names a non-EVM wallet, which is never stored). A v1 key and a
///      v2 key can hash the same condition differently, so configure the hash
///      your own key era returns.
///
///      JWKS for the signing key: https://api.insumermodel.com/v1/jwks
///      Deploy only on a chain that provides `P256VERIFY` at `0x0100`
///      (RIP-7212 on L2s such as Base, Optimism, Arbitrum, Polygon, Scroll,
///      ZKsync, Celo; EIP-7951 on L1).
///
///      Post-quantum signature: every attest response is signed twice, ES256
///      and a post-quantum ML-DSA-65 signature (`pqSig`/`pqKid`, and `pqJwt`
///      beside `jwt`), and the JWKS lists its key (kids
///      insumer-attest-pq1/insumer-trust-pq1) after the three EC entries. This
///      contract verifies the classical ES256 signature only and does not
///      consume the post-quantum signature.
///
/// @dev FALLBACK MODE: trusted relayer (testnet-only)
///      ----------------------------------------------------------------
///      Constructing with `pubKeyX = pubKeyY = 0` disables token submission;
///      the relayer instead pushes results with `submitTrustedResult`, and the
///      contract trusts them as given. This is a testnet / local-development
///      convenience and is on a deprecation track. Do NOT use in production:
///      it removes the cryptographic anchor and collapses the trust model to
///      "we trust the relayer," which is oracle-shaped, not verifier-shaped.
///
/// @dev INTEGRATION FLOW (anchored mode)
///      1. Off-chain: obtain a token for `(wallet, condition)` from
///         `POST https://api.insumermodel.com/v1/attest` with `"format": "jwt"`.
///      2. Anyone calls `submitAttestation(bytes(response.data.jwt))`.
///      3. `WalletStateHook` (or any other consumer) reads `checkWalletState()`
///         to gate job-lifecycle actions.
///
/// @dev GETTING CREDENTIALS
///      Free tier, no credit card: 100 daily reads + 10 attestation credits.
///
///      Developers (email-based):
///        POST https://api.insumermodel.com/v1/keys/create
///        body: {"email":"YOUR_EMAIL","appName":"erc8183-hooks","tier":"free"}
///
///      Agents (wallet-based, no email):
///        POST https://api.insumermodel.com/v1/keys/buy
///        body: {"txHash":"0x...","chainId":8453,"amount":5,"appName":"my-agent"}
///        Agent sends USDC/USDT/BTC to the platform wallet, then POSTs the tx
///        hash; the sending wallet is the identity. Stablecoin auto-detected
///        from the transfer log. Minimum 5 stablecoin units; credits scale with
///        amount.
///
///      API reference: https://insumermodel.com/developers/api-reference/
///      Attestation:   POST https://api.insumermodel.com/v1/attest
///      JWKS:          https://api.insumermodel.com/v1/jwks
/// @custom:audit status=unaudited
contract InsumerWalletStateVerifier is IWalletStateVerifier {
    struct Attestation {
        bool verified;
        uint256 validUntil;
    }

    error NotRelayer();
    error NotOwner();
    error ZeroAddress();
    error InvalidToken();
    error ExpiredToken();
    error NotNewer();
    error AnchoredMode();
    error FallbackMode();
    error PartialKey();

    event AttestationSubmitted(
        address indexed wallet,
        bytes32 indexed conditionsHash,
        bool verified,
        uint256 validUntil
    );
    event RelayerUpdated(address indexed oldRelayer, address indexed newRelayer);

    /// @dev InsumerAPI service P-256 public key coordinates.
    ///      Non-zero for anchored mode (recommended); (0, 0) for the
    ///      trusted-relayer fallback (testnet-only).
    uint256 public immutable pubKeyX;
    uint256 public immutable pubKeyY;

    /// @dev True in anchored mode (both coordinates non-zero). A key with
    ///      exactly one zero coordinate is refused at construction.
    bool public immutable verifySignatures;

    /// @dev Relayer for the fallback mode. Unused in anchored mode.
    address public relayer;

    /// @dev Contract owner (can update relayer)
    address public owner;

    /// @dev Stored attestations keyed by (wallet, conditionsHash)
    mapping(address => mapping(bytes32 => Attestation)) private _attestations;

    /// @param _relayer  Fallback-mode relayer (may be zero in anchored mode)
    /// @param _pubKeyX  X coordinate of attestation service public key (0 for fallback mode)
    /// @param _pubKeyY  Y coordinate of attestation service public key (0 for fallback mode)
    constructor(address _relayer, uint256 _pubKeyX, uint256 _pubKeyY) {
        if ((_pubKeyX == 0) != (_pubKeyY == 0)) revert PartialKey();
        verifySignatures = _pubKeyX != 0;
        if (!verifySignatures && _relayer == address(0)) revert ZeroAddress();
        relayer = _relayer;
        owner = msg.sender;
        pubKeyX = _pubKeyX;
        pubKeyY = _pubKeyY;
    }

    /// @inheritdoc IWalletStateVerifier
    function checkWalletState(address wallet, bytes32 conditionsHash)
        external
        view
        override
        returns (bool verified, uint256 validUntil)
    {
        Attestation memory a = _attestations[wallet][conditionsHash];
        if (!a.verified || a.validUntil <= block.timestamp) return (false, 0);
        return (true, a.validUntil);
    }

    /// @notice Store the verdict an InsumerAPI attestation token carries.
    ///         Anyone may call; every stored value is read from the signed token.
    /// @param token The compact JWT, as ASCII bytes.
    function submitAttestation(bytes calldata token) external {
        if (!verifySignatures) revert FallbackMode();
        (bool ok, InsumerAttestationToken.Claims memory c) = InsumerAttestationToken.read(token, pubKeyX, pubKeyY);
        if (!ok) revert InvalidToken();
        if (c.exp <= block.timestamp) revert ExpiredToken();
        Attestation storage stored = _attestations[c.sub][c.conditionHash];
        if (c.exp <= stored.validUntil) revert NotNewer();
        stored.verified = c.pass;
        stored.validUntil = c.exp;
        emit AttestationSubmitted(c.sub, c.conditionHash, c.pass, c.exp);
    }

    /// @notice Fallback mode only (testnet): the relayer pushes a result that
    ///         the contract trusts as given.
    function submitTrustedResult(
        address wallet,
        bytes32 conditionsHash,
        bool verified,
        uint256 validUntil
    ) external {
        if (verifySignatures) revert AnchoredMode();
        if (msg.sender != relayer) revert NotRelayer();
        _attestations[wallet][conditionsHash] = Attestation({verified: verified, validUntil: validUntil});
        emit AttestationSubmitted(wallet, conditionsHash, verified, validUntil);
    }

    /// @notice Update the fallback-mode relayer address.
    function setRelayer(address _relayer) external {
        if (msg.sender != owner) revert NotOwner();
        if (_relayer == address(0)) revert ZeroAddress();
        emit RelayerUpdated(relayer, _relayer);
        relayer = _relayer;
    }
}
