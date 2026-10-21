// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IWalletStateAttestation.sol";
import "./InsumerAttestationToken.sol";

/// @notice Single machine-readable access requirement, per ERC-8257.
struct AccessRequirement {
    bytes4 kind;
    bytes data;
    string label;
}

/// @notice Boolean logic combining multiple requirements, per ERC-8257.
enum RequirementLogic { AND, OR }

/// @title IAccessPredicate
/// @notice Three-function predicate interface for ERC-8257 tool gating.
/// @dev Inlined here so the example compiles on its own; the interface ID
///      matches ERC-8257. Downstream consumers can import it from the ERC-8257
///      reference implementation (`github.com/ProjectOpenSea/tool-registry`).
interface IAccessPredicate {
    function hasAccess(
        uint256 toolId,
        address account,
        bytes calldata data
    ) external view returns (bool);

    function name() external view returns (string memory);

    function getRequirements(uint256 toolId)
        external
        view
        returns (AccessRequirement[] memory requirements, RequirementLogic logic);
}

/// @notice Minimal ERC-165 interface (inlined to keep the example single-file).
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/// @title InsumerAccessPredicate
/// @notice Reference `IAccessPredicate` (ERC-8257) for off-chain-signed
///         wallet-state attestations issued by InsumerAPI.
///
/// @dev Architecture
///      ----------------------------------------------------------------
///      The proof is the attestation's Wallet Auth token: the ES256 JWT
///      InsumerAPI returns from `POST /v1/attest` with `"format": "jwt"`.
///      `hasAccess` takes the compact token bytes as `data`, verifies the
///      signature on-chain, and reads every claim it acts on from the
///      signed payload itself (see `InsumerAttestationToken`):
///        sub            the wallet the condition evaluated (== account)
///        pass           the issuer's verdict (must be true)
///        conditionHash  the evaluated condition (must be the pinned one)
///        exp            expiry (must be later than block.timestamp)
///      Nothing is taken from the caller beside the token, so the caller
///      cannot pair a genuine signature with claims the issuer did not make.
///
/// @dev Deploying
///      ----------------------------------------------------------------
///      Deploy only on a chain that provides the `P256VERIFY` precompile at
///      `0x0100`; without it every token is denied.
///
///      One deployment gates one condition, and a token carries exactly one
///      condition hash. The ERC-8257 reference `CompositePredicate` cannot
///      combine several of these predicates: it forwards the same `data` to
///      every term and gives each term 50,000 gas, below what one token
///      check costs.
///
///      Pin a condition on an EVM chain. A token's `sub` names the wallet
///      the condition evaluated, and `account` is an EVM address, so a
///      condition on a non-EVM chain can never be satisfied here.
///
///      Pin the `conditionHash` your own API key returns. A v1 key and a
///      v2 key can hash the same condition differently (a `token_balance`
///      condition does, an `nft_ownership` condition does not), so a
///      deployment serves the key era whose hash it pins. The hash covers
///      the condition exactly as written, including the letter case of a
///      contract address, so an agent must send the same condition object
///      to obtain a token that matches. Conditions that include the wallet
///      itself (`erc8004_agent`, `erc7710_delegation`) hash to a value that
///      gates exactly one wallet.
///
///      The pinned hash cannot be reversed into the condition. Publish the
///      exact condition object, as it must be sent to `/v1/attest`, in the
///      tool's ERC-8257 manifest so agents know what to request.
///
/// @dev What the token proves
///      ----------------------------------------------------------------
///      The token is a signed public statement about a wallet's state, not
///      a secret: it carries no audience, and anyone holding it can present
///      it until `exp` (30 minutes after issuance, 5 when the request
///      includes an `erc7710_delegation` condition). It proves the state of
///      `account`, not that the caller controls `account`. ERC-8257
///      §"Account Parameter Is Advisory" applies: downstream enforcers MUST
///      bind `account` to the real principal independently, for example
///      with the requester-signed AccessProof pattern. The same verdict can
///      be encoded as more than one valid token string (ECDSA signatures
///      admit a high-s twin), so a consumer tracking replay keys on the
///      token's `jti` claim (read from the payload off-chain), not on its
///      bytes.
///
/// @dev Why this shape rather than direct on-chain reads
///      ----------------------------------------------------------------
///      Predicates that read holdings on-chain (ERC-721, ERC-1155,
///      subscription) see only the chain the registry is deployed on. An
///      issuer-signed verdict lets a registry on one chain gate on wallet
///      state held on another, evaluated off-chain and verified here.
///
/// @dev Gas budget
///      ----------------------------------------------------------------
///      About 130,000 gas for a typical single-condition token, and under
///      200,000 up to the 64 KB token limit, including for malformed input.
///      The reference registry calls `hasAccess` with 200,000 gas.
///
/// @dev GETTING CREDENTIALS
///      ----------------------------------------------------------------
///      Free tier, no credit card: 100 daily reads + 10 attestation credits.
///
///      Developers (email-based):
///        POST https://api.insumermodel.com/v1/keys/create
///        body: {"email":"YOUR_EMAIL","appName":"erc8257-predicate","tier":"free"}
///
///      Agents (wallet-based, no email):
///        POST https://api.insumermodel.com/v1/keys/buy
///        body: {"txHash":"0x...","chainId":8453,"amount":5,"appName":"my-agent",
///               "senderSignature":"0x..."}
///        Agent sends USDC to the platform wallet, then POSTs the tx hash
///        with its signature over the text the API returns (a call without
///        it answers 400 with that text); the wallet that paid is the
///        identity. USDC only. Minimum 5 USDC; credits scale with amount.
///
///      Once the key is provisioned, fetch a signed attestation as a token:
///        POST https://api.insumermodel.com/v1/attest
///        headers: {"X-API-Key": "<your_key>"}
///        body: {"wallet": "0x...", "format": "jwt", "conditions": [{
///               "type":"token_balance", "contractAddress":"0x...",
///               "chainId": 1, "threshold": "1", "label": "USDC >= 1"}]}
///
///      Pass `bytes(response.data.jwt)` to
///      `IToolRegistry.hasAccess(toolId, account, data)` unchanged.
///
///      API reference:        https://insumermodel.com/developers/api-reference/
///      JWKS:                 https://api.insumermodel.com/.well-known/jwks.json
///      Verification library: npm install insumer-verify
///
/// @custom:audit status=unaudited
contract InsumerAccessPredicate is IAccessPredicate, IERC165 {
    /// @dev InsumerAPI ECDSA P-256 public-key X coordinate.
    ///      Source: https://api.insumermodel.com/.well-known/jwks.json
    uint256 public immutable pubKeyX;

    /// @dev InsumerAPI ECDSA P-256 public-key Y coordinate.
    uint256 public immutable pubKeyY;

    /// @dev The condition this predicate enforces: the 32-byte SHA-256
    ///      `conditionHash` InsumerAPI returns for it. Pinned at construction.
    bytes32 public immutable expectedConditionHash;

    /// @dev URI advertised in `getRequirements` so agents can locate the
    ///      issuer's public-key set.
    string public issuerJWKSURI;

    /// @param _pubKeyX                X coordinate of the InsumerAPI P-256 key.
    /// @param _pubKeyY                Y coordinate of the InsumerAPI P-256 key.
    /// @param _expectedConditionHash  The condition's `conditionHash` exactly as
    ///                                the API returns it (`0x` + 64 hex digits),
    ///                                as a `bytes32`.
    /// @param _issuerJWKSURI          HTTPS URL to the issuer's JWKS document.
    constructor(
        uint256 _pubKeyX,
        uint256 _pubKeyY,
        bytes32 _expectedConditionHash,
        string memory _issuerJWKSURI
    ) {
        pubKeyX = _pubKeyX;
        pubKeyY = _pubKeyY;
        expectedConditionHash = _expectedConditionHash;
        issuerJWKSURI = _issuerJWKSURI;
    }

    /// @inheritdoc IAccessPredicate
    /// @dev Returns `false` on any verification failure rather than
    ///      reverting, so `IToolRegistry.tryHasAccess` distinguishes a
    ///      clean denial `(true, false)` from a predicate malfunction
    ///      `(false, false)` per ERC-8257 §"Predicate Reverting".
    ///
    /// @param account  Address being checked; must equal the token's `sub`.
    /// @param data     The compact JWT, as ASCII bytes.
    function hasAccess(
        uint256 /* toolId */,
        address account,
        bytes calldata data
    ) external view override returns (bool) {
        (bool ok, InsumerAttestationToken.Claims memory c) = InsumerAttestationToken.read(data, pubKeyX, pubKeyY);
        return ok
            && c.pass
            && c.sub == account
            && c.conditionHash == expectedConditionHash
            && c.exp > block.timestamp;
    }

    /// @inheritdoc IAccessPredicate
    function name() external pure override returns (string memory) {
        return "InsumerAccessPredicate";
    }

    /// @inheritdoc IAccessPredicate
    function getRequirements(uint256 /* toolId */)
        external
        view
        override
        returns (AccessRequirement[] memory requirements, RequirementLogic logic)
    {
        requirements = new AccessRequirement[](1);
        requirements[0] = AccessRequirement({
            kind: type(IWalletStateAttestation).interfaceId,
            data: abi.encode(issuerJWKSURI, expectedConditionHash),
            label: "InsumerAPI signed wallet-state attestation"
        });
        logic = RequirementLogic.AND;
    }

    /// @inheritdoc IERC165
    /// @dev MUST advertise both `IERC165` and `IAccessPredicate` so that
    ///      registration validation per ERC-8257 §"Predicate Validation
    ///      at Registration" accepts the predicate.
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(IAccessPredicate).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }
}
