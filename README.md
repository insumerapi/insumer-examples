# InsumerAPI Examples

Condition-based access infrastructure for 37 blockchains. Send a wallet and conditions, get a signed boolean. No secrets, no identity, no static credentials.

## Try It (no key needed)

```bash
curl -s https://api.insumermodel.com/v1/compliance/templates | python3 -m json.tool
```

That's a live API response. No auth required. Now get a free key and verify a wallet:

```bash
curl -s -X POST https://api.insumermodel.com/v1/keys/create \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "appName": "my-app", "tier": "free"}'
```

Free tier: **10 free verifications plus 100 requests a day**. Or run the quickstart: it generates a key and makes a call in one step:

```bash
bash quickstart.sh
```

Prefer no key at all? `/v1/attest` also speaks **x402 pay-per-call** — see [Three Ways to Authenticate](#three-ways-to-authenticate).

## Verify a Wallet

```bash
curl -s -X POST https://api.insumermodel.com/v1/attest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "wallet": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    "conditions": [
      {
        "type": "token_balance",
        "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "chainId": 1,
        "threshold": "100",
        "label": "USDC >= 100 on Ethereum"
      }
    ]
  }'
```

Response — signed boolean, no balances exposed:

```json
{
  "ok": true,
  "data": {
    "attestation": {
      "id": "ATST-881391A0EB4520C4",
      "pass": false,
      "results": [
        {
          "condition": 0,
          "label": "USDC >= 100 on Ethereum",
          "type": "token_balance",
          "chainId": 1,
          "met": false,
          "evaluatedCondition": {
            "type": "token_balance",
            "chainId": 1,
            "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "operator": "gte",
            "threshold": "100"
          },
          "conditionHash": "0x42e5e627bf7ccb39eef4319e6d0c07d4d48918eb89727905a2087e68c52d95d3",
          "blockNumber": "0x18f0322",
          "blockTimestamp": "2026-10-08T19:07:35.000Z"
        }
      ],
      "passCount": 0,
      "failCount": 1,
      "attestedAt": "2026-10-08T19:07:44.174Z",
      "expiresAt": "2026-10-08T19:37:44.174Z"
    },
    "sig": "Xo/zSlKyzOvUDPe2kHN48FHr2X7Yz0eCJnTQqmyAWpi5bR90hxEjRH8RNbqqSn//oDJtZKyCIHWvIskz/1EZoQ==",
    "kid": "insumer-attest-v2",
    "pqSig": "f0Ga18TrdY5nLnynCGSz2ArIwZjML2S/lU/ijrgAtAW5tHePXML3fSAiY4nj029arSjUxkNddL2QYtqaMlme...",
    "pqKid": "insumer-attest-pq1"
  },
  "meta": {
    "version": "1.0",
    "timestamp": "2026-10-08T19:07:44.371Z",
    "creditsRemaining": 9,
    "creditsCharged": 1
  }
}
```

The result is signed twice: ES256 (`sig`, `kid`) and a post-quantum ML-DSA-65 signature (`pqSig`, `pqKid`; shortened above, about 4.4 KB of base64). Here the wallet held less than 100 USDC at that block, so the signed answer is `false`. Verify both signatures offline via JWKS: `https://api.insumermodel.com/v1/jwks`. The JWKS has five entries over two keys. Three ECDSA P-256 `kid` labels resolve to the same P-256 key: `insumer-attest-v1` (v1 attest and v1 trust), `insumer-attest-v2` (v2 attest), `insumer-trust-v2` (v2 trust). Two ML-DSA-65 post-quantum `kid` labels resolve to the same ML-DSA-65 key: `insumer-attest-pq1` and `insumer-trust-pq1`.

Note on key versions: every newly created key is **v2** — thresholds go in as decimal **strings** (`"100"`, not `100`; a JSON number is rejected with 400) and come back as canonical decimal strings, with no `decimals` field in the response. Older v1 keys keep the numeric format and the `insumer-attest-v1` kid.

## Three Ways to Authenticate

1. **API key** (default) — `X-API-Key` header. Free tier in one call via `POST /v1/keys/create`.
2. **x402 pay-per-call** (no key at all) — call `POST /v1/attest`, `/v1/trust`, or `/v1/trust/batch` with no credential headers and you get a 402 quote instead of a 401. The quote lists one accept per settlement network — USDC on Base, Polygon, Arbitrum, Arc, or Solana, same price on each. Pay the quoted amount on the network you choose, signing under the EIP-712 domain that entry's `extra` quotes (the token's name is `USD Coin` on Base, Polygon and Arbitrum, `USDC` on Arc), and retry with the `PAYMENT-SIGNATURE` header (`X-PAYMENT`, the v1 name, is still accepted). Gasless for the payer, zero signup — the fastest path for an autonomous agent. A `503` on the paid call is never a refusal: on Arc it can mean the settlement is still unresolved, so retry the exact same request with the SAME payment header (it cannot charge twice) and never sign a new authorization for it; the client does this. Dynamic pricing: $0.05–0.10 per attest, $0.15–0.30 per trust profile, $0.15–3.00 per batch. Runnable client: [x402-pay-per-call.js](x402-pay-per-call.js).
3. **Wallet-signed (SIWE)** — `Authorization: Wallet <base64(JSON({message, signature}))>` from a wallet that holds the Insumer Access pass (soulbound ERC-721 on Base, `0x3E2a408cc6eceba04FF9d04A5B8B05aBa8DD50ce`). Wallet-native keys with no email via `POST /v1/keys/buy`. Drop-in middleware: [`@skyemeta/access`](https://www.npmjs.com/package/@skyemeta/access) on npm.

## What Wallet Auth Covers

Ten condition types, mixable in a single call:

- **Token balances** (`token_balance`): Does this wallet hold at least X of token Y on chain Z?
- **NFT ownership** (`nft_ownership`): Does this wallet own an NFT from collection Y? 33 chains (31 EVM, Solana and XRPL), including XRPL NFTs with taxon filters
- **EAS attestations** (`eas_attestation`): Does this wallet hold an on-chain attestation matching a schema and attester? Pre-configured compliance templates via `GET /v1/compliance/templates`
- **Farcaster identity** (`farcaster_id`): Is this wallet a registered Farcaster identity?
- **Arbitrary view calls** (`evm_view_call`): Does `anyViewFunction(address)` on your contract return `true` for this wallet?
- **Ratio to amount** (`ratio_to_amount`): Does the wallet hold >= N times a reference amount? Self-scaling collateral checks — "hold 10x the transaction size"
- **Ratio to supply** (`ratio_to_supply`): Does the wallet hold >= a given fraction of an ERC-20's total supply?
- **ERC-8004 agent registration** (`erc8004_agent`): Is this wallet the owner or bound wallet of an agent in the ERC-8004 Identity Registry on Base? Honest semantics: registration is permissionless — the signed statement is registration and binding, not vetting or reputation
- **ERC-7710 delegation validity** (`erc7710_delegation`): Did a principal really authorize this agent wallet? Verifies the signed MetaMask Delegation Framework delegation — delegate match, declared delegator, EIP-712 signature (EOA or ERC-1271), on-chain revocation as of the anchored block, and recognized caveat enforcers. Delegation attestations expire in 5 minutes, keeping the verdict window tight
- **Account code** (`account_code`, any EVM chain): Is this wallet a plain key (`expect: "none"`), an EIP-7702-delegated key (`"eip7702"`, optionally to a named `delegate`), or a contract (`"contract"`)? Answered as `met` only; the code and the delegation target are never returned

Plus:

- **Multiple conditions**: Up to 10 conditions per call, across any mix of 37 chains
- **Cross-chain**: Ethereum, Base, Polygon, Arbitrum, Optimism, Avalanche, BNB Chain, XDC, Solana, XRPL, Bitcoin, Tron, Stellar, Sui, and 23 more EVM chains
- **Merkle storage proofs**: `proof: "merkle"` adds EIP-1186 storage proofs for trustless verification against block headers: token balance slots on 27 of 31 EVM chains (not available on ZKsync Era, Sei, Viction or XDC Network, nor on any non-EVM chain), account proofs for native balances and `account_code`, and delegation revocation slots (2 credits instead of 1)
- **Fact profiles**: 155 base checks across 27 chains in 10 dimensions, up to 176 across 29 chains in 14 with the optional wallets (`POST /v1/trust`); no score, no opinion, just cryptographically verifiable evidence organized by dimension. Every check is a presence check. The signed `conditionSetVersion` (currently `2026-10-08`) names the check list run; log it, never reject on it. Batch up to 10 wallets in one call via `POST /v1/trust/batch`

Every attest and trust response is signed twice: ES256 (ECDSA P-256) and a post-quantum ML-DSA-65 signature. Pass the wallet auth result to downstream systems as cryptographic proof without re-querying the chain.

**Who uses this:**
- **Token-gated content** — media platforms, newsletters, community access
- **Commerce** — wallet-based discounts and eligibility (WooCommerce, Shopify)
- **Compliance** — KYA (Know Your Agent) checks before DeFi interactions
- **DAO governance** — verify voting eligibility across chains
- **Agent cold-start signals** — wallet-state evidence as a baseline before behavioral history accrues for new AI agents
- **Agent authorization** — verify an agent's ERC-8004 registration and ERC-7710 delegation before honoring its requests

## Examples

| File | Language | What it does |
|------|----------|-------------|
| [quickstart.sh](quickstart.sh) | Bash | Generates a key and runs a wallet auth check — zero setup |
| [verify.js](verify.js) | Node.js | Express server with wallet auth for token-gated discounts |
| [verify.py](verify.py) | Python | On-chain verification with signature handling |
| [verify-xrpl.js](verify-xrpl.js) | Node.js | XRPL: XRP, RLUSD, USDC trust lines, NFTs, fact profiles |
| [verify-tron.js](verify-tron.js) | Node.js | Tron: native TRX, USDT-TRC20, fact profile with Tron dimension |
| [verify-stellar.js](verify-stellar.js) | Node.js | Stellar: native XLM, USDC trustline, BENJI trustline, fact profile |
| [verify-sui.js](verify-sui.js) | Node.js | Sui: native SUI, USDC, fact profile with Sui rows evaluated |
| [x402-condition-gate.js](x402-condition-gate.js) | Node.js | x402 endpoint that gates free access on the payer's wallet eligibility (incl. a self-scaling `ratio_to_amount` option, `?gate=ratio`: hold >= 10x the payment) |
| [x402-pay-per-call.js](x402-pay-per-call.js) | Node.js | Pays InsumerAPI per call via x402 — no API key: 402 quote → EIP-3009 USDC authorization on Base (or Polygon/Arbitrum/Arc via `X402_NETWORK`, e.g. `eip155:5042` for Arc) → `PAYMENT-SIGNATURE` → signed attestation + settlement receipt |
| [x402-pay-trust.js](x402-pay-trust.js) | Node.js | Same pay-per-call flow against the trust endpoints: one $0.15 settlement each on `POST /v1/trust` and `/v1/trust/batch`, with a mid-run USDC balance check that skips cleanly instead of failing at the facilitator |
| [agent-delegation-verify.js](agent-delegation-verify.js) | Node.js | Agent standing on Base: `erc8004_agent` registration check + `erc7710_delegation` validity — signs a real MetaMask Delegation Framework delegation; runs with an API key or keyless via x402 |

### XRPL

```bash
curl -s -X POST https://api.insumermodel.com/v1/attest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "xrplWallet": "rG1QQv2nh2gr7RCZ1P8YYcBUKCCN633jCn",
    "conditions": [
      {
        "type": "token_balance",
        "contractAddress": "native",
        "chainId": "xrpl",
        "threshold": "100",
        "label": "XRP >= 100"
      }
    ]
  }'
```

## On-Chain Reference Contracts

EVM Solidity contracts that consume InsumerAPI's off-chain signed attestations on-chain. The off-chain primitive issues a signed verdict over a wallet's condition set; these contracts verify the signature against the published JWKS via the `P256VERIFY` precompile (`0x0100`), then expose a verifiable result to a consumer surface. Same family across three ERC consumer specs: one primitive, three consumer interfaces.

Deploy on chains that provide `P256VERIFY` (RIP-7212 on L2s such as Base, Optimism, Arbitrum, Polygon, Scroll, ZKsync, Celo; EIP-7951 on L1). Issuer JWKS: `https://api.insumermodel.com/.well-known/jwks.json` (P-256 / ES256; the three ES256 `kid`s resolve to the same key, so the contracts verify against one set of coordinates regardless of signing scheme).

| File | Spec | Role |
|------|------|------|
| [InsumerAttestationToken.sol](InsumerAttestationToken.sol) | shared | Library the attestation contracts share. Takes the InsumerAPI attestation token (`POST /v1/attest` with `format: "jwt"`), verifies its P-256 signature on-chain and returns the wallet (`sub`), verdict (`pass`), `conditionHash` and expiry (`exp`) read from the signed payload itself. Decodes only the ends of the payload: about 130,000 gas for a typical token, and under the reference registry's 200,000-gas call up to the 64 KB token limit, malformed input included. |
| [InsumerWalletStateVerifier.sol](InsumerWalletStateVerifier.sol) | ERC-8183 | Implements `IWalletStateVerifier` for hook-based access gating. Returns `(true, validUntil)` for a passing, unexpired verdict keyed on `(wallet, conditionsHash)`, otherwise `(false, 0)`. Anchored mode: anyone submits an attestation token and every stored value is read from its signed payload, so the submitter is untrusted; a newer token replaces an older one, never the reverse. A trusted-relayer fallback remains for testnets only. |
| [InsumerTrustOracle.sol](InsumerTrustOracle.sol) | ERC-8183 | Implements `ITrustOracle` for fact-profile-based gating. Bridges `POST /v1/trust` output (`totalPassed / totalChecks`) into the `getTrustScore(address) → uint256` interface required by hooks. 30-minute freshness window matching the API's `expiresAt` TTL. The relayer is trusted to relay an honest score: the optional signature check shows the relayer holds a genuine issuer signature, not that the signature covers the score. |
| [InsumerKeeperHook.sol](InsumerKeeperHook.sol) | ERC-8191 | Implements `IKeeperHook` for recurring-payment cycle gating. `beforeKeep` takes the attestation token and passes only when its signed payload names the merchant, the subscription's condition and a passing, unexpired verdict, so the keeper cannot relay a verdict the issuer did not sign; an optional pinned caller limits the hooks to the subscription contract. Pattern 4.2 (Trust Gating) from the IKeeperHook companion spec. |
| [InsumerAccessPredicate.sol](InsumerAccessPredicate.sol) | ERC-8257 | Implements `IAccessPredicate` for agent tool registry access gating. Takes the attestation token as `data`, unchanged, and grants only when its signed payload names `account`, the pinned condition and a passing, unexpired verdict. Returns `false` (no revert) on failure so `tryHasAccess` cleanly distinguishes denial from malfunction. Advertises `IAccessPredicate` + `IERC165` for registration validation; pin one EVM condition per deployment. |
| [IWalletStateAttestation.sol](IWalletStateAttestation.sol) | ERC-8257 | Marker interface for the `AccessRequirement.kind` proposed on [ethereum-magicians #28457](https://ethereum-magicians.org/t/erc-8257-agent-tool-registry/28457/3). Selector `0x7a111640 = bytes4(keccak256("walletStateAttestation()"))`, verified non-colliding with the markers pinned in ERC-8257 and its reference implementation. Requirement data carries the issuer JWKS URI and the condition hash exactly as the issuer reports it; the proof is the issuer's compact JWT. |
| `*.t.sol` | tests | Foundry suites, 76 cases: 45 for the predicate, 16 for the wallet-state verifier, 10 for the keeper hook, 5 for the library. Real P-256 verification of four live production tokens, from both v1 and v2 keys, through the precompile; denial of the other signed message kinds tested (raw v1 and v2 attestations, the post-quantum key binding); claims spelled inside labels or nested objects never read as claims; expiry boundaries; canonical encoding; fuzzed no-revert on random and mutated input; and a clean result inside the reference registry's 200,000-gas call for long, proof-sized and malformed input. Run with `forge test` (requires `evm_version = "osaka"` in `foundry.toml` to activate the precompile in Foundry's local REVM). |

Architectural pattern across the attestation contracts: InsumerAPI signs off-chain, anyone supplies the signed token on-chain, and the contract verifies the P-256 signature against the immutable issuer pubkey and reads every value it acts on from the signed payload, then exposes the result to its consumer surface (hook / predicate). The trust oracle differs only in that its relayer computes the score. The off-chain primitive is the issuer; these contracts are the consumers.

## Agent SDKs

- **MCP Server** (Claude, Cursor, Windsurf): `npx -y mcp-server-insumer` — [npm](https://www.npmjs.com/package/mcp-server-insumer)
- **Hosted MCP** (no install, no key): connect by URL to `https://api.insumermodel.com/mcp` (MCP streamable HTTP) from ChatGPT, claude.ai or any hosted agent. Ten tools on a shared daily allowance: `insumer_attest`, `insumer_wallet_trust`, `insumer_batch_wallet_trust`, `insumer_compliance_templates`, `insumer_jwks`, `insumer_list_merchants`, `insumer_get_merchant`, `insumer_list_tokens`, `insumer_check_discount`, `insumer_validate_code`. No ACP/UCP discount issuance or merchant setup; for all 27 tools on your own key, use the npm server above.
- **LangChain** (Python agents): `pip install langchain-insumer` — [PyPI](https://pypi.org/project/langchain-insumer/)
- **GPT Actions**: Import the [OpenAPI spec](https://insumermodel.com/openapi.yaml) into any Custom GPT

## Submit to the Public Registry

Anyone with an API key can submit a token or NFT collection to the public Insumer registry — free, no credits charged. Submissions land as pending, go through human review, and appear in the registry (and the surfaces that read it) once approved. Idempotent per chain + address: re-submitting an existing asset returns the existing entry.

```bash
curl -s -X POST https://api.insumermodel.com/v1/registry/submit \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "name": "My Token",
    "assetType": "token",
    "symbol": "MYT",
    "contractAddress": "0x...",
    "chainId": 8453,
    "standard": "ERC-20",
    "logo": "https://example.com/logo.png"
  }'
```

`assetType` routes the submission: `"token"` (ERC-20, ERC-3643, SPL — `symbol` required) or `"nft"` (ERC-721/1155, incl. ERC-5192 soulbound). Omit it and it is inferred from `standard`. EVM uses `contractAddress`; Solana uses `mintAddress` with `chainId: "solana"`.

## Handling `rpc_failure` Errors

If the API cannot reach an upstream blockchain data source after retries, it returns HTTP 503 with `error.code: "rpc_failure"`. No attestation is signed, no credits are charged. This is a retryable error — wait 2-5 seconds and retry.

**Important:** `rpc_failure` is NOT a verification failure. Do not treat it as `pass: false`. It means the data source was temporarily unavailable and the API refused to sign an unverified result.

```javascript
const res = await fetch(`${API}/v1/attest`, { method: "POST", headers, body });
const result = await res.json();

if (res.status === 503 && result.error?.code === "rpc_failure") {
  // Retryable — data source temporarily unavailable
  console.log("Failed sources:", result.error.failedConditions);
  // Wait 2-5s and retry
}
```

## Supported Chains (37)

**EVM (31):** Ethereum (1), BNB Chain (56), Base (8453), Avalanche (43114), Polygon (137), Arbitrum (42161), Optimism (10), XDC (50), Chiliz (88888), Soneium (1868), Plume (98866), Sonic (146), Gnosis (100), Mantle (5000), Scroll (534352), Linea (59144), zkSync Era (324), Blast (81457), Taiko (167000), Ronin (2020), Celo (42220), Viction (88), opBNB (204), World Chain (480), Unichain (130), Ink (57073), Sei (1329), Berachain (80094), ApeChain (33139), Robinhood Chain (4663), Arc (5042)

**Non-EVM (6):** Solana (`chainId: "solana"`), XRPL (`chainId: "xrpl"` — native XRP, trust line tokens, NFTs), Bitcoin (`bitcoinWallet` — native BTC, P2PKH/P2SH/bech32/Taproot), Tron (`chainId: "tron"` — native TRX, TRC-20 incl. USDT-TRC20), Stellar (`chainId: "stellar"` — native XLM, classic trustlines incl. USDC and BENJI), Sui (`chainId: "sui"` — native SUI, Sui-native tokens incl. USDC)

## Pricing

| Tier | Daily Requests | Credits | Price |
|------|-------------|---------|-------|
| Free | 100/day | 10 | $0 |
| Pro | 10,000/day | 1,000/mo | $29/mo |
| Enterprise | 100,000/day | 5,000/mo | $99/mo |

Verification costs: 1 credit per attest (2 with `proof: "merkle"`), 3 per trust profile (6 with proof), 3 per wallet in a batch.

Beyond the card tiers:

- **x402 pay-per-call** — no key, no signup; USDC on Base, Polygon, Arbitrum, Arc, or Solana per call (see [Three Ways to Authenticate](#three-ways-to-authenticate))
- **Crypto credit top-ups** — `POST /v1/credits/buy` with USDC, USDT, or BTC; volume-priced from 25 credits/$1 ($5–99) up to 50 credits/$1 ($500+)
- **Prepaid crypto keys** — `POST /v1/keys/purchase`: 30-day Pro or Enterprise keys paid in USDC/USDT/BTC, no card
- **Wallet-native keys** — `POST /v1/keys/buy`: the sender wallet is the identity, no email needed

[Full pricing →](https://insumermodel.com/pricing/)

---

## Multi-Attestation Verification

Before an AI agent transacts, a relying party can verify twelve signed dimensions across ten independent issuers in a single pass:

| Dimension | Question | Issuer | Algorithm |
|-----------|----------|--------|-----------|
| **Wallet State** | "What does this wallet hold?" | [InsumerAPI](https://insumermodel.com) | ES256 |
| **Compliance Risk** | "Is this counterparty sanctioned?" | [Revettr](https://revettr.com) (OFAC / EU / UN screening) | ES256 |
| **Reasoning Integrity** | "Did this agent reason correctly?" | [ThoughtProof](https://thoughtproof.ai) | EdDSA |
| **Behavioral Trust** | "Is this agent legitimate?" | [RNWY](https://rnwy.com) (150K+ agents, dual-score) | ES256 |
| **Wallet Intelligence** | "What does RNWY know about the operator wallet itself?" | [RNWY](https://rnwy.com) (`rnwy-wallet-v1`, signalDepth + riskIntensity quadrant) | ES256 |
| **MCP-Server Trust** | "Is this MCP server capable and low-risk?" | [RNWY](https://rnwy.com) (`rnwy-mcp-v1`, quality + risk quadrant; server-subject) | ES256 |
| **Job Performance** | "Has this agent delivered before?" | [Maiat](https://app.maiat.io) | ES256 |
| **Passport Grade** | "How deeply is this agent's identity verified?" | [APS](https://github.com/aeoess/agent-passport-system) | EdDSA |
| **Trust Verification** | "How reliable is this agent's behavior?" | [AgentID](https://getagentid.dev) | EdDSA |
| **Security Posture** | "Is this agent's code secure?" | [AgentGraph](https://agentgraph.co) | EdDSA |
| **Settlement Witness** | "Was the task actually delivered?" | [SAR](https://defaultverifier.com) | EdDSA |
| **Cross-Chain Reputation** | "How many addresses across how many chains, and what's the consolidated reputation?" | [TrustLayer](https://api.thetrustlayer.xyz) (19 chains, 1,468 identity groups) | ES256 |

Each attestation is independently signed and verifiable offline via JWKS. No shared keys, no shared infrastructure.

### Add Your Attestation (Issuer #11+)

The envelope is open. If you sign a distinct dimension of agent or wallet trust, you can join the verification pass. Ten issuers live today; the reference verifier loads any number.

**Checklist (Harold/AgentID pattern, verified in ~30 min):**

1. **JWKS endpoint** at a stable HTTPS URL, RFC 7517 compliant (`kid`, `kty`, `crv`/`alg`, public key material).
2. **Sample JWT** posted on [issues/1](https://github.com/insumerapi/insumer-examples/issues/1) with all claims documented.
3. **Signature algorithm** declared — ES256 or EdDSA preferred (reference verifier supports both).
4. **One-line dimension** — the question your attestation answers (e.g. "What does this wallet hold?").

Post your JWKS URL + sample JWT on [issues/1](https://github.com/insumerapi/insumer-examples/issues/1) and tag @douglasborthwick-crypto. We run the verifier against your live signature, flag any issues, and add you to the spec + reference verifier on pass. No fee, no contract, no shared keys. Each issuer stays independent.

**Who uses this:**
- **Agent commerce** (x402, ERC-8183) — verify wallet + reasoning + behavior before an agent spends money
- **DeFi lending** — wallet state + behavioral trust + sybil analysis before extending credit
- **Autonomous agent platforms** — multi-dimensional trust check before high-stakes tool calls

| File | Description |
|------|-------------|
| [wallet-resolve.js](wallet-resolve.js) | Multi-attestation fetcher — calls InsumerAPI first (wallet-state foundation layer), then fans out to all configured providers in parallel; outputs a standard multi-attestation envelope compatible with `multi-attest-verify.js` |
| [multi-attest-verify.js](multi-attest-verify.js) | Verifies signatures from 12 signed dimensions across 10 independent issuers (ES256 + EdDSA) |
| [thoughtproof-verify-example.js](thoughtproof-verify-example.js) | ThoughtProof attestation walkthrough — JWKS fetch, EdDSA key import, live wallet-bound signature verification (`/v1/issuer/wallet/{wallet}`) |
| [x402-sar-integration.js](x402-sar-integration.js) | x402 SAR integration — attestation → payment → delivery proof → offline verification |
| [x402-sar-integration-settlementwitness.js](x402-sar-integration-settlementwitness.js) | SettlementWitness SAR integration — live endpoint, Ed25519 verification ([nutstrut](https://github.com/nutstrut)) |

Spec: [MULTI-ATTESTATION-SPEC.md](./MULTI-ATTESTATION-SPEC.md) | Blog: [Would You Trust Your Agent? KYA Is Real.](https://insumermodel.com/blog/multi-attestation-spec-five-shipped-wallet-binding.html) · [Multi-Issuer Verification (predecessor)](https://insumermodel.com/blog/multi-attestation-four-issuers-one-verification-pass.html) | Discussion: [insumer-examples#1](https://github.com/insumerapi/insumer-examples/issues/1)

---

## Agent-to-Agent Sessions (AgentTalk)

A SCIF for AI agents. Every agent in the room verifies the same on-chain conditions before information moves, like verifying clearance before entering a secure facility. Bilateral sessions, working groups, or town halls. No artificial cap on participants. Up to 10 composable conditions per channel across any mix of 37 chains.

```json
{
  "conditions": [
    { "type": "token_balance", "chainId": 1, "threshold": "1000000", "label": "USDC >= $1M on Ethereum" },
    { "type": "token_balance", "chainId": 137, "threshold": "500000", "label": "USDC >= $500K on Polygon" },
    { "type": "nft_ownership", "chainId": 1, "label": "Series 7 attestation NFT" },
    { "type": "nft_ownership", "chainId": 1, "label": "KYC credential" },
    { "type": "nft_ownership", "chainId": 8453, "label": "NDA attestation on Base" },
    { "type": "eas_attestation", "label": "Accredited investor (EAS)" }
  ],
  "capacity": 10,
  "autoStart": true
}
```

Six conditions, three chains, every agent in the room, all must pass. But this is only one configuration. One condition on one chain, or ten spanning all 37. Two agents or two hundred. The strength of the lock and the size of the room are at the creator's discretion.

Dynamic enforcement — lose a credential, get ejected on re-verify. Creator can kick. Agents can leave.

```bash
node agenttalk-example.js                          # bilateral (2 agents)
node agenttalk-example.js multiparty               # multi-party (3 agents, kick, leave)
DEMO_PRIVATE_KEY=0x... node agenttalk-example.js   # gate on a wallet you fund (real PASS)
```

By default the example generates fresh, throwaway keypairs and signs with them —
so it proves control end-to-end but the attestation honestly returns `pass:false`
(an empty wallet holds no USDC). Set `DEMO_PRIVATE_KEY` to a wallet you control
and fund to see a real PASS; the key is read only at runtime and never committed.

The flow:
0. **Prove control** — Before declaring or joining, each agent signs a one-time challenge with its wallet key. Holdings are public, so naming a wallet isn't enough — control of it is what grants entry.
1. **Declare** — Creator opens a channel with conditions + capacity. `autoStart: true` makes it live immediately.
2. **Join** — Agents prove control of their wallets and submit them. Each is attested on entry via InsumerAPI.
3. **Attest** — Every wallet verified — each agent gets an ECDSA-signed JWT.
4. **Session** — `sessionId` + `conditionsHash` bind all attestations together.
5. **Enforce** — Re-verify ejects agents who lose credentials. Creator can kick (`/kick`). Agents can leave (`/leave`) — each signed by the acting wallet.

**Built for regulated industries:**
- **Finance & Banking** — syndication rooms, counterparty qualification, collateral verification before term sheets
- **Legal** — privileged communication, M&A data rooms, expert network compliance
- **Intelligence & Defense** — multi-agency briefing rooms, clearance-equivalent credentials, ITAR compliance
- **Healthcare** — HIPAA-qualified data exchange, multi-site clinical trial coordination

| File | Description |
|------|-------------|
| [agenttalk-example.js](agenttalk-example.js) | Bilateral + multi-party flows: prove control → declare → join → verify → kick → leave |

AgentTalk is a [SkyeMeta](https://skyemeta.com) product, powered by InsumerAPI. | API: `https://skyemeta.com/api/agenttalk/` | Docs: [skyemeta.com/agenttalk](https://skyemeta.com/agenttalk/)

## Links

- [Developer docs](https://insumermodel.com/developers/)
- [API reference](https://insumermodel.com/developers/api-reference/)
- [OpenAPI 3.1 spec](https://insumermodel.com/openapi.yaml)
- [llms.txt](https://insumermodel.com/llms.txt)

## License

MIT
