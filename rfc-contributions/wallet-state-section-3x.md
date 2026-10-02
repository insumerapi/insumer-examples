# Section 3.x — `wallet_state` as the Payment-Enforcement Category

**Target:** [A2A discussion #1734 — Composable Trust Evidence Format for Multi-Provider Agent Attestations](https://github.com/a2aproject/A2A/discussions/1734), v0.2 draft.

**Contributor:** Douglas Borthwick (InsumerAPI), drafting at @kenneives's and @AlexanderLawson17's invitation.

**Status:** Proposed 9th provider category, parallel in shape to `compliance_risk` (Alexander Lawson, Revettr) and `transactional` / `sovereignty` (Erik Newton, Verascore).

**Updated 2026-10-01:** the trust-profile figures below (check counts, dimension list, the `conditionSetVersion` example) were refreshed to the condition set live since 2026-10-01: 145 base checks across 27 chains in 9 dimensions, up to 166 across 29 in 13, and `conditionSetVersion` now a dated set id (`"2026-10"`) on every key version. The argument is unchanged; the figures as originally posted are in the git history of this file.

---

## Proposing `wallet_state` as the 9th Provider Category

@kenneives, @eriknewton, @AlexanderLawson17 — thanks for the invitation to draft. The v0.2 taxonomy now covers code safety, runtime behavior, continuous monitoring, identity, peer signals, transactional history, sovereignty posture, and regulatory compliance. That is a strong foundation for gating non-payment decisions: code-review gating, tool-call approval, content access, reputation-weighted routing.

There is one gap that becomes obvious the moment the same envelope is used to gate payment-class actions: none of the eight categories answer the on-chain solvency question. I want to propose `wallet_state` as a distinct ninth category and walk through why it does not fold into the existing types.

## Why `wallet_state` is distinct

| Category | What it answers | What it does NOT answer |
|---|---|---|
| `static_analysis` | Is the code safe to run? | Can this wallet actually pay, at this block, on this chain? |
| `behavioral` | Does the agent act within bounds at runtime? | Does its controlling wallet hold the asset it is committing to settle in? |
| `continuous_monitoring` | Is the agent still behaving over time? | Has the wallet's position changed between quote and execution? |
| `identity` | Who is the agent? | Does the wallet bound to that identity actually hold the threshold? |
| `peer_review` | Do other agents vouch for it? | Peer trust says nothing about on-chain position. |
| `transactional` | Has it paid and been paid reliably? | Clean payment history does not equal current solvency at block N. |
| `sovereignty` | Where does the agent run, who controls it? | Sovereignty posture is orthogonal to what the controlled wallet holds. |
| `compliance_risk` | Is the wallet legally allowed to transact? | Legal clearance does not equal ability to pay. |

`wallet_state` answers: **At a specific block on a specific chain, does this wallet satisfy a set of caller-supplied conditions over its on-chain state — and can a verifier prove that offline against a JWKS-published public key, without trusting the issuer or re-querying the chain?**

Alexander made the clearest version of this point in the thread: *"a compliance_risk clear tells a gateway the wallet is legally allowed to transact, but not whether it has the funds to do so at block N across every chain it holds assets on. Two different signals, two different category homes."* `wallet_state` is the category home for the second signal.

### Definition

> `wallet_state`: Attestations derived from direct evaluation of on-chain state — token balances, NFT ownership, staking positions, governance holdings, protocol-specific state — against caller-supplied conditions, at a specific block, on one or more supported chains. Each result includes the block number and timestamp at which the chain was read, a canonical hash of the evaluated condition for tamper detection, and a per-condition boolean outcome. The signed payload is wallet-bound: the wallet address is committed inside signature scope, so a verifier holding only the signed bytes can prove "this wallet satisfied this condition at this block" without trusting the issuer.

Signal types that fall under this category:

- **Token balance evaluation** — ERC-20, SPL, and equivalent balance thresholds against caller-supplied operators (`gt`, `gte`, `eq`, `lt`, `lte`).
- **NFT ownership** — ERC-721 and ERC-1155 ownership checks, including contract-scoped and token-id-scoped conditions.
- **Governance holdings** — governance token positions, delegation state, voting power snapshots.
- **Staking positions** — LSD holdings, locked stake, unbonding state.
- **Protocol-specific state** — position health in lending protocols, concentrated liquidity positions, perp exposure — anything exposed through a standardized read call that returns a boolean outcome against a caller-supplied threshold.

The common shape across all of these: a read from an on-chain source, an evaluation against a caller-supplied condition, and a signed boolean that commits to the block number the read was taken from.

## Sample attestation envelope

Following the envelope format from @kenneives's RFC, with a real signed payload fetched live from `https://api.insumermodel.com/v1/attest` against Vitalik's wallet at block `0x17b37a4` on Ethereum. It was issued on 2026-04-10 under the legacy `insumer-attest-v1` kid, which is why `threshold` is a number and `decimals` is echoed; a key issued today signs under `insumer-attest-v2`, echoes `threshold` as a decimal string, and omits `decimals`:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": "TrustAttestation",
  "version": "1.0.0",
  "provider": {
    "id": "https://api.insumermodel.com",
    "category": "wallet_state"
  },
  "subject": {
    "id": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
  },
  "attestation": {
    "type": "WalletStateAttestation",
    "confidence": 1.0,
    "payload": {
      "iss": "https://api.insumermodel.com",
      "sub": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      "jti": "ATST-6295DA4F61C1FEB8",
      "iat": 1775861027,
      "exp": 1775862827,
      "pass": true,
      "conditionHash": [
        "0xc938b71ac78df5843d6823dd78ee0a5b64dd56fa850984e954dd070285169444"
      ],
      "blockNumber": "0x17b37a4",
      "blockTimestamp": "2026-04-10T22:43:35.000Z",
      "results": [
        {
          "condition": 0,
          "label": "USDC on Ethereum",
          "type": "token_balance",
          "chainId": 1,
          "met": true,
          "evaluatedCondition": {
            "type": "token_balance",
            "chainId": 1,
            "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "operator": "gte",
            "threshold": 1,
            "decimals": 6
          },
          "conditionHash": "0xc938b71ac78df5843d6823dd78ee0a5b64dd56fa850984e954dd070285169444",
          "blockNumber": "0x17b37a4",
          "blockTimestamp": "2026-04-10T22:43:35.000Z"
        }
      ]
    }
  },
  "refresh_hint": {
    "strategy": "block_bound",
    "bound_block_number": "0x17b37a4",
    "bound_chain_id": 1,
    "max_age_seconds": 1800
  },
  "jws": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imluc3VtZXItYXR0ZXN0LXYxIn0..."
}
```

Anyone can pull and verify a live one:

```bash
# Get a free key (returns the key immediately, no credit card)
curl -X POST https://api.insumermodel.com/v1/keys/create \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","appName":"my-app","tier":"free"}'

# Pull the JWKS
curl -s https://insumermodel.com/.well-known/jwks.json

# Profile a wallet across the default curated condition set (9 dimensions,
# 145 base checks at time of writing: stablecoins, governance, NFTs, staking,
# institutional stablecoins, tokenized treasuries, stablecoin deposits,
# wrapped bitcoin, names; up to 166 checks in 13 dimensions with the optional
# Solana, XRPL, Bitcoin and Tron wallets)
curl -s -X POST https://api.insumermodel.com/v1/trust \
  -H "Content-Type: application/json" \
  -H "x-api-key: $KEY" \
  -d '{"wallet":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"}'

# Or evaluate caller-supplied conditions and get a compact JWS
curl -s -X POST https://api.insumermodel.com/v1/attest \
  -H "Content-Type: application/json" \
  -H "x-api-key: $KEY" \
  -d '{
    "wallet":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    "format":"jwt",
    "conditions":[
      {"label":"USDC on Ethereum","type":"token_balance","chainId":1,
       "contractAddress":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
       "threshold":"1"}
    ]
  }'
```

ES256 (P-256), JWKS at the standard path, with the signing key selected by the `kid` on the response — `insumer-attest-v2` for `/v1/attest` and `insumer-trust-v2` for `/v1/trust` on any key issued since 2026-06-10, `insumer-attest-v1` for keys created before it. The `POST /v1/trust` endpoint returns a P1363 base64 signature (88 base64 characters, 64 raw bytes) over the preimage its `kid` selects: under `insumer-trust-v2`, the domain tag `insumer.trust.v2`, a newline, then the canonical JSON of the `trust` object (keys sorted recursively, no whitespace); under the legacy `insumer-attest-v1`, `JSON.stringify(trust)` as issued. Every attest and trust response also carries a post-quantum companion signature (`pqSig`, `pqKid`; ML-DSA-65) over the same preimage, verifiable against the same JWKS. The `POST /v1/attest` endpoint returns both the raw signature and a compact JWS in the `jwt` field, with the header `{"alg":"ES256","typ":"JWT","kid":"insumer-attest-v2"}` and claims `pass`, `conditionHash[]`, `blockNumber`, `blockTimestamp`, `results[]`, `iss`, `sub`, `jti`, `iat`, `exp`. The `sub` claim is the wallet address — that is how the category stays wallet-bound inside signature scope.

## TTL semantics for `wallet_state`

This is where `wallet_state` behaves differently from the other categories. On-chain state is the most time-sensitive dimension in the taxonomy after `compliance_risk`: a wallet can move its position between the block when the attestation was signed and the block when the gateway evaluates it. A pure time-based TTL is a blunt instrument for this — what actually matters is whether the bound block is still the head of the chain, or at least recent enough for the consumer's block-depth tolerance.

Proposing a hybrid model that fits Erik's `refresh_hint` framework:

| Parameter | Value | Rationale |
|---|---|---|
| `ttl` | 1800 (30 min) | The current InsumerAPI default. Long enough for a multi-step agent flow to complete, short enough that head movement on most chains caps consumer risk. |
| `refresh_hint.strategy` | `"block_bound"` | The authoritative freshness signal is not wall-clock TTL — it is whether the bound block is still acceptable to the consumer. |
| `refresh_hint.bound_block_number` | `"0x..."` | The specific block the read was taken from, committed inside signature scope. |
| `refresh_hint.bound_chain_id` | integer | The chain ID the block number is meaningful on. Required for multi-chain attestations — a single envelope may bind multiple blocks across multiple chains. |
| `refresh_hint.max_age_seconds` | 1800 | Hard ceiling. No `wallet_state` attestation should be trusted beyond 30 minutes without refresh, even if the bound block is still within the consumer's depth tolerance. |
| `stale_action` | `"hard_fail"` | Default fail-closed. For payment-enforcement consumers this is the safe default — concede on Alexander's same-argument reasoning for `compliance_risk`. Configurable per deployment. |

For multi-chain attestations (the `POST /v1/trust` endpoint returns a single envelope containing per-condition `blockNumber` and `chainId` for each of the 145 base checks at time of writing), the `refresh_hint.bound_block_number` and `bound_chain_id` become arrays indexed by condition — or, cleaner, the whole `refresh_hint` is per-result rather than per-envelope. I think per-result is the right shape but want to discuss it.

The 30-minute `max_age` is not a negotiable lower bound for `wallet_state`. A consumer that wants a 5-minute refresh cycle should just re-query rather than ask the provider to emit shorter-lived signatures — the cryptographic cost dominates, and the provider already has the block number in signature scope so the consumer can always reason about staleness directly.

## Verdict TTL cascading

The rule in @kenneives's draft (*"A verdict MUST expire before any attestation in its evidence bundle expires"*) applies with teeth here. A gateway that includes a `wallet_state` attestation in its evidence bundle inherits the shortest TTL of any attestation in that bundle. If a `wallet_state` signal expires at t+30min and the gateway issues a verdict at t+0, the verdict cannot live past t+30min regardless of other attestation TTLs — and for payment-class verdicts, the consumer should probably cap at t+5min anyway, leaving 25 minutes of margin for the rest of the flow.

For the payment-enforcement subset specifically, I would add a stronger guidance to Section 6: when the evidence bundle contains both `compliance_risk` and `wallet_state`, the verdict TTL SHOULD be the minimum of the two, and the verdict body SHOULD quote both bound timestamps (compliance list publication time, on-chain block time) so downstream auditors can reconstruct the state at decision time.

## InsumerAPI as reference implementation

InsumerAPI is live and can serve as a reference implementation for the `wallet_state` category.

| Field | Value |
|---|---|
| Issuer URI | `https://api.insumermodel.com` |
| DID | `did:web:insumermodel.com` |
| JWKS | `https://insumermodel.com/.well-known/jwks.json` |
| Algorithm | ES256 (P-256) |
| Key ID | `insumer-attest-v2` (attest) / `insumer-trust-v2` (trust) / `insumer-attest-v1` (pre-2026-06-10 keys) |
| Free key endpoint | `POST https://api.insumermodel.com/v1/keys/create` — returns the key immediately, no credit card |
| Per-condition attestation | `POST https://api.insumermodel.com/v1/attest` — caller-supplied conditions, returns raw sig + compact JWS |
| Curated wallet profile | `POST https://api.insumermodel.com/v1/trust` — EVM wallet, 9 dimensions (stablecoins, governance, NFTs, staking, institutional stablecoins, tokenized treasuries, stablecoin deposits, wrapped bitcoin, names), 145 base checks at time of writing; up to 166 checks in 13 dimensions with optional Solana, XRPL, Bitcoin and Tron wallets |
| Signed payload scope | `wallet` is committed inside the signed bytes (`sub` claim for JWT, `wallet` field for `POST /v1/trust`) |
| Chain coverage | 37 chains — 31 EVM (including Ethereum, Base, Arbitrum, Optimism, Polygon, BNB, Avalanche, XDC, Linea, Scroll, zkSync, Celo, Gnosis, and others) + Solana + XRPL + Bitcoin + Tron + Stellar + Sui |
| Signature format | P1363 base64 (64 bytes) for raw signatures, or compact JWS when `format: "jwt"` is requested on `/v1/attest` |
| Condition tamper detection | Each result includes a `conditionHash` = SHA-256 of the canonical (sorted-key) evaluated condition JSON — consumers that submitted conditions can recompute and compare |
| Privacy | Attestations expose boolean `met: true/false` per condition, never the underlying balance — threshold satisfaction, not position disclosure |

InsumerAPI has been running in production for 37-chain wallet state evaluation since before this spec was drafted. It is already the foundation layer in `MULTI-ATTESTATION-SPEC.md` (issue [`insumerapi/insumer-examples#1`](https://github.com/insumerapi/insumer-examples/issues/1)), underneath nine specialized dimensions including three that are already reference implementations in the RFC (AgentGraph, RNWY, AgentID). The foundation shape is: `wallet_state` answers "what does this wallet hold and do on-chain," and the specialized dimensions answer adjacent questions on top of that foundation.

## Weighing in on the open questions

### Attestation chaining

From a `wallet_state` perspective, chaining is valuable but not essential for v1. When a consumer requests a follow-up attestation against a previous one — e.g., "the same conditions as last time, re-evaluated at head" — a single back-pointer (`prior_attestation_id`) lets the gateway diff the two envelopes and detect state changes without re-submitting the full condition set.

Agreed with @eriknewton that a single back-pointer is sufficient for v1. Full DAG traversal is overkill. For `wallet_state`, the interesting diff semantics are:

```json
{
  "prior_attestation_id": "ATST-BCB27849413440C7",
  "prior_bound_block_number": "0x17b3000",
  "prior_bound_chain_id": 1,
  "state_change": "none"
}
```

`state_change: "none"` means the new envelope passed the same `pass: true/false` outcome at the new block. This lets consumers cheaply check "is the condition still satisfied" without re-submitting the whole condition set, and is useful for long-running multi-step payment flows.

### Revocation

For `wallet_state` specifically, pre-expiry revocation is rare in practice but should still be supported via the same two-tier approach Alexander proposed for `compliance_risk`:

1. **v1**: providers expose `GET /.well-known/revocations.json` listing revoked attestation IDs with timestamps. Gateways poll on short intervals (5 min) or on cache miss. The primary revocation case for `wallet_state` is a provider-side bug where a wrong condition was evaluated against the right wallet — this is rare but has to be addressable.
2. **v2**: event-driven push for high-stakes categories. `wallet_state` is not high-stakes in the same sense as `compliance_risk` or `sovereignty` — there is no urgent harm from a stale `pass: true` because the bound block is inside signature scope and consumers can always re-evaluate themselves. v1 revocation list is sufficient.

The 30-minute `max_age` backstop is already doing most of the work for `wallet_state` that the `max_age` in `compliance_risk` does for sanctions hits.

### Encrypted payloads

`wallet_state` is mechanically privacy-preserving by design: the signed payload exposes per-condition booleans, not balances. A consumer learns whether a threshold was satisfied, not how much the wallet holds. That means the standard `wallet_state` envelope does not need encrypted payloads for the most common use case.

There is one edge case worth flagging: the `evaluatedCondition` object inside each result contains the evaluated condition parameters (`contractAddress`, `threshold`, the `operator` applied, etc.). In most cases these are public — USDC on Base is USDC on Base. But in some cases the condition itself is policy-sensitive (a private gating threshold a merchant does not want to broadcast). For those cases, the optional `encrypted_evidence` field that Erik proposed for `sovereignty` is sufficient — the outer envelope (category, confidence, bound block, JWS) stays public, and the `evaluatedCondition` block can be encrypted with the gateway's public key from its JWKS endpoint. No schema change needed; the existing `encrypted_evidence` slot covers it.

### Schema versioning

Agreed with @eriknewton's `envelope_version: "1.0.0"` proposal at the top level with semver, and providers committing to supporting at least N and N-1 major versions during a 6-month deprecation window. For `wallet_state` specifically, there is one additional versioning axis worth naming: the **condition set version** for curated wallet profiles (`POST /v1/trust` style endpoints). InsumerAPI already emits `conditionSetVersion` as a signed field: a dated set id (`"2026-10"` at time of writing), the same on every key version, that names the check list run; readers log it and must not reject on it. When a curated set changes (new chain added, new dimension added, operator semantics tweaked), a signed version field of this kind is what lets a consumer that pinned one version explicitly decide whether to accept another. This is cleaner than conflating condition set evolution with envelope schema evolution.

Suggest the RFC allow providers to include an optional `provider_schema_version` field alongside the top-level `envelope_version` for exactly this case. Other categories may or may not need it; `wallet_state` definitely does.

## Summary

Adding `wallet_state` as the 9th category closes the payment-enforcement gap. The existing eight categories collectively tell you whether an agent is well built, well behaved, properly identified, historically reliable, regulatorily clean, and operating under known sovereignty posture. None of them tell you whether the wallet bound to that agent can actually pay, at this block, across every chain it might hold assets on, verified against an independent signed source. That is the role `wallet_state` fills.

InsumerAPI has live endpoints, verified JWKS, compact JWS output, an attestation envelope that already matches the RFC's structure, a 37-chain signed foundation, and existing wallet-bound semantics (the wallet lives inside signature scope via the `sub` claim on JWT or the top-level `wallet` field on `/v1/trust`). Happy to tune fields during the v0.2 review and test interoperability with other providers. Happy to draft the formal Section 3.9 (`wallet_state`) addition for the v0.2 source alongside Alexander's Section 3.8 (`compliance_risk`) if that helps land both categories in the same draft.

On the v1.0 venue move to a neutral `trust-evidence-format` org: appreciate the heads-up Alexander already offered on the other comment and happy to coordinate jointly with @kenneives, @eriknewton, and @AlexanderLawson17 so every reference implementation lands with commit rights from day one. Standing by.
