# Multi-Attestation Payload Format

**Version:** 1.2
**Status:** Draft
**Date:** 2026-09-02
**Discussion:** [insumer-examples#1](https://github.com/insumerapi/insumer-examples/issues/1)
**Blog posts:** [Multi-Issuer Verification](https://insumermodel.com/blog/multi-attestation-four-issuers-one-verification-pass.html) · [Would You Trust Your Agent? KYA Is Real.](https://insumermodel.com/blog/multi-attestation-spec-five-shipped-wallet-binding.html)

---

## Abstract

The Multi-Attestation Payload Format defines a composable envelope for bundling independently signed attestations from multiple issuers into a single verifiable object. Each attestation is self-describing — it carries its own algorithm, key identifier, and JWKS discovery endpoint. No shared registry or coordination between issuers is required. A relying party selects attestations by `type`, fetches each issuer's public key via standard JWKS, and verifies signatures independently.

This format emerged from convergence across ten independent issuers contributing twelve signed dimensions: InsumerAPI (wallet state, the foundation layer, 37 chains), Revettr (compliance risk), ThoughtProof (reasoning integrity), RNWY (three dimensions: agent-level behavioral trust, operator-level wallet intelligence, AND MCP-server trust), Maiat (job performance), APS (passport grade), AgentID (trust verification), AgentGraph (security posture), SAR (settlement witness), and TrustLayer (cross-chain reputation, 19 chains). Each issuer publishes a JWKS endpoint and signs attestations using either ES256 or EdDSA. The payload format is algorithm-agnostic and supports both raw signatures (base64-encoded P1363) and compact JWS (JWT).

---

## 1. Payload Format

```json
{
  "v": 1,
  "attestations": [
    {
      "issuer": "https://api.insumermodel.com",
      "type": "wallet_state",
      "kid": "insumer-attest-v2",
      "alg": "ES256",
      "jwks": "https://insumermodel.com/.well-known/jwks.json",
      "signed": null,
      "sig": "<compact-jws>",
      "expiry": "2026-03-20T13:04:57.000Z"
    }
  ],
  "expired": []
}
```

### Root Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | integer | MUST | Payload format version. Currently `1`. Distinct from an issuer's signing-scheme version, which each attestation carries in its own `kid`. |
| `attestations` | array | MUST | Active, unexpired attestation entries. |
| `expired` | array | SHOULD | Attestation entries past their TTL. Separated from `attestations` so relying parties can distinguish stale data without re-checking expiry. |

### Attestation Entry

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuer` | string (URI) | MUST | Canonical issuer identifier. |
| `type` | string | MUST | Attestation type (see Section 2). Relying parties select entries by this field, not by position. |
| `kid` | string | MUST | Key ID for JWKS lookup. |
| `alg` | string | MUST | Signing algorithm. One of `ES256`, `EdDSA`. |
| `jwks` | string (URL) | MUST | Where this issuer publishes its keys. A discovery hint for relying parties enrolling the issuer, not the trust root: the verifying key comes from the key set the relying party holds or pins for `issuer` (Section 4, step 3), and this URL MUST match that pinned origin. |
| `signed` | object \| null | CONDITIONAL | The signed payload object. MUST be present when `sig` is a raw signature. When `sig` is a compact JWS the payload is embedded in the JWT and this field is not verified, so it MUST be `null`: an object carried alongside a JWS bears no signature, and a relying party that reads claims from it is reading unsigned data. A verifier MUST refuse such an entry as malformed rather than verify the JWS and report success, since a verifier that returns before examining `signed` reports a valid signature over an object the signature does not cover. Matching `signed` against the JWT payload instead is not a general alternative. The relationship between the two is issuer-specific: for some issuers the object is a subset of the JWS payload and the comparison is well defined, while for others the JWT is a different projection of the attestation and there is nothing to compare. Because this format requires no coordination between issuers, a verifier cannot know which convention applies to an entry it is handed, and a check that is meaningless for some issuers can only fall back to accepting them, which reinstates the problem. Rejection is the one rule that holds uniformly. Note for integrators: several issuers return the JWS and its decoded payload as separate fields of the same API response. Carry only the JWS into the entry and set `signed` to `null` — nothing is lost, since decoding the JWS recovers the object. An issuer whose signature covers anything other than the serialization of this object, a domain-separated preimage for example, MUST use the compact JWS form: the raw form verifies over `signed` itself and cannot represent such a signature. |
| `sig` | string | MUST | Either a base64-encoded raw signature (P1363 format for ES256, raw bytes for EdDSA) or a compact JWS string (three dot-separated base64url segments). |
| `expiry` | string (ISO 8601) | SHOULD | Expiration timestamp. If absent, relying parties SHOULD apply a default TTL of 30 minutes from `attestedAt` (or its snake_case spelling `attested_at`) / `iat` / `timestamp` in the signed payload. That fallback is unavailable on an entry whose `sig` is a compact JWS, where `signed` is necessarily `null` and there is no payload object beside the signature to read a timestamp from; a verifier reads the expiry claim inside the token instead, as section 4 step 1 describes. An entry in that form SHOULD still carry `expiry`, so that it can be judged by a relying party that does not decode the token, and because a token carrying no expiry claim of its own leaves nothing else to read. |

### Design Decisions

- **Insertion order is not significant.** Relying parties select attestations by `type`, never by array index.
- **`requiredTypes` belongs in verifier configuration, not in the payload.** The payload is a neutral bundle; policy is the relying party's concern.
- **Only verifiable entries appear in `attestations`.** Unsigned or unverifiable data MUST NOT be included.
- **Self-describing entries.** Each attestation carries its own `alg`, `kid`, and `jwks`. No shared key registry. The trust anchor is the key set the relying party holds for the issuer, selected by `kid`; the entry's `jwks` says where that set is published and MUST match the origin the relying party has pinned for `issuer`. A `kid` that resolves to no key in that set is a failure, not a reason to fetch another key.
- **Signature format is polymorphic, and the two forms are exclusive.** If `sig` contains exactly two dots, it is a compact JWS. Otherwise, it is a base64-encoded raw signature over `JSON.stringify(signed)`. An entry carries one form or the other, never both: a JWS with a non-null `signed` is malformed, because the object beside it is unsigned data in a field a relying party reads as attested.

### Reference Implementation Criteria

The issuer table in Section 2 is this spec's reference set. Participation in the discussion thread ([insumer-examples#1](https://github.com/insumerapi/insumer-examples/issues/1)) is open and is not by itself a reference — entries are added to the table only after meeting the criteria below.

To be added to the reference set, an implementation MUST:

1. **Publish a JWKS endpoint** at a stable URL, returning a JWK set containing the `kid` referenced in the attestation entry.
2. **Sign attestations end-to-end.** The `sig` field MUST verify against the public key published at the JWKS endpoint, over the canonical bytes of the signed payload — `header.payload` for compact JWS, or either insertion-order `JSON.stringify(signed)` or sorted-key (canonical) JSON for ES256 raw P1363 and EdDSA raw (the reference verifier accepts both for both algorithms).
3. **Be reproducible by a third-party verifier.** The reference verifier (`multi-attest-verify.js`) MUST resolve the JWKS, fetch a live attestation, and return a verified result with no issuer cooperation beyond the published endpoints.

When all three conditions hold against a live attestation, the implementation is added to the Section 2 table as a live issuer.

Schema reservations, aspirational commitments, or proposed attestation dimensions that have not shipped a live JWKS and a verifiable attestation are not in the reference set. They may be tracked elsewhere as future work.

---

## 2. Attestation Types

| Type | Issuer | Algorithm | Signature Format | Default TTL |
|------|--------|-----------|------------------|-------------|
| `wallet_state` | InsumerAPI | ES256 | base64 P1363 (or JWT when `format: "jwt"` requested) | 30 min |
| `compliance_risk` | Revettr | ES256 | compact JWS (JWT) | 1 hour |
| `reasoning_integrity` | ThoughtProof | EdDSA (Ed25519) | compact JWS (JWT) | per-issuer |
| `behavioral_trust` | RNWY | ES256 | base64 P1363 + compact JWS (kid `rnwy-trust-v2`, legacy `rnwy-trust-v1`) | 24 hours |
| `wallet_intelligence` | RNWY | ES256 | compact JWS (JWT, kid `rnwy-wallet-v1`) | 24 hours |
| `mcp_trust` | RNWY | ES256 | compact JWS (JWT, kid `rnwy-mcp-v1`) | 24 hours |
| `job_performance` | Maiat | ES256 | compact JWS (JWT) | 30 min |
| `passport_grade` | APS | EdDSA (Ed25519) | compact JWS (JWT) | per-issuer |
| `trust_verification` | AgentID | EdDSA (Ed25519) | compact JWS (JWT) | 1 hour |
| `security_posture` | AgentGraph | EdDSA (Ed25519) | compact JWS (JWT) | 24 hours |
| `settlement_witness` | SAR | EdDSA (Ed25519) | compact JWS (JWT, kid `sar-prod-ed25519-06` current; `-05`/`-03`/`-02`/`-01` legacy) | per-issuer |
| `cross_chain_reputation` | TrustLayer | ES256 | base64url P1363 over canonical (sorted-key) JSON | per-issuer |

---

## 2.5 Two Categories of Wallet Binding

An analytical split across the envelope worth naming because it clarifies how composition policies should weight signals. Both categories are cryptographically verifiable and both fit the envelope. They answer different questions, and neither is weaker than the other.

**Wallet-bound identity dimensions.** The signed JWS payload contains the wallet itself. A verifier holding only the signed bytes can prove "this specific wallet → this signal." The binding is cryptographic end-to-end.

| Dimension | Provider | Signed field |
|---|---|---|
| Wallet state (foundation, 37 chains) | InsumerAPI | `wallet` (EVM via `/v1/trust`) / JWT `sub` (non-EVM via `/v1/attest`) |
| Behavioral trust (agent) | RNWY v2 | `owner` |
| Wallet intelligence (operator) | RNWY `rnwy-wallet-v1` | `sub`, `wallet` |
| Job performance | Maiat | `sub`, `agent` |
| Compliance risk | Revettr | `sub` |
| Identity verification | AgentID v1.1.0 | `bound_addresses`, `solana_address`, `wallet_address` |
| Passport grade (governance) | APS `gateway-v1` | `wallet_ref[].address` (envelope JWS, gateway key) + `wallet_ref[].binding_sig` (per-entry, passport pubkey) |
| Settlement witness (new receipts) | SAR `sar-prod-ed25519-06`, profile `settlement-witness-verified-v0.2-counterparty-bound` | `counterparty` |
| Reasoning integrity (wallet-indexed) | ThoughtProof `tp-attestor-v1` | `wallet` (via `/v1/issuer/wallet/{wallet}`) |
| Cross-chain reputation | TrustLayer `trustlayer-signing-1` | `wallet` |

**APS has a two-layer binding model worth naming.** The `wallet_ref[]` array is inside the envelope-level Ed25519 JWS signed by the `gateway-v1` key, which proves "the APS gateway attested that this agent has these bound wallets at the named `bound_at` timestamps." Each entry additionally carries a per-wallet `binding_sig` — a separate Ed25519 signature over the canonical binding payload `{passport_id, chain, address, bound_at}` (via the reference `canonicalize()` algorithm), signed by the passport's own private key. The per-wallet signature verifies against the passport pubkey (published in a fixture for the canonical `aeoess-bound-demo` test passport, and in the passport object itself for production passports). Both layers verify offline and compose: the gateway layer says "our infrastructure observed this binding," and the passport layer says "the passport holder cryptographically claimed this binding themselves." Consumers can require either or both layers depending on their trust model.

**Wallet-discoverable content dimensions.** The signed JWS payload commits to what is being attested about (a repo, a task outcome, a delivery record). The wallet is a lookup key that discovers the relevant signed subject. A verifier holding only the signed bytes can prove "this repo scored 100" or "this task outcome matched spec" — but not "this wallet owns this repo." This is not a limitation; it is the correct architectural shape for dimensions that attest to things rather than identities.

| Dimension | Provider | Signed subject |
|---|---|---|
| Security posture | AgentGraph | `github:owner/repo` |
| MCP-server trust | RNWY (`rnwy-mcp-v1`) | `server` (`{owner}/{repo}`) |

Under the SAR `settlement-witness-verified-v0.2-counterparty-bound` receipt profile (kid `sar-prod-ed25519-06`), the `counterparty` field is inside signed bytes, placing `settlement_witness` in the wallet-bound category. Legacy receipts signed under kid `-02` or `-01` remain wallet-discoverable via the `/settlement-witness/receipts?wallet={address}` transport lookup.

**ThoughtProof ships both shapes.** Its original `reasoning_integrity` verdict (`POST /v1/verify`, `/v1/check`) commits to a `claim_hash` (SHA-256 of a natural-language reasoning claim); the wallet does not appear in those signed bytes, which is correct for attesting the soundness of a reasoning chain — a property of the action, not the actor. As of 2026-04-11, ThoughtProof also ships a wallet-indexed variant at `GET /v1/issuer/wallet/{wallet}` (no API key) returning a `wallet_reasoning_integrity/v1` envelope with the wallet inside the signed bytes alongside `verdict`, `score_normalized`, `confidence_bps`, and supporting evidence. `NOT_FOUND` envelopes are signed too, so consumers get a verifiable answer either way. That endpoint moves the reasoning-integrity signal into the wallet-bound category for wallet-indexed lookups — hence its row in the wallet-bound table above. See §3.2 for the wallet-indexed schema.

**RNWY's MCP-server trust is server-subject.** As of 2026-05-24, RNWY signs a third dimension at `GET /api/mcp-attestation?server={owner}/{repo}` (kid `rnwy-mcp-v1`, ES256 compact JWS), scoring an MCP server's quality and risk. The signed subject is the `server` identifier (`{owner}/{repo}`), not a wallet — there is no wallet entry point on this endpoint, so it is wallet-discoverable/entity-subject like AgentGraph, and is not orchestrated by wallet-keyed consumers. See §3.12 for the schema.

---

## 3. Per-Issuer Schemas

### 3.1 InsumerAPI — `wallet_state` (foundation layer)

**InsumerAPI is the foundation layer.** It reads wallet state across 37 chains (31 EVM + Solana + XRPL + Bitcoin + Tron + Stellar + Sui) and establishes the chain context every other dimension composes on top of. The other eleven dimensions answer specialized questions; the foundation answers "what does this wallet actually hold and do on-chain."

Privacy-preserving on-chain verification. Returns signed booleans. No balances exposed.

**Endpoint routing by wallet format:**

- **EVM wallets** → `POST /v1/trust` — curated multi-chain trust profile. Returns an ECDSA-signed fact profile across stablecoins, governance tokens, NFTs, staking positions, institutional stablecoins, tokenized treasuries, stablecoin deposits, wrapped bitcoin and names (145 base checks on 27 chains, up to 166 on 29 with the optional wallets). An EVM wallet is the mandatory anchor for this endpoint.
- **Non-EVM wallets (Solana, XRPL, Bitcoin, Tron, Stellar, Sui)** → `POST /v1/attest` with `format: "jwt"` and chain-appropriate conditions. The wallet lands in the signed JWT `sub` claim, making the binding cryptographic even for non-EVM formats.

| Property | Value |
|----------|-------|
| Issuer URI | `https://api.insumermodel.com` |
| Algorithm | ES256 (ECDSA P-256) |
| Key ID | `insumer-attest-v2` (see below) |
| JWKS | `https://insumermodel.com/.well-known/jwks.json` |
| Also | `GET /v1/jwks` (API endpoint, 24h cache) |

The JWKS publishes five entries over two keys. Three `EC` entries share the same P-256 key: `insumer-attest-v1` (legacy attest and trust), `insumer-attest-v2` (v2 attest), and `insumer-trust-v2` (v2 trust). Two RFC 9964 `AKP` entries, appended after them, publish the ML-DSA-65 key for the post-quantum companion under `insumer-attest-pq1` and `insumer-trust-pq1` (see the companion note below). Every key created on or after the v2 rollout is v2. The `kid` on each response selects both the key and the signing scheme, so a verifier reads it rather than assuming one, and selects by `kid`, never by position in the set.

**Getting started:** Free API key, no credit card. Returns the key immediately.

```bash
curl -X POST https://api.insumermodel.com/v1/keys/create \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","appName":"my-app","tier":"free"}'
```

Docs: [insumermodel.com/developers](https://insumermodel.com/developers/)

**Signed payload fields** (these fields are covered by the signature under both signing schemes):

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique attestation identifier (e.g., `ATST-BCB27849413440C7`). |
| `pass` | boolean | Aggregate result — `true` if all conditions met. |
| `results` | array | Per-condition results. |
| `results[].condition` | number | Zero-based condition index. |
| `results[].label` | string | Caller-supplied label. |
| `results[].type` | string | Condition type (e.g., `token_balance`, `nft_ownership`). |
| `results[].chainId` | number \| string | Chain ID where the condition was evaluated. |
| `results[].met` | boolean | Whether this individual condition was satisfied. |
| `results[].evaluatedCondition` | object | The evaluated condition parameters (type, chainId, contractAddress, operator, threshold, etc.). |
| `results[].conditionHash` | string | `0x`-prefixed SHA-256 hash of the canonical (sorted-key) evaluated condition JSON. |
| `results[].blockNumber` | string | `0x`-prefixed hex block number at evaluation time (EVM chains, when available). |
| `results[].blockTimestamp` | string | Block timestamp (when available). |
| `attestedAt` | string | ISO 8601 timestamp of attestation creation. |

**Not signed** (present in the API response but NOT covered by the signature):

| Field | Type | Description |
|-------|------|-------------|
| `passCount` | number | Number of conditions that passed. |
| `failCount` | number | Number of conditions that failed. |
| `expiresAt` | string | ISO 8601 expiration timestamp (30 minutes from `attestedAt`). |

**Signature:** Selected by `kid`. Keys issued before the v2 rollout sign a base64-encoded P1363 (`r || s`, 64 bytes) raw signature over `JSON.stringify(signed)`, where `signed` = `{ id, pass, results, attestedAt }`. Keys created on or after it, which is every key issued today, sign a domain-separated preimage instead: the tag `insumer.attestation.v2`, a newline, then the canonical JSON of `{ v: 2, id, pass, results, attestedAt }`, with keys sorted lexicographically and recursively rather than left in insertion order. The bare object is therefore not the signed bytes under v2, which is why the raw form cannot represent such an attestation and the compact JWS form carries it in an envelope. See the note below and the [State Attestation Specification](https://insumermodel.com/state-attestation-spec/).

**Optional JWT format:** When requested with `format: "jwt"`, the API also returns an ES256 JWT with claims: `iss`, `sub` (the wallet a condition evaluated; see the State Attestation Specification Section 5.4), `jti` (attestation ID), `iat`, `exp` (matching the attestation's expiry: +1800s, or +300s when the request carries an `erc7710_delegation` condition), `pass`, `conditionHash[]`, `blockNumber`, `blockTimestamp`, `results[]`.

**Carrying an InsumerAPI attestation in an envelope.** Request it with `format: "jwt"` and place the returned JWT in `sig` with `signed` set to `null`. Keys created on or after the v2 rollout sign a domain-separated preimage rather than the bare attestation object, so the raw form, which verifies a signature over the serialization of `signed`, cannot carry them. The JWT is signed with the same key and selected by the same `kid`, so it verifies against the same JWKS. Populate `expiry` on the entry as well: with `signed` set to `null` there is no `attestedAt` for a relying party to fall back to, and the JWT's own `exp` claim sits inside the signature rather than beside it. A verifier that decodes the token reads that claim regardless (section 4 step 1), but `expiry` lets the entry be judged without decoding, and is the only signal at all on a token carrying no expiry claim of its own.

**The post-quantum companion and the envelope.** Since 2026-09-01 every InsumerAPI attestation and trust profile also carries an ML-DSA-65 companion signature beside the classical one: `pqSig` and `pqKid` on the raw response, and a `pqJwt` beside `jwt` on the JWT format, resolved from the two `AKP` entries in the same JWKS. The envelope entry stays classical. An entry carries one classical `sig` under one classical `kid` and `alg` (`ES256` or `EdDSA`); the entry schema in section 1 has no companion slot, and this version does not add one. A companion may travel alongside the entry, for instance as `pqSig` and `pqKid` or `pqJwt` members an assembler leaves on it, but the envelope verifier does not evaluate those members, the per-slot verdict does not include them, and nothing in the envelope covers or binds them to the entry. A relying party that wants the companion verdict verifies each InsumerAPI entry's original response with `insumer-verify`, which reports the companion as its own verdict (`verified`, `refuted`, `absent`, `unverifiable`) beside the classical checks, under the policy in the [State Attestation Specification](https://insumermodel.com/state-attestation-spec/) (Check 6).


### 3.2 ThoughtProof — `reasoning_integrity`

AI reasoning verification. Attests to the integrity and diversity of model reasoning behind a claim.

| Property | Value |
|----------|-------|
| Issuer URI | `https://api.thoughtproof.ai` |
| Algorithm | EdDSA (Ed25519) |
| Key ID | `tp-attestor-v1` |
| JWKS | `https://api.thoughtproof.ai/.well-known/jwks.json` |
| SDK | `thoughtproof-sdk` on npm (v0.2.1) |

**Getting started:** Free operator key, or pay per-call via x402 (USDC on Base) with no key.

```bash
curl -X POST https://api.thoughtproof.ai/v1/operators \
  -H "Content-Type: application/json" \
  -d '{"name":"my-agent","email":"you@example.com"}'
```

Docs: [thoughtproof.ai/api](https://thoughtproof.ai/api)

**Signed payload fields (JWT claims):**

| Field | Type | Description |
|-------|------|-------------|
| `verdict` | string | One of `ALLOW`, `HOLD`, `UNCERTAIN`, `DISSENT`. |
| `confidence` | number | Confidence score. |
| `mdi` | number | Model Diversity Index — measures reasoning diversity. |
| `claimHash` | string | `sha256:...` hash of the original claim. |
| `domain` | string | Domain of the claim (e.g., `financial`). |
| `stakeLevel` | string | Stake level of the verification. |
| `timestamp` | string | ISO 8601 timestamp. |

**Signature:** Compact JWS (JWT) with EdDSA (Ed25519).

**Wallet-indexed variant (shipped 2026-04-11, no API key):**

```bash
curl https://api.thoughtproof.ai/v1/issuer/wallet/0x0000000000000000000000000000000000001004
```

Returns a `wallet_reasoning_integrity/v1` envelope that puts the queried wallet inside the signed bytes:

| Field | Type | Description |
|-------|------|-------------|
| `wallet` | string | The queried wallet — inside signature scope. |
| `found` | boolean | Whether ThoughtProof holds a reasoning receipt for this wallet. `NOT_FOUND` envelopes are signed too. |
| `verdict` | string | `VERIFIED` / `NOT_FOUND`. |
| `score_normalized` | number | Normalized reasoning-integrity score (0–1). |
| `confidence_bps` | number | Confidence in basis points. |
| `evidence` | object | Supporting attestation evidence (counts, latest attestation hash). |
| `issuedAt` / `expiresAt` | string | ISO 8601 validity window. |
| `signature` | object | `{ alg, kid, value }` — detached EdDSA. |

**Signature (wallet-indexed):** Detached EdDSA over the recursively sorted-key compact JSON of the payload (every field except `signature`) — i.e. `json.dumps(payload, sort_keys=True, separators=(",", ":"))`. `signature.value` is base64url. This is the wallet-bound surface referenced in §2's wallet-bound table.


### 3.3 RNWY — `behavioral_trust`

On-chain behavioral trust scoring with sybil detection across ERC-8004, Olas, Virtuals, and SATI (Solana) agent registries. Dual-score architecture: Signal Depth (behavioral observability) and Risk Intensity (sybil/fraud risk) are independent axes — collapsing them into a single number loses information. Keyless (no API key required).

| Property | Value |
|----------|-------|
| Issuer URI | `https://rnwy.com` |
| Algorithm | ES256 (ECDSA P-256) |
| Key ID | `rnwy-trust-v2` (current, shipped 2026-04-10) · `rnwy-trust-v1` (legacy, compat window) |
| JWKS | `https://rnwy.com/.well-known/jwks.json` |
| On-chain oracle | [`0xD5fdccD492bB5568bC7aeB1f1E888e0BbA6276f4`](https://basescan.org/address/0xD5fdccD492bB5568bC7aeB1f1E888e0BbA6276f4) (Base, 150K+ agents) |
| SDK | `rnwy-sdk` on npm |
| Default TTL | 24 hours (nightly pipeline refresh at 3 AM UTC) |

**Getting started:** No API key required. Install the SDK and start querying.

```bash
npm install rnwy-sdk
```

Docs: [rnwy.com/api](https://rnwy.com/api)

**Coverage:** 150,000+ agents indexed across ERC-8004, Olas, Virtuals, and SATI (Solana). 121,000+ wallets scored. 12 EVM chains + Solana. 1.7M+ on-chain commerce jobs indexed.

**Signed payload fields:**

| Field | Type | Description |
|-------|------|-------------|
| `agentId` | number | Agent identifier. |
| `chain` | string | Chain where the behavior was evaluated (e.g., `base`). |
| `registry` | string | Registry identifier (`erc8004`, `olas`, `sati`). |
| `score` | number | Trust score (0–95). Capped at 95; no agent achieves perfect observability. |
| `tier` | string | Trust tier: `flagged`, `limited`, `developing`, `established`. |
| `badges` | array | Earned badges and warnings (e.g., `original_owner`, `low_history_reviewers`, `sybil_heavy`). |
| `sybilSeverity` | string | Sybil risk severity: `none`, `low`, `moderate`, or `heavy`. |
| `sybilSignals` | array | Specific sybil indicators: `sweep_pattern`, `inhuman_velocity`, `score_clustering`, `coordination`, `common_funder`. |
| `attestedAt` | string | ISO 8601 attestation timestamp. |

**Signature:** Base64-encoded P1363 (`r || s`, 64 bytes) over `JSON.stringify(signed)`. As of 2026-05-24, the trust-check endpoint **additionally** returns a standard compact JWS in a `jws` field alongside the raw `sig` (both over the same `rnwy-trust-v2` payload), so a standard JOSE library verifies out of the box; the raw `sig` remains for backward compatibility.

#### 3.3.0 `rnwy-trust-v2` — upgraded signed payload (current)

As of 2026-04-10, RNWY ships `rnwy-trust-v2` with an expanded signed payload putting the wallet directly in signature scope — cryptographic wallet→score binding end-to-end.

**Signed block (`rnwy-trust-v2`):** `agentId`, `chain`, `registry`, `owner`, `score`, `tier`, `badges`, `sybilSeverity`, `sybilSignals`, `issuedAt`, `verifiedAt`, `expiry`.

- `owner` is the wallet address — this is the wallet-bound field that moves RNWY from wallet-discoverable to wallet-bound in the taxonomy above.
- Chain auto-resolves from the highest-scoring agent owned by the wallet — no `?chain=` parameter required for a wallet lookup.
- Unknown wallets return a **signed `found: false` envelope**: `{ found: false, wallet, issuedAt }` with a full ES256 signature. Cryptographic proof of absence rather than unsigned JSON. Consumers that want to deny-list on "no positive signal" can rely on a verifiable negative claim.

**Wallet-based lookup:** call the trust-check endpoint with a wallet address — RNWY resolves to the highest-scoring owned agent and returns the signed `rnwy-trust-v2` envelope. No chain parameter required.

#### 3.3.1 Evidence Extension (proposed)

The following evidence fields are served by the explorer API and are not yet covered by the signed payload. The proposal is to incorporate them into the signed object in a future update, making the evidence verifiable end-to-end.

**Dual scores (independent axes, not one number):**

| Score | Range | Zones | Description |
|-------|-------|-------|-------------|
| `signal_depth` | 0–95 | Minimal / Emerging / Established / Deep | Behavioral observability: on-chain activity, commerce history, review patterns, wallet tenure. Capped at 95 — no agent achieves perfect observability. |
| `risk_intensity` | 0–100 | Clean / Low / Elevated / Severe | Sybil and fraud risk: wallet funding patterns, review velocity, sweep detection, score clustering. |

**Evidence fields:**

| Field | Type | Description |
|-------|------|-------------|
| `wallet_age_days` | number | Wallet age in days. |
| `wallet_age_score` | number | Wallet age score (0–100). |
| `agent_registered_days` | number | Days since agent registration. |
| `is_original_owner` | boolean | Whether the registering wallet still owns the agent. |
| `transfer_count` | number | Number of ownership transfers. |
| `total_feedback` | number | Total reviews received. |
| `reviewer_diversity_ratio` | number | Ratio of unique reviewers to total reviews. |
| `reviewer_burst_pct` | number | Percentage of reviews in the densest 24-hour window. |
| `reviewer_spread_score` | number | Temporal distribution across review period (0 = all clustered). |
| `sybil_flags` | number | Number of independent sybil signals firing. |
| `sybil_severity` | string | Sybil risk severity level. |
| `sybil_weighted_score` | number | Weighted sybil composite score. |
| `sybil_signals` | array | Active sybil indicators (see signed payload). |
| `reviewer_credibility.pct_low_history` | number | Percentage of reviewers with low-history wallets. |
| `reviewer_credibility.dominant_age_bucket` | string | Most common reviewer wallet age bucket. |
| `reviewer_credibility.label` | string | Credibility label (`Not Credible`, `Low`, `Moderate`, `High`). |
| `transaction_backed_review_pct` | number | Percentage of reviews tied to verifiable on-chain commerce. |
| `commerce_jobs_completed` | number | Verifiable on-chain commerce jobs. |
| `commerce_circularity_pct` | number | Self-dealing detection — fraction of commerce looping back to owner. |
| `registration_quality_score` | number | Metadata completeness and connectivity score. |

**Sybil detection signals (first-class, not bolted on):**

| Signal | Description |
|--------|-------------|
| `common_funder` | Multiple reviewer wallets funded by the same source. |
| `inhuman_velocity` | Review submission rate exceeding human capability. |
| `sweep_pattern` | Reviewers spread across hundreds of agents without returning. |
| `score_clustering` | Reviewers consistently assigning identical scores. |
| `coordination` | Agent-level modifier detecting coordinated reviewer behavior. |

**Reference case:** Agent [Base #1380](https://rnwy.com/explorer/base/1380) — 1,520 reviews, score of zero. 99.7% of reviewers have wallets created the same day they reviewed, four sybil signals firing, 0% of reviews tied to on-chain commerce. A star-counting system would rank it highly.


**Live endpoints:**

| Endpoint | URL |
|----------|-----|
| Trust check (signed) | `GET https://rnwy.com/api/trust-check?chain=base&id={agentId}` |
| Explorer (full evidence) | `GET https://rnwy.com/api/explorer?id={agentId}&chain=base` |
| Explorer (web) | `https://rnwy.com/explorer/{chain}/{agentId}` |
| JWKS | `https://rnwy.com/.well-known/jwks.json` |
| On-chain oracle | [`0xD5fd...e4` on Base](https://basescan.org/address/0xD5fdccD492bB5568bC7aeB1f1E888e0BbA6276f4) |


### 3.4 Maiat — `job_performance`

Agent job performance scoring. Keyless (no API key required, rate-limited to 10 req/min).

| Property | Value |
|----------|-------|
| Issuer URI | `https://app.maiat.io` |
| Algorithm | ES256 (ECDSA P-256) |
| Key ID | `maiat-trust-v1` |
| JWKS | `https://app.maiat.io/.well-known/jwks.json` |
| Default TTL | 30 minutes |

**Getting started:** No API key required. Call the API directly or install the SDK.

```bash
npm install @jhinresh/maiat-sdk
```

Docs: [github.com/JhiNResH/maiat-protocol](https://github.com/JhiNResH/maiat-protocol)

**Signed payload fields (JWT claims):**

| Field | Type | Description |
|-------|------|-------------|
| `agent` | string | Agent identifier. |
| `score` | number | Job performance score. |
| `completionRate` | number | Job completion rate. |
| `sybilFlags` | array | Sybil indicators. |
| `jobCount` | number | Total jobs completed. |
| `tier` | string | Performance tier. |
| `attestedAt` | string | ISO 8601 attestation timestamp. |

**Signature:** Compact JWS (JWT) with ES256.


### 3.5 APS (Agent Passport System) — `passport_grade`

Agent identity verification with graded passports. Measures how deeply an agent's identity has been verified, and cryptographically binds the passport to one or more wallet addresses via a per-wallet signature architecture.

| Property | Value |
|----------|-------|
| Issuer URI | `https://gateway.aeoess.com` |
| Algorithm | EdDSA (Ed25519) |
| Key ID | `gateway-v1` |
| JWKS | `https://gateway.aeoess.com/.well-known/jwks.json` |
| SDK | `agent-passport-system` — [github.com/aeoess/agent-passport-system](https://github.com/aeoess/agent-passport-system) |
| Reference verifier | [`verifyBoundWallet()` in `src/v2/wallet-binding/bind.ts`](https://github.com/aeoess/agent-passport-system/blob/main/src/v2/wallet-binding/bind.ts) |

**Getting started:** No API key required. Three endpoints cover agent-first, wallet-first, and attestation retrieval flows.

```bash
# Agent-first lookup — agent_id → envelope (warm step required before /attestation)
curl https://gateway.aeoess.com/api/v1/public/trust/{agent_id}
curl https://gateway.aeoess.com/api/v1/public/trust/{agent_id}/attestation

# Wallet-first reverse index — address → envelope with wallet_ref[] populated
curl https://gateway.aeoess.com/api/v1/public/trust/by-wallet/{address}
```

The reverse index endpoint was shipped 2026-04-10 and enables SkyeProfile-style orchestrators to start from a wallet address, resolve the bound passport, and fetch the signed attestation without needing to know the `agent_id` in advance. It returns `found: false` with a `reason` field for unbound wallets. The attestation endpoint is cache-backed by `agent_id`; a warm GET on `/trust/{agent_id}` is required before `/trust/{agent_id}/attestation` returns a signed JWS (cold requests return 404).

Docs: [github.com/aeoess/agent-passport-system](https://github.com/aeoess/agent-passport-system)

**Signed payload fields (envelope, Ed25519 JWS signed by `gateway-v1`):**

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | string | Passport identifier (e.g., `aeoess-bound-demo`). |
| `grade` | number | Passport grade (0-3). |
| `grade_label` | string | Human-readable grade label. |
| `risk_level` | string | Risk assessment level. |
| `context_continuity` | object | Context continuity metrics. |
| `has_delegation` | boolean | Whether the agent has active delegation. |
| `has_wallet` | boolean | Legacy envelope-level flag indicating any wallet is registered. |
| `wallet_ref` | array | Bound wallets, each with `{chain, address, bound_at, binding_sig}`. Inside envelope signature scope. |
| `matched_wallet` | object | The specific `wallet_ref[]` entry that matched the query, when the lookup was wallet-first. |
| `evaluatedAt` | string | ISO 8601 evaluation timestamp. |

**Signature:** Compact JWS (JWT) with EdDSA (Ed25519), signed by the `gateway-v1` key.

**Per-wallet binding signatures (`wallet_ref[].binding_sig`) — the strict layer.**

Each entry in `wallet_ref[]` carries its own `binding_sig`, a raw Ed25519 signature independent of the envelope JWS. The signature is over the canonical payload:

```
canonicalize({
  passport_id: <string>,
  chain: <string>,        // e.g. "ethereum", "base"
  address: <string>,      // wallet address, case-preserving
  bound_at: <string>      // ISO 8601 with millisecond precision
})
```

where `canonicalize()` is the reference algorithm in [`src/core/canonical.ts`](https://github.com/aeoess/agent-passport-system/blob/main/src/core/canonical.ts) — sort keys alphabetically, strip null/undefined, compact JSON (no whitespace). The `binding_sig` is signed by the **passport's own private key**, not the gateway key. This gives the wallet binding two independent cryptographic layers:

1. **Envelope layer** (`gateway-v1` JWS) — proves "the APS gateway's infrastructure observed and attested this binding at the named timestamp." Verifiable against `https://gateway.aeoess.com/.well-known/jwks.json`.
2. **Per-wallet layer** (`binding_sig` against passport pubkey) — proves "the passport holder themselves cryptographically committed to this binding." Verifiable against the passport's public key, which lives in the passport object itself for production passports, and in a published fixture file for the canonical `aeoess-bound-demo` test passport.

Both layers verify offline. A consumer wanting the strongest possible "this wallet is bound to this passport" guarantee can require both. A consumer accepting the gateway's observation alone can verify only the envelope layer.

**Strict verification path for the `aeoess-bound-demo` fixture** (canonical reference implementation):

```javascript
// Reference implementation in insumer-examples/wallet-resolve.js: verifyAPSWalletRefBindings()
const fixture = await fetch('https://raw.githubusercontent.com/aeoess/agent-passport-system/main/tests/fixtures/wallet-binding/aeoess-bound-demo.json').then(r => r.json());
const pubKey = createPublicKey({
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(fixture.fixture_public_key, 'hex')]),
  format: 'der', type: 'spki'
});
for (const ref of envelope.wallet_ref) {
  const payload = canonicalize({
    passport_id: envelope.agent_id,
    chain: ref.chain,
    address: ref.address,
    bound_at: ref.bound_at
  });
  const ok = verify(null, Buffer.from(payload, 'utf8'), pubKey, Buffer.from(ref.binding_sig, 'hex'));
  // ok === true means this wallet is cryptographically bound to the passport
}
```

For production passports (non-fixture), the same verification logic applies, but the pubkey is fetched from the passport object's `publicKey` field rather than the fixture file. The canonical payload shape and canonicalization are identical.

**Wallet-binding category**: APS is wallet-bound at both layers. The `wallet_ref[]` array is inside the envelope signature scope, and each entry's `binding_sig` is inside an independent per-entry signature scope. A verifier holding only the signed bytes can prove "this specific wallet → this passport" twice over.


### 3.6 AgentID — `trust_verification`

Behavioral reliability scoring for AI agents. Measures trust level, behavioral risk, and context continuity.

| Property | Value |
|----------|-------|
| Issuer URI | `https://getagentid.dev` |
| Algorithm | EdDSA (Ed25519) |
| Key ID | `agentid-2026-03` |
| JWKS | `https://getagentid.dev/.well-known/jwks.json` |
| SDK | `getagentid` on PyPI |
| Default TTL | 1 hour |

**Getting started:** Free account, or use the public endpoints with no key.

```bash
# Verify any agent (no key required)
curl -X POST https://getagentid.dev/api/v1/agents/verify \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "agent_xxx"}'

# Get trust header (EdDSA JWT, no key required)
curl "https://getagentid.dev/api/v1/agents/trust-header?agent_id=agent_xxx"
```

Docs: [getagentid.dev/docs](https://getagentid.dev/docs)

**Signed payload fields (JWT claims, schema `version: "1.1.0"` as of 2026-04-10):**

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Schema version — currently `"1.1.0"`. |
| `agent_id` | string | Agent identifier. |
| `trust_level` | number | Numeric trust level. |
| `trust_level_label` | string | Human-readable trust level (e.g., "L2 — Verified"). |
| `context_continuity_score` | number | Context continuity metric. |
| `behavioral_risk_score` | number | Behavioral risk assessment. |
| `scarring_score` | number | Historical negative signal accumulation. |
| `negative_signals` | number | Count of negative signals. |
| `resolved_signals` | number | Count of resolved negative signals. |
| `attestation_count` | number | Total attestations issued for this agent. |
| `did` | string | Decentralized identifier (`did:web:getagentid.dev:agent:{id}`). |
| `solana_address` | string | Solana address bound to this agent (when present). |
| `wallet_address` | string | EVM wallet address bound to this agent (when present). |
| `wallet_chain` | string | Chain identifier for `wallet_address` (when present). |
| `bound_addresses` | string[] | All wallet addresses bound to this agent. |
| `subject_binding` | string | Binding type indicator — `"wallet_bound"` when the signed payload includes a wallet. |
| `evaluatedAt` | string | ISO 8601 evaluation timestamp. |

**Signing key unchanged:** kid remains `agentid-2026-03`. The schema was extended in place via the `version` field; no key rotation.

**Wallet lookup:** `GET /api/v1/agents/trust-header?wallet={address}` — OR-filter match on `solana_address` or `wallet_address`.

**Multi-category endpoint:** `GET /api/v1/agents/attestation?agent_id={id}&category={identity|behavioral|continuous-monitoring|key-lifecycle}` — returns a per-category JWS-signed envelope. Wallet binding lives in the `identity` category specifically.

**Signature:** Compact JWS (JWT) with EdDSA (Ed25519).


### 3.7 AgentGraph — `security_posture`

Source code vulnerability scanning for AI agents. Answers: has this agent's code been scanned, and what is the severity profile?

| Property | Value |
|----------|-------|
| Issuer URI | `https://agentgraph.co` |
| Algorithm | EdDSA (Ed25519) |
| Key ID | `agentgraph-security-v1` |
| JWKS | `https://agentgraph.co/.well-known/jwks.json` |
| Default TTL | 24 hours |

**Getting started:** No API key required. Any scanned entity returns a signed attestation.

```bash
# Entity lookup
curl https://agentgraph.co/api/v1/entities/{entity_id}/attestation/security

# Wallet-scoped scan lookup (resolves wallet → scanned entity → signed attestation)
curl "https://agentgraph.co/api/v1/public/scan/wallet/{wallet}?chain=ethereum"
```

Docs: [github.com/agentgraph-co/agentgraph](https://github.com/agentgraph-co/agentgraph)

**Category:** wallet-discoverable content dimension — the signed `subject.id` is `github:owner/repo` (the thing being scanned), not the wallet. The wallet is a discovery key. Consistent with the security posture semantic: the scan evaluates code, not identity.

**Signed payload fields (JWT claims):**

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `SecurityPostureAttestation` |
| `issuer` | object | `{ id, name, url }` — issuer metadata. |
| `subject` | object | `{ id, entity_id, display_name }` — scanned entity. |
| `scan.result` | string | `clean`, `warnings`, or `critical`. |
| `scan.findings` | object | `{ critical, high, medium, total }` — finding counts by severity. |
| `scan.checks` | object | Boolean checks: `no_critical_findings`, `no_high_findings`, `has_readme`, `has_license`, `has_tests`. |
| `scan.positiveSignals` | array | Security best practices detected. |
| `scan.filesScanned` | number | Number of files analyzed. |
| `scan.framework` | string | Detected framework (mcp, langchain, crewai, etc.). |
| `trust.overall` | number | Composite trust score (0.0–1.0). |
| `issuedAt` | string | ISO 8601 attestation timestamp. |
| `expiresAt` | string | ISO 8601 expiration timestamp. |

**Signature:** Compact JWS (JWT) with EdDSA (Ed25519).


### 3.8 SAR (SettlementWitness) — `settlement_witness`

Post-execution delivery attestation. Answers: was the task actually delivered as specified?

| Property | Value |
|----------|-------|
| Issuer URI | `https://defaultverifier.com` |
| Algorithm | EdDSA (Ed25519) |
| Key ID | `sar-prod-ed25519-06` (current, since the 2026-08 repair) · `-05` / `-03` / `-02` / `-01` (legacy, compat) |
| JWKS | `https://defaultverifier.com/.well-known/jwks.json` |

**Getting started:** `/attest` requires an enrolled caller key (since 2026-08-29): send it as a Bearer token with a unix-seconds timestamp and a fresh nonce on every request (the issuer keeps a replay ledger). Ask SettlementWitness for a key. `/receipts` stays public.

```bash
# Attest a task outcome
curl -X POST https://defaultverifier.com/settlement-witness/attest \
  -H "Authorization: Bearer $SAR_API_KEY" \
  -H "X-Settlement-Timestamp: $(date +%s)" \
  -H "X-Settlement-Nonce: $(openssl rand -hex 16)" \
  -H "Content-Type: application/json" \
  -d '{"task_id":"example","spec":{"checks":[{"kind":"field_equals","inputs":{"output_path":"$.status"},"expected":"ok"}]},"output":{"status":"ok"},"receipt_profile":"settlement-witness-verified-v0.2-counterparty-bound","counterparty":"{address}"}'

# Wallet-indexed receipt history (signed receipts where the wallet is the counterparty)
curl "https://defaultverifier.com/settlement-witness/receipts?wallet={address}"
```

Docs: [github.com/nutstrut](https://github.com/nutstrut)

**Category:** wallet-bound when the request names `receipt_profile: settlement-witness-verified-v0.2-counterparty-bound` (the `counterparty` lands inside the signed bytes, and rebinding the wallet invalidates the receipt); wallet-discoverable otherwise via the `/receipts?wallet=` transport lookup. Verdicts: the v0.2 deterministic evaluator needs `spec.checks[]` (`field_equals` over an `output_path`); a spec without checks returns `INDETERMINATE` / `CONDITION_NOT_EVALUABLE`. Binding and verdict are independent. The signed payload also carries an informational x402 fee notice (`requested_not_enforced`).

**Signed payload fields (JWT claims, kid `sar-prod-ed25519-06`):**

| Field | Type | Description |
|-------|------|-------------|
| `task_id_hash` | string | `sha256:...` hash of the task identifier. |
| `verdict` | string | `PASS`, `FAIL`, or `INDETERMINATE`. |
| `confidence` | number | Confidence score (0.0–1.0). |
| `reason_code` | string | Reason for the verdict (e.g., `SPEC_MATCH`). |
| `ts` | string | ISO 8601 timestamp. |
| `verifier_kid` | string | Key ID used for signing. |
| `receipt_id` | string | `sha256:...` derived from the signed core. |
| `counterparty` | string | Wallet address, inside signature scope under the `-counterparty-bound` receipt profile (first shipped with kid `-03` on 2026-04-10, dropped during the 2026-08 repair, restored 2026-09-09). Makes `settlement_witness` a wallet-bound dimension. |

**Signature:** Compact JWS (JWT) with EdDSA (Ed25519).

Legacy receipts signed under kids `-01` or `-02` do not contain `counterparty` in the signed bytes and remain wallet-discoverable only via the `/receipts?wallet=` transport lookup.


### 3.9 Revettr — `compliance_risk`

Counterparty risk scoring. Answers: is the wallet on a sanctions list, does it look like a clean counterparty, what is the regulatory exposure?

| Property | Value |
|----------|-------|
| Issuer URI | `did:web:revettr.com` |
| Algorithm | ES256 (P-256) |
| Key ID | `revettr-attest-v1` |
| JWKS | `https://revettr.com/.well-known/jwks.json` |
| Default TTL | 1 hour |

**Getting started:** No API key required. Keyless `POST /v1/attest` accepts a wallet address and returns a signed compliance risk attestation. Rate-limited to 10 requests per minute per IP.

```bash
curl -X POST https://revettr.com/v1/attest \
  -H "Content-Type: application/json" \
  -d '{"wallet_address":"0x..."}'
```

Discovery: `GET https://revettr.com/.well-known/risk-check.json`

**Signed payload fields (JWT claims):**

| Field | Type | Description |
|-------|------|-------------|
| `iss` | string | `did:web:revettr.com` |
| `sub` | string | Wallet address being scored. |
| `iat` | number | Unix timestamp at issuance. |
| `exp` | number | Unix timestamp at expiration (iat + 3600). |
| `category` | string | Always `compliance_risk`. |
| `attestation_type` | string | Always `compliance_risk`. |
| `score` | number | Composite compliance score (0–100). |
| `tier` | string | `low`, `medium`, `high`, or `critical`. |
| `confidence` | number | Confidence in the score (0.0–1.0), based on signal availability. |
| `flags` | array | Behavioral flags (e.g. `wallet_established`, `sanctions_clear`, `wallet_high_activity`). |
| `signals` | object | Per-signal sub-scores: `domain`, `ip`, `wallet`, `sanctions`. |
| `input_hash` | string | SHA-256 of the input parameters for replay detection. |

**Refresh hint:** Event-driven, with `events: ["ofac_sdn_update", "eu_consolidated_update", "un_sc_update"]` and `max_age_seconds: 43200`.

**Signature:** Compact JWS (JWT) with ES256 (P-256).

**Coverage:** EVM only — Base, Ethereum, Optimism, Arbitrum (chain-agnostic at the `/v1/attest` endpoint, which scans across all 4 by default).


### 3.10 RNWY Wallet Intelligence — `wallet_intelligence`

Operator-level wallet intelligence. Answers "what does RNWY know about the operator wallet itself as an actor" — tenure, commerce history, agent ownership, review behavior, and sybil detection reactivity. Distinct from `behavioral_trust` (agent-level), which answers "is this agent trustworthy." The two dimensions compose — a high-behavioral-trust agent owned by a low-signal-depth operator is a meaningfully different risk than the same agent owned by a deeply established operator.

| Property | Value |
|----------|-------|
| Issuer URI | `https://rnwy.com` |
| Algorithm | ES256 (ECDSA P-256) |
| Key ID | `rnwy-wallet-v1` |
| JWKS | `https://rnwy.com/.well-known/jwks.json` |
| Default TTL | 24 hours |

**Getting started:** No API key required.

```bash
curl "https://rnwy.com/api/wallet-score?address={wallet}"
```

Docs: [rnwy.com/api](https://rnwy.com/api)

**Signed payload fields (JWT claims):**

| Field | Type | Description |
|-------|------|-------------|
| `iss` | string | Issuer identifier. |
| `sub` | string | Wallet address (JWT-style subject). |
| `wallet` | string | Wallet address (explicit alias). |
| `signalDepth` | number | 0–95. Observational tenure, commerce history, agent ownership, review behavior. |
| `riskIntensity` | number | 0–100. Sybil detection reactivity. Zero means clean. Independent from `signalDepth`. |
| `quadrant` | string | e.g. `high_depth_low_risk`, `high_depth_high_risk`, etc. |
| `activityZone` | string | Named zone — `Established`, `Emerging`, etc. |
| `riskZone` | string | Named zone — `Clean`, `Elevated`, etc. |
| `issuedAt` | string | ISO 8601 — when the score was computed. |
| `verifiedAt` | string | ISO 8601 — request time. |
| `expiry` | string | ISO 8601 — end of validity window. |

**Unscored wallets** return a signed `{ found: false, wallet, issuedAt }` envelope — cryptographic proof of absence rather than unsigned JSON. Downstream consumers that want to deny-list on "no positive signal" can rely on a verifiable negative claim.

**Chain coverage:** EVM only as of 2026-04-10.

**Signature:** Compact JWS (JWT) with ES256.


### 3.11 TrustLayer — `cross_chain_reputation`

Cross-chain wallet linkage and reputation. Answers: how many addresses across how many chains does this wallet operate under, and what is the consolidated reputation across the cross-chain identity graph? Sibling to RNWY's `behavioral_trust` (agent-level) and `wallet_intelligence` (operator-level) — TrustLayer's signal is the cross-chain identity graph itself, not behavior or operator history.

| Property | Value |
|----------|-------|
| Issuer URI | `https://api.thetrustlayer.xyz` |
| Algorithm | ES256 (ECDSA P-256) |
| Key ID | `trustlayer-signing-1` |
| JWKS | `https://api.thetrustlayer.xyz/.well-known/jwks.json` |
| Default TTL | per-issuer (signed `attested_at` present; consumers default to 30 minutes) |

**Getting started:** No API key required. Wallet-bound endpoint accepts EVM (`0x…`) or Solana base58 addresses.

```bash
# Default — highest-scored agent owned by the wallet across all indexed chains
curl https://api.thetrustlayer.xyz/attest/wallet/{wallet}

# Chain-scoped query — agent on a specific chain
curl "https://api.thetrustlayer.xyz/attest/wallet/{wallet}?chain=base"
```

Reference verifier: [`goatgaucho/trustlayer-middleware-express/verify-attestation.js`](https://github.com/goatgaucho/trustlayer-middleware-express/blob/main/verify-attestation.js).

**Coverage:** 19 chains — Arbitrum, Avalanche, Base, BSC, Celo, Ethereum, Gnosis, GOAT, Linea, Mantle, Metis, Monad, Optimism, Polygon, Scroll, Soneium, Solana, Taiko, xLayer. 1,468 cross-chain identity groups indexed.

**Signed payload fields:**

| Field | Type | Description |
|-------|------|-------------|
| `wallet` | string | The queried wallet address (EVM `0x…` or Solana base58). Inside signature scope — this is the wallet-binding field. |
| `agent_id` | string | `{chain}:{registry_id}` of the resolved agent (e.g. `ethereum:29057`). |
| `identity_group_id` | string \| null | Cross-chain group identifier (e.g. `owner_790`). `null` when the wallet's agent is not yet clustered into a group. |
| `linked_addresses_count` | number | Number of addresses in the wallet's identity group across all indexed chains. `1` when the wallet is unclustered. |
| `chains_present` | array | Chain identifiers where the identity group has presence. |
| `score` | number | Cross-chain reputation score (0–100). |
| `sybil_flags` | array | Detected sybil indicators (empty when none). |
| `match_method` | string \| null | How the agent was resolved (e.g. `owner_wallet`). |
| `match_confidence` | number \| null | Resolution confidence (0.0–1.0). |
| `scored_at` | string | ISO 8601 — when the score was computed (background pipeline). |
| `attested_at` | string | ISO 8601 — request time. |

**Unknown wallets** return a signed envelope with `identity_group_id: null`, `linked_addresses_count: 1`, and a chain-specific `agent_id` — the dimension stays queryable even when the wallet isn't in a cross-chain group. **Wallets with no agent in any indexed registry** return `{wallet, found: false, note}` (200, no envelope).

**Signature:** Base64url-encoded P1363 (`r || s`, 64 bytes) over the **canonical (sorted-key) JSON serialization** of `signed`. The reference verifier (`multi-attest-verify.js`) accepts both insertion-order and canonical JSON for ES256 raw, so TrustLayer's canonical form verifies under the standard ES256 raw path.

**Wallet-binding category**: wallet-bound — the `wallet` field is inside signature scope.


### 3.12 RNWY MCP Trust — `mcp_trust`

MCP-server quality and risk scoring. Answers "how capable and how risky is this MCP server" — tenure, adoption, capability surface, and reliability rolled into a quality score, with an independent risk score. The signed subject is the server (`{owner}/{repo}`), not a wallet: this dimension attests to a server, not an actor, so it is wallet-discoverable/entity-subject (like AgentGraph) rather than wallet-bound. Keyless (no API key required).

| Property | Value |
|----------|-------|
| Issuer URI | `https://rnwy.com` |
| Algorithm | ES256 (ECDSA P-256) |
| Key ID | `rnwy-mcp-v1` |
| JWKS | `https://rnwy.com/.well-known/jwks.json` |
| Default TTL | 24 hours |

**Getting started:** No API key required. The query is server-scoped (`{owner}/{repo}`) — there is no wallet entry point.

```bash
curl "https://rnwy.com/api/mcp-attestation?server={owner}/{repo}"
```

**Signature:** Compact JWS (JWT) with ES256 (P-256), in the `jws` field; a raw `sig` over `JSON.stringify(signed)` is returned alongside for backward compatibility.

**Signed payload fields:**

| Field | Type | Description |
|-------|------|-------------|
| `server` | string | The attested MCP server, `{owner}/{repo}`. Signed subject. |
| `qualityScore` | number | Composite quality (0–100) from tenure, adoption, capability, reliability. |
| `riskScore` | number | Risk score; lower is cleaner. Independent from `qualityScore`. |
| `quadrant` | string | e.g. `low_quality_low_risk`, `high_quality_low_risk`. |
| `breakdown` | object | Per-component scoring detail (`quality`, `risk`, `version`, `quadrant`). |
| `issuedAt` | string | ISO 8601 scan timestamp. |
| `verifiedAt` | string | ISO 8601 attestation timestamp. |
| `expiry` | string | ISO 8601 expiry (`verifiedAt` + 24h). |

**Wallet-binding category**: wallet-discoverable / entity-subject — the signed subject is the server, not a wallet.


---

## 4. Verification Algorithm

For each attestation entry in `attestations[]`:

0. **Contain malformed entries.** If an entry is not an object, or is missing `kid`, `alg`, `jwks`, or `sig`, record a failure result for that slot and continue. The same applies to an entry whose `sig` is a compact JWS and whose `signed` is not `null`: verify nothing on it. The JWS path never reads `signed`, so verifying the signature and returning would report a valid signature while an unsigned object sits in a field relying parties read claims from. Classifying it here rather than at step 4 is deliberate — it is a defect in the entry's form, knowable before any key is fetched, and it is refused whether or not the entry is also stale. A malformed entry MUST fail its own slot only; it MUST NOT abort verification of the remaining entries or suppress their verdicts. Per-slot independence includes fault containment, not just signature isolation.

1. **Check expiry.** If `expiry` is present and in the past, the entry is expired: record that on the entry's own result and do not examine its signature. A verifier reports expiry per entry rather than partitioning the payload. `expired[]` is a field an assembler populates when it builds the envelope (section 1); it is not an array a verifier writes into, and leaving every entry where it sits keeps results aligned with the entries they describe. If `expiry` is absent, compute expiry from `attestedAt` (or its snake_case spelling `attested_at`, or `iat` / `timestamp`) plus the issuer's default TTL. Read both spellings: issuers differ, and a verifier that checks only one silently treats an entry carrying the other as never expiring. When `sig` is a compact JWS, decode the token and use its `exp` (or `expiresAt`) claim: a conformant JWS entry has `signed` set to `null`, so none of the fallbacks above are available on it, and a verifier that does not read the token treats every such entry as permanently fresh. Where both an entry-level `expiry` and a token claim are present, the entry is expired if either says so — the envelope is unsigned, so the `expiry` beside a signature can be set by whoever relays it, while the token's own claim cannot. If no timing fields are present, skip expiry check.

2. **Determine signature format.** If `sig` contains exactly two `.` characters, treat it as a compact JWS (JWT). Otherwise, treat it as a base64-encoded raw signature.

3. **Resolve the public key from the relying party's own key set for `issuer`.** A relying party holds, or pins by origin, the JWKS for every issuer it accepts; the entry's `jwks` MUST match that pinned origin, and an entry whose `issuer` is not in the relying party's set, or whose `jwks` points elsewhere, fails closed. Fetch that pinned JWKS (not a URL taken on trust from the entry) and find the key where `kid` matches; a `kid` matching no key is a failure, not a reason to fetch another key. Discovery mode (accepting `jwks` from the entry for an issuer not yet pinned) is a relying-party opt-in, never the default. Implementations SHOULD cache JWKS responses (recommended: 1 hour TTL). Cache entries MUST be keyed by the JWKS URL (or URL plus `kid`), never by `kid` alone: two issuers may publish the same `kid`, and a cache keyed only on `kid` would let one issuer's key satisfy another issuer's lookup. The reference verifier keys its cache on `jwksUrl:kid`. Note also that the verifier does not derive a JWKS location from `issuer`; the `jwks` URL is taken from the attestation itself, and pinning issuers to expected JWKS URLs is the relying party's job (see 5.1).

4. **Verify the signature.**

   **Raw signature path** (P1363 / raw bytes):
   - Decode `sig` from base64 (or base64url) to bytes.
   - Compute the signing input: `JSON.stringify(signed)` encoded as UTF-8. If verification fails, retry with the canonical sorted-key JSON serialization of `signed` — some issuers sign the canonical form (e.g., TrustLayer ES256, RNWY-pattern EdDSA). The reference verifier accepts both forms for both ES256 raw and EdDSA raw.
   - For ES256: convert P1363 format (`r || s`, 64 bytes) to DER, then verify with SHA-256 and the P-256 public key.
   - For EdDSA: verify the raw signature bytes directly against the signing input using the Ed25519 public key (no hash — Ed25519 hashes internally).

   **JWT path** (compact JWS):
   - Split `sig` on `.` into `[header, payload, signature]`.
   - The entry-level `kid` alone selects the key. The signature check against that key is what binds the entry to it: a `kid` that names a key other than the one that signed the token fails at the signature step, so the verifier does not consult a `kid` inside the JWS header. Two kids that resolve to the same public key (the three InsumerAPI EC kids do) verify identically, and that is a labelling difference, not a forgery path.
   - The signing input is `header.payload` (the first two segments joined by `.`).
   - Decode `signature` from base64url to bytes.
   - For ES256: convert P1363 to DER, verify with SHA-256 and P-256.
   - For EdDSA: verify raw bytes directly against signing input with Ed25519.

5. **Evaluate policy and compute the aggregate.** After verifying all entries, compute the top-level `valid`. With `requiredTypes` empty it is the AND over the per-slot verdicts: every entry must be signature-valid and unexpired. With `requiredTypes` non-empty it is the required-types check alone: each required type must have at least one signature-valid, unexpired slot, and failures in unrelated slots do not lower it. The aggregate is a pure function of the per-slot verdicts and the verifier options. Policy is the relying party's responsibility; the payload carries no policy.

### Pseudocode

```
function verifyMultiAttestation(payload, requiredTypes):
    results = []
    for att in payload.attestations:
        if not isObject(att) or missing(att.kid, att.alg, att.jwks, att.sig):
            results.push({ type: null, status: "failed", error: "malformed entry" })
            continue
        if isJWT(att.sig) and att.signed != null:
            results.push({ type: att.type, status: "failed", error: "malformed entry" })
            continue
        if isExpired(att):
            results.push({ type: att.type, status: "expired" })
            continue
        pinned = trustedIssuers[att.issuer]           # relying-party configuration
        if pinned == null or origin(att.jwks) != origin(pinned):
            results.push({ type: att.type, status: "failed", error: "issuer not pinned or jwks origin mismatch" })
            continue
        key = fetchJWKS(pinned, att.kid, att.alg)
        if isJWT(att.sig):
                continue
            valid = verifyJWT(att.sig, key, att.alg)
        else:
            message = JSON.stringify(att.signed)
            valid = verifyRaw(att.sig, message, key, att.alg)
        results.push({ type: att.type, status: valid ? "verified" : "failed" })

    missing = requiredTypes.filter(t => !results.find(r => r.type == t && r.status == "verified"))
    allValid = results.every(r => r.status == "verified")
    return { valid: missing.length == 0 && (requiredTypes.length > 0 || allValid), results, missing }
```

---

## 5. Security Considerations

### 5.1 JWKS Integrity

Each issuer's JWKS endpoint is the root of trust for that issuer. Implementations MUST fetch JWKS over HTTPS. Pinning issuer URIs to expected JWKS URLs is RECOMMENDED for high-security deployments.

### 5.2 Replay and Expiry

Attestations are time-limited. Relying parties MUST check expiry before accepting an attestation. The `expiry` field, when present, can expire an entry but cannot extend one. The envelope is unsigned, so `expiry` is settable by whoever relays the entry, while an expiry claim inside a compact JWS is within signature scope; where both are present the entry is expired if either says so. When neither is present, relying parties SHOULD enforce a default TTL no longer than 30 minutes.

Attestation IDs (where provided by the issuer, e.g., InsumerAPI's `id` field or a JWT `jti` claim) MAY be used for replay detection.

### 5.3 No Cross-Issuer Trust

Each attestation is independently verifiable. A valid signature from one issuer implies nothing about the validity or trustworthiness of another issuer in the same payload. The payload is a bundle, not a chain of trust.

Independence is testable, and implementations SHOULD test it rather than assume it: strip one issuer's signature and confirm that only that slot fails, that every other slot's verdict is unchanged, and that the stripped slot's absence is never treated as another slot's failure. Independence also includes fault containment (see 4, step 0): one malformed entry failing must never suppress the verdicts of the entries beside it.

The aggregate `valid` is derived from the per-slot verdicts and is an input to none of them: recomputing it from those verdicts and the verifier options (see 4, step 5) MUST reproduce the emitted value. An aggregate that cannot be reproduced from the slots carries state the slots do not, which is exactly the channel this section exists to exclude.

### 5.4 Payload Integrity

The multi-attestation envelope itself is unsigned. The `attestations` array can be reordered, entries can be removed, or entries from `expired[]` can be moved back to `attestations[]`. Relying parties MUST NOT rely on the envelope's structure for security — only on individual attestation signatures and their expiry. If envelope integrity is required, the relying party should sign the entire payload at the application layer.

### 5.5 Condition Tamper Detection

For `wallet_state` attestations, each result includes a `conditionHash` (SHA-256). Relying parties that submitted conditions can recompute the hash and compare it to the signed value, ensuring the issuer evaluated the exact conditions that were requested.

### 5.6 Privacy

`wallet_state` attestations expose boolean results (`met: true/false`), not balances. This is by design — the relying party learns whether a threshold was satisfied, not how much the wallet holds.

---

## 6. Reference Implementation

[`multi-attest-verify.js`](./multi-attest-verify.js) in this repository. Zero dependencies — uses Node.js built-in `crypto` and `https` modules only.

```js
const { verifyMultiAttestation } = require('./multi-attest-verify');

const result = await verifyMultiAttestation(payload, {
  requiredTypes: ['wallet_state', 'behavioral_trust']
});

if (result.valid) {
  // All required attestation types are present and verified
}
```

The verifier:
- Fetches and caches JWKS keys (1-hour TTL)
- Auto-detects signature format (raw base64 vs. compact JWS)
- Verifies ES256 (P-256) and EdDSA (Ed25519)
- Checks expiry and flags expired entries per slot
- Evaluates `requiredTypes` policy
- Runs all signature verifications in parallel

---

## Appendix A: JWKS Endpoints

| Issuer | JWKS URL |
|--------|----------|
| InsumerAPI | `https://insumermodel.com/.well-known/jwks.json` |
| ThoughtProof | `https://api.thoughtproof.ai/.well-known/jwks.json` |
| RNWY | `https://rnwy.com/.well-known/jwks.json` |
| Maiat | `https://app.maiat.io/.well-known/jwks.json` |
| APS | `https://gateway.aeoess.com/.well-known/jwks.json` |
| AgentID | `https://getagentid.dev/.well-known/jwks.json` |
| AgentGraph | `https://agentgraph.co/.well-known/jwks.json` |
| SAR | `https://defaultverifier.com/.well-known/jwks.json` |
| TrustLayer | `https://api.thetrustlayer.xyz/.well-known/jwks.json` |

## Appendix B: Algorithm Support Matrix

| Algorithm | Curve | Issuers | Signature Encoding |
|-----------|-------|---------|-------------------|
| ES256 | P-256 | InsumerAPI, RNWY (behavioral_trust + wallet_intelligence + mcp_trust), Maiat, Revettr, TrustLayer | P1363 base64/base64url or JWT |
| EdDSA | Ed25519 | ThoughtProof, APS, AgentID, AgentGraph, SAR | JWT |
