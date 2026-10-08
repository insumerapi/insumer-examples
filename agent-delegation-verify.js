/**
 * InsumerAPI Agent Standing — ERC-8004 registration + ERC-7710 delegation
 *
 * At settlement time three questions exist: can this wallet pay (payment
 * rails), is the decision sound (reasoning verifiers), and does this party
 * have STANDING to act? The two agent condition types answer the third,
 * straight from chain state:
 *
 *   erc8004_agent      — is this wallet a registered ERC-8004 agent?
 *                        met iff the attested wallet owns the agent NFT
 *                        (ownerOf) or is the registry's signature-verified
 *                        agentWallet binding. Honest semantics: registration
 *                        is permissionless minting — the signed statement is
 *                        registration and binding, NOT vetting or reputation.
 *   erc7710_delegation — did principal P really authorize this agent wallet?
 *                        met iff the attested wallet is the delegate, the
 *                        declared delegator matches expectedDelegator, the
 *                        EIP-712 signature verifies (EOA or ERC-1271), the
 *                        delegation is unrevoked as of the anchored block,
 *                        and every caveat uses a recognized enforcer.
 *
 * Both are Base-only (chainId 8453). One /v1/attest call costs 1 credit (or
 * $0.05 via x402 pay-per-call) whether it carries one condition or both, and
 * they come back inside a signed attestation, never a credential.
 * Attestations containing a delegation condition expire in
 * 5 minutes, not the standard 30: revocation is one transaction away, so the
 * verdict window stays tight.
 *
 * What this example does with throwaway keypairs (no funds needed):
 *   1. Generates a principal and an agent wallet.
 *   2. Signs a REAL ERC-7710 delegation (MetaMask Delegation Framework
 *      EIP-712 shape) from principal → agent.
 *   3. Submits both conditions against the agent wallet.
 * Expected honest result: erc7710_delegation is MET — the signature is real,
 * the delegation was never revoked. erc8004_agent is NOT MET — a throwaway
 * wallet owns no agent in the registry. Own a registered agent? Set AGENT_ID
 * and AGENT_PRIVATE_KEY to see both conditions pass.
 *
 * Usage:
 *   npm install viem
 *   INSUMER_API_KEY=insr_live_... node agent-delegation-verify.js
 *
 *   # or with no key at all, pay $0.05 for the call via x402:
 *   DEMO_PRIVATE_KEY=0x... node agent-delegation-verify.js
 *
 * Get a free API key (10 free verifications plus 100 requests a day):
 *   bash quickstart.sh
 */

const { privateKeyToAccount, generatePrivateKey } = require("viem/accounts");
const { payPerCall } = require("./x402-pay-per-call");

const API = "https://api.insumermodel.com";
const KEY = process.env.INSUMER_API_KEY;

// ─── Public Base mainnet constants ───
// ERC-8004 Identity Registry and the recognized MetaMask Delegation Framework
// v1.3.0 DelegationManager (the manager that also supports Merkle revocation
// proofs via proof: "merkle").
const BASE_CHAIN_ID = 8453;
const DELEGATION_MANAGER = "0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3";
const ROOT_AUTHORITY = `0x${"ff".repeat(32)}`; // root delegations only in v1

// ─── ERC-7710 delegation typed-data (MetaMask Delegation Framework) ───
const DELEGATION_TYPES = {
  Caveat: [
    { name: "enforcer", type: "address" },
    { name: "terms", type: "bytes" },
  ],
  Delegation: [
    { name: "delegate", type: "address" },
    { name: "delegator", type: "address" },
    { name: "authority", type: "bytes32" },
    { name: "caveats", type: "Caveat[]" },
    { name: "salt", type: "uint256" },
  ],
};

/**
 * Sign an ERC-7710 root delegation from principal → agent.
 * @param {object} principal - viem account of the principal (delegator)
 * @param {string} agentAddress - the agent wallet being authorized
 * @param {object[]} [caveats=[]] - caveats to embed ({enforcer, terms})
 * @returns {Promise<object>} the delegation object /v1/attest expects
 */
async function signDelegation(principal, agentAddress, caveats = []) {
  const salt = String(Math.floor(Math.random() * 1e12));
  const signature = await principal.signTypedData({
    domain: {
      name: "DelegationManager",
      version: "1",
      chainId: BASE_CHAIN_ID,
      verifyingContract: DELEGATION_MANAGER,
    },
    types: DELEGATION_TYPES,
    primaryType: "Delegation",
    message: {
      delegate: agentAddress,
      delegator: principal.address,
      authority: ROOT_AUTHORITY,
      caveats,
      salt: BigInt(salt),
    },
  });
  return {
    delegator: principal.address,
    delegate: agentAddress,
    authority: ROOT_AUTHORITY,
    caveats,
    salt,
    signature,
  };
}

/**
 * Attest agent standing: registration + delegation, one signed call.
 * Uses X-API-Key when INSUMER_API_KEY is set; otherwise pays per call via
 * x402 with DEMO_PRIVATE_KEY (no key, no signup).
 * @param {object} body - the /v1/attest request body
 * @returns {Promise<object>} the parsed response body
 */
async function attest(body) {
  if (KEY) {
    const res = await fetch(`${API}/v1/attest`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": KEY },
      body: JSON.stringify(body),
    });
    return res.json();
  }
  const payerKey = process.env.DEMO_PRIVATE_KEY;
  if (!payerKey) {
    console.error("Set INSUMER_API_KEY (see quickstart.sh), or DEMO_PRIVATE_KEY");
    console.error("holding a wallet with USDC on Base to pay $0.05 via x402.");
    process.exit(1);
  }
  const result = await payPerCall("/v1/attest", body, payerKey);
  if (result.settlement) {
    console.log(`Paid via x402 — settlement tx: ${result.settlement.transaction}\n`);
  }
  return result.body;
}

async function main() {
  // Throwaway identities by default — override to use real ones.
  const principal = privateKeyToAccount(process.env.PRINCIPAL_PRIVATE_KEY || generatePrivateKey());
  const agent = privateKeyToAccount(process.env.AGENT_PRIVATE_KEY || generatePrivateKey());
  const agentId = process.env.AGENT_ID || "1";

  console.log(`Principal (delegator): ${principal.address}`);
  console.log(`Agent (delegate):      ${agent.address}\n`);

  const delegation = await signDelegation(principal, agent.address);

  const body = {
    wallet: agent.address,
    conditions: [
      {
        type: "erc8004_agent",
        chainId: BASE_CHAIN_ID,
        agentId,
        label: `Registered as agent #${agentId} in the ERC-8004 Identity Registry`,
      },
      {
        type: "erc7710_delegation",
        chainId: BASE_CHAIN_ID,
        delegationManager: DELEGATION_MANAGER,
        expectedDelegator: principal.address,
        delegation,
        label: "Holds a live delegation from the principal",
      },
    ],
  };

  const result = await attest(body);
  if (!result.ok) {
    const msg = result.error && result.error.message ? result.error.message : JSON.stringify(result);
    console.error(`attest failed: ${msg}`);
    process.exit(1);
  }

  const { attestation, sig, kid } = result.data;
  console.log(`Attestation ${attestation.id} — overall pass: ${attestation.pass}`);
  console.log(`Expires ${attestation.expiresAt} (5-minute window: a delegation condition is present)\n`);

  for (const r of attestation.results) {
    console.log(`[${r.met ? "MET" : "NOT MET"}] ${r.label || r.type}`);
    if (r.type === "erc8004_agent") {
      console.log(`        matchedVia: ${r.matchedVia || "none"} — with throwaway keys this is`);
      console.log("        honestly NOT MET: registration can't be faked without owning the agent.");
    }
    if (r.type === "erc7710_delegation") {
      if (r.met) {
        console.log("        A real EIP-712 signature over an unrevoked delegation — MET with");
        console.log("        zero funds. Authority is proven by signature, not by balance.");
      } else if (r.failReason) {
        console.log(`        failReason: ${r.failReason}`);
      }
      if (r.declaredLimits) {
        console.log(`        declaredLimits: ${JSON.stringify(r.declaredLimits)}`);
      }
    }
  }

  console.log(`\nSigned with kid ${kid} — verify offline via ${API}/v1/jwks`);
  console.log(`sig: ${sig.slice(0, 44)}…`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { signDelegation, DELEGATION_TYPES, DELEGATION_MANAGER, ROOT_AUTHORITY };
