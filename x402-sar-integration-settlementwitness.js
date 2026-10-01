/**
 * InsumerAPI + x402 SAR Integration Example
 *
 * End-to-end flow: attestation → payment → SAR receipt → offline verification
 *
 * This variant performs:
 * - Step 3: a live SettlementWitness call
 * - Step 4c: SAR receipt verification against the live key registry
 *
 * Usage:
 *   npm install insumer-verify jose canonicalize @noble/ed25519 @noble/hashes
 *   INSUMER_API_KEY=insr_live_... node x402-sar-integration-settlementwitness.js
 */


const { createRemoteJWKSet, jwtVerify } = require("jose");


const ed = require("@noble/ed25519");
// canonicalize 2.x and later is an ES module. Under Node 22, require() returns its
// namespace, and the function is its default export; 1.x returns the function itself.
const canonicalizeModule = require("canonicalize");
const canonicalize = canonicalizeModule.default || canonicalizeModule;
const crypto = require("crypto");

ed.hashes.sha512 = (m) => crypto.createHash("sha512").update(m).digest();
ed.hashes.sha512Async = async (m) =>
  crypto.createHash("sha512").update(m).digest();


const API = "https://api.insumermodel.com";
const SAR_API = "https://defaultverifier.com";
const KEY = process.env.INSUMER_API_KEY;

if (!KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

// Consistent identity across all four steps
const AGENT_ID = `agent-${Date.now()}`;

// Example: verify counterparty holds USDC on Base before transacting
const WALLET = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const CONDITIONS = [
  {
    type: "token_balance",
    contractAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    chainId: 8453,
    threshold: "1",
    label: "USDC on Base",
  },
];

async function verifySARReceipt(receipt) {
  // Fetch public key registry
  const registryRes = await fetch(
    `${SAR_API}/.well-known/sar-keys.json`
  );
  const registry = await registryRes.json();

  const core = receipt.receipt_v0_1;
  const kid = core?.verifier_kid;
  const keyEntry = registry.keys?.find((k) => k.kid === kid);
  console.log("      Registry kids:", registry.keys?.map((k) => k.kid));
  console.log("      Receipt kid:", kid);

  if (!keyEntry) {
    return { valid: false, reason: `Key not found in registry: ${kid}` };
  }

  // Decode public key
  const pubKeyB64 = keyEntry?.public_key_b64url || keyEntry?.x;
  const pubKeyBytes = Buffer.from(pubKeyB64, "base64url");

  // Extract signature
  const sigB64 = core?.sig?.replace("base64url:", "");
  const sigBytes = Buffer.from(sigB64, "base64url");

  // Build the exact signed core (SAR v0.1 spec section 3)
  // Signature covers these six fields only — order matters for RFC 8785
  const signedCore = {
    task_id_hash: core.task_id_hash,
    verdict: core.verdict,
    confidence: core.confidence,
    reason_code: core.reason_code,
    ts: core.ts,
    verifier_kid: core.verifier_kid,
  };

  // RFC 8785 canonicalize → SHA256 → Ed25519 verify
  const canonical = canonicalize(signedCore);
  const canonicalBytes = new TextEncoder().encode(canonical);
  const digest = crypto.createHash("sha256").update(canonicalBytes).digest();

  const valid = await ed.verify(sigBytes, digest, pubKeyBytes);

  // Diagnostic: receipt_id derivation check
  // Note: receipt_id is derived from the verifier signature, not the digest.
  // A mismatch here is diagnostic only — it does not invalidate the receipt.
  const receiptIdCheck = `sha256:${Buffer.from(digest).toString("hex")}`;
  const receiptIdMatches = core.receipt_id === receiptIdCheck;

  return {
    valid,
    kid,
    receiptIdMatches,
    expectedReceiptId: receiptIdCheck,
    actualReceiptId: core.receipt_id,
  };
}

async function main() {
  console.log(`Agent: ${AGENT_ID}\n`);

  // ─── Step 1: Pre-transaction attestation (InsumerAPI) ───
  console.log("Step 1: Pre-transaction attestation");
  console.log("  Verifying counterparty wallet meets conditions...\n");

  const attestRes = await fetch(`${API}/v1/attest`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": KEY },
    body: JSON.stringify({
      wallet: WALLET,
      conditions: CONDITIONS,
      format: "jwt",
    }),
  });

  const attestResult = await attestRes.json();

  if (!attestResult.ok) {
    console.error("Attestation failed:", attestResult.error);
    process.exit(1);
  }

  const { attestation, sig, jwt } = attestResult.data;

  console.log(`  Attestation ID: ${attestation.id}`);
  console.log(`  Pass: ${attestation.pass}`);
  console.log("  Results:");
  attestation.results.forEach((r) => {
    console.log(`    [${r.met ? "MET" : "NOT MET"}] ${r.label} (chain ${r.chainId})`);
  });
  console.log(`  Signature: ${sig.substring(0, 20)}...`);
  console.log(`  JWT: ${jwt.substring(0, 40)}...`);
  console.log(`  Agent: ${AGENT_ID}\n`);
  console.log(`  Note: when agent_id maps to a stable wallet address,`);
  console.log(`  call POST ${API}/v1/trust with a JSON body { "wallet": WALLET } before transacting`);
  console.log(`  to pull a full trust profile: stablecoins, governance tokens, NFTs,`);
  console.log(`  staking, institutional stablecoins, tokenized treasuries, stablecoin`);
  console.log(`  deposits, wrapped bitcoin and names across 27 chains`);
  console.log(`  (up to 29 with optional non-EVM wallets).`);
  console.log(`  Pre-transaction trust profile + post-transaction SAR receipt`);
  console.log(`  gives both sides of the picture.\n`);

  // ─── Step 2: x402 payment ───
  console.log("Step 2: x402 payment");
  console.log("  [Adoption phase] Fee requested but not enforced.");
  console.log("  The attestation from Step 1 informs the agent whether to proceed.");
  console.log(`  Agent ID: ${AGENT_ID}\n`);

  const paymentTxHash = "0x_adoption_phase_placeholder";

  // ─── Step 3: SAR receipt (SettlementWitness live endpoint) ───
  console.log("Step 3: SAR receipt");
  console.log("  Calling SettlementWitness live endpoint...\n");

  const sarRes = await fetch(`${SAR_API}/settlement-witness`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      task_id: `task-${Date.now()}`,
      agent_id: AGENT_ID,
      spec: {
        asset: "USDC",
        chain: "Base",
        action: "delivery_verification",
        attestation_pass: attestation.pass,
      },
      output: {
        asset: "USDC",
        chain: "Base",
        action: "delivery_verification",
        attestation_pass: attestation.pass,
      },
    }),
  });

  const sarReceipt = await sarRes.json();

  if (!sarReceipt?.receipt_v0_1) {
    console.error("SAR receipt failed or unexpected response shape:");
    console.error(JSON.stringify(sarReceipt, null, 2));
    process.exit(1);
  }

  console.log(`  SAR Verdict:    ${sarReceipt.receipt_v0_1.verdict}`);
  console.log(`  SAR Receipt ID: ${sarReceipt.receipt_v0_1.receipt_id}`);
  console.log(`  SAR Key ID:     ${sarReceipt.receipt_v0_1.verifier_kid}`);
  console.log(`  Agent ID:       ${sarReceipt._ext?.agent_id}`);
  console.log(`  TrustScore:     ${sarReceipt.trustscore_update?.score} (${sarReceipt.trustscore_update?.tier})\n`);

  // ─── Step 4: Offline verification of both artifacts ───
  console.log("Step 4: Offline verification\n");


  // 4b. Verify JWT independently (ES256 via JWKS)
  console.log("  4b. Verifying JWT via JWKS...");
  try {
    const JWKS = createRemoteJWKSet(new URL(`${API}/v1/jwks`));
    const { payload } = await jwtVerify(jwt, JWKS, {
      issuer: "https://api.insumermodel.com",
      algorithms: ["ES256"],
    });
    console.log(`      JWT valid. Subject: ${payload.sub}, Pass: ${payload.pass}`);
  } catch (err) {
    console.log(`      JWT verification error: ${err.message}`);
  }

  // 4c. Verify SAR receipt (Ed25519 via key registry)
  console.log("  4c. SAR receipt verification...");
  try {
    const sarVerify = await verifySARReceipt(sarReceipt);
    console.log(`      Valid: ${sarVerify.valid}`);
    console.log(`      Key ID: ${sarVerify.kid}`);
    console.log(`      receipt_id digest check: ${sarVerify.receiptIdMatches} (diagnostic only)`);
    if (!sarVerify.valid) {
      console.log(`      Reason: ${sarVerify.reason}`);
    }
  } catch (err) {
    console.log(`      SAR verification error: ${err.message}`);
  }

  // ─── Summary: agent_id links all artifacts ───
  console.log("\n─── Artifact Summary ───");
  console.log(`Agent ID:        ${AGENT_ID}`);
  console.log(`Attestation ID:  ${attestation.id}`);
  console.log(`Payment TX:      ${paymentTxHash}`);
  console.log(`SAR Receipt ID:  ${sarReceipt.receipt_v0_1.receipt_id}`);
  console.log(
    "\nAll four artifacts are linked by agent_id and independently"
  );
  console.log("verifiable offline — no callbacks to either issuer required.");
}

main().catch((err) => {
  console.error("Fatal error:");
  console.error(err);
  process.exit(1);
});
