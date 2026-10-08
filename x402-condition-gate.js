/**
 * InsumerAPI x402 Condition Gate — reference endpoint
 *
 * An x402-protected resource that checks the PAYER's on-chain wallet
 * eligibility BEFORE charging. Wallets that meet the conditions get the
 * resource for free; everyone else falls through to the normal x402 paid
 * flow. One signed call sits between the payment request and the charge.
 *
 * The trust split this demonstrates:
 *   - x402 (and Visa's Trusted Agent Protocol, and MPP) authenticate the
 *     AGENT and its payment — identity and membership.
 *   - InsumerAPI attests the WALLET's eligibility — a signed boolean over
 *     on-chain state, verifiable offline via JWKS. A different question:
 *     not "who is this agent" but "is this wallet allowed to buy this."
 *
 * Soundness: the payer wallet is read from the SIGNED x402 payment payload
 * (payload.authorization.from) and the EIP-3009 signature is verified before
 * the wallet is trusted. A request that claims someone else's wallet fails
 * signature recovery and never reaches the eligibility check — no spoofing.
 * In a production deployment this verification is performed by the x402
 * facilitator's verify step; it is shown inline here so the demo is
 * self-contained and the anti-spoofing property is visible.
 *
 * This endpoint is a CALLER of /v1/attest. It does not re-sign or wrap the
 * attestation; the only signature over wallet state is the one InsumerAPI
 * produced. The endpoint forwards that signature and the attestation id so a
 * client can verify the verdict offline against the public JWKS.
 *
 * Usage:
 *   npm install express viem
 *   INSUMER_API_KEY=insr_live_... node x402-condition-gate.js
 *
 * Get a free API key (10 free verifications plus 100 requests a day):
 *   bash quickstart.sh
 *   # or:
 *   curl -s -X POST https://api.insumermodel.com/v1/keys/create \
 *     -H "Content-Type: application/json" \
 *     -d '{"email":"you@example.com","appName":"x402-gate","tier":"free"}'
 *
 * Then exercise it:
 *   node x402-condition-gate-test.js
 */

const express = require("express");
const { recoverTypedDataAddress } = require("viem");

const API = "https://api.insumermodel.com";
const KEY = process.env.INSUMER_API_KEY;

if (!KEY) {
  console.error("Set INSUMER_API_KEY environment variable (see quickstart.sh)");
  process.exit(1);
}

// ─── Resource pricing (x402 "exact" scheme over USDC on Base) ───
// Public mainnet constants. USDC's EIP-3009 domain is fixed and public.
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const BASE_CHAIN_ID = 8453;
const PRICE_ATOMIC = "10000"; // 0.01 USDC (6 decimals)
const PAY_TO = "0x0000000000000000000000000000000000000000"; // set to your address

// ─── Eligibility conditions evaluated against the authenticated payer ───
// Swap these for whatever should grant free access. Here: holds USDC on Base.
const CONDITIONS = [
  {
    type: "token_balance",
    contractAddress: USDC_BASE,
    chainId: BASE_CHAIN_ID,
    threshold: "1",
    label: "Holds USDC on Base",
  },
];

// ─── Alternative: a self-scaling agent-spend gate (ratio_to_amount) ───
// x402 (and AP2, ACP, MPP) authorize agent spending with FLAT caps. A
// `ratio_to_amount` condition instead ties eligibility to the size of THIS
// payment: the payer must hold at least `multiple`× the amount it is paying.
// One rule scales to every transaction — no per-amount re-tuning — and it
// means the same thing on any EVM chain or token. `amount` is in token/display
// units (not atomic), so it is derived from the x402 payment value. RPC EVM
// chains only. Try it live by adding `?gate=ratio` to the /premium request.
function selfScalingConditions(amountAtomicStr, decimals = 6) {
  const amount = Number(amountAtomicStr) / Math.pow(10, decimals);
  return [
    {
      type: "ratio_to_amount",
      contractAddress: USDC_BASE,
      chainId: BASE_CHAIN_ID,
      multiple: "10", // v2 keys take ratio quantities as decimal strings
      amount: String(amount), // met iff the payer holds >= 10x the USDC paid in this x402 call
      label: `Holds >= 10x the ${amount} USDC payment`,
    },
  ];
}

// EIP-3009 TransferWithAuthorization typed-data, used to authenticate the payer.
const EIP3009_DOMAIN = {
  name: "USD Coin",
  version: "2",
  chainId: BASE_CHAIN_ID,
  verifyingContract: USDC_BASE,
};
const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

/**
 * Build the x402 402 Payment Required body (PaymentRequired shape).
 * @param {string} resourceUrl - absolute URL of the protected resource
 * @returns {object} the 402 response body
 */
function paymentRequired(resourceUrl) {
  return {
    x402Version: 2,
    error: "payment required",
    resource: { url: resourceUrl, description: "Premium data feed", mimeType: "application/json" },
    accepts: [
      {
        scheme: "exact",
        network: `eip155:${BASE_CHAIN_ID}`,
        asset: USDC_BASE,
        amount: PRICE_ATOMIC,
        payTo: PAY_TO,
        maxTimeoutSeconds: 300,
        extra: {},
      },
    ],
  };
}

/**
 * Recover the signer of an x402 "exact" EVM payment and confirm it matches the
 * claimed `from`. Returns the authenticated wallet, or null if the signature
 * does not bind to the claimed address (a spoofed wallet).
 * @param {object} exactPayload - the decoded payload.payload (ExactEvmPayload)
 * @returns {Promise<string|null>} authenticated payer address, or null
 */
async function authenticatePayer(exactPayload) {
  const { signature, authorization } = exactPayload || {};
  if (!signature || !authorization || !authorization.from) return null;

  try {
    const recovered = await recoverTypedDataAddress({
      domain: EIP3009_DOMAIN,
      types: EIP3009_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        from: authorization.from,
        to: authorization.to,
        value: BigInt(authorization.value),
        validAfter: BigInt(authorization.validAfter),
        validBefore: BigInt(authorization.validBefore),
        nonce: authorization.nonce,
      },
      signature,
    });
    // The signature is authentic only if it recovers to the claimed wallet.
    if (recovered.toLowerCase() === authorization.from.toLowerCase()) {
      return authorization.from;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Evaluate the authenticated wallet against the given conditions.
 * Returns the raw InsumerAPI attestation (signed, JWKS-verifiable). The
 * endpoint never re-signs this — it forwards InsumerAPI's signature as-is.
 * @param {string} wallet - authenticated payer address
 * @param {object[]} [conditions=CONDITIONS] - conditions to evaluate
 * @returns {Promise<object>} the attestation response data
 */
async function attest(wallet, conditions = CONDITIONS) {
  const res = await fetch(`${API}/v1/attest`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": KEY },
    body: JSON.stringify({ wallet, conditions, format: "jwt" }),
  });
  const body = await res.json();
  if (!body.ok) {
    const msg = body.error && body.error.message ? body.error.message : `HTTP ${res.status}`;
    throw new Error(`attest failed: ${msg}`);
  }
  return body.data;
}

const app = express();
app.use(express.json());

// The protected resource. No payment → 402. Paid → gate on wallet eligibility.
app.get("/premium", async (req, res) => {
  const resourceUrl = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
  // x402 v2 clients send PAYMENT-SIGNATURE; v1 clients send X-PAYMENT.
  const paymentHeader = req.get("PAYMENT-SIGNATURE") || req.get("X-PAYMENT");

  // Step 1: no payment presented → ask for one (standard x402 402).
  if (!paymentHeader) {
    return res.status(402).json(paymentRequired(resourceUrl));
  }

  // Step 2: decode the signed payment payload.
  let payment;
  try {
    payment = JSON.parse(Buffer.from(paymentHeader, "base64").toString("utf8"));
  } catch {
    return res.status(402).json(paymentRequired(resourceUrl));
  }

  // Step 3: authenticate the payer from the SIGNED payload (anti-spoof).
  const wallet = await authenticatePayer(payment.payload);
  if (!wallet) {
    return res.status(402).json({
      ...paymentRequired(resourceUrl),
      error: "payment signature did not authenticate the claimed wallet",
    });
  }

  // Step 4: eligibility check — the one signed call between request and charge.
  // Default gate: holds USDC on Base. With `?gate=ratio`, gate on a self-scaling
  // rule instead — holds >= 10x the amount being paid in THIS x402 call.
  const conditions =
    req.query.gate === "ratio"
      ? selfScalingConditions(payment.payload.authorization.value)
      : CONDITIONS;
  let data;
  try {
    data = await attest(wallet, conditions);
  } catch (err) {
    // Eligibility service unavailable → fall through to the normal paid flow.
    return res.status(402).json({ ...paymentRequired(resourceUrl), error: String(err.message) });
  }

  const passed = data.attestation.pass;

  if (passed) {
    // Eligible wallet → serve for free. Forward InsumerAPI's signature and
    // attestation id so the client can verify the verdict offline (JWKS).
    res.set("X-Eligibility-Attestation", data.attestation.id);
    res.set("X-Eligibility-Signature", data.sig);
    return res.status(200).json({
      data: "premium payload — granted free via wallet eligibility",
      eligibility: {
        attestationId: data.attestation.id,
        pass: true,
        verifyOffline: `${API}/v1/jwks`,
      },
    });
  }

  // Not eligible → normal x402 paid flow. In production the resource server
  // calls the x402 facilitator's settle step here to capture the signed
  // payment, then serves. Settlement is the facilitator's responsibility and
  // is intentionally not reimplemented in this reference.
  res.set("X-Eligibility-Attestation", data.attestation.id);
  return res.status(200).json({
    data: "premium payload — served via normal x402 payment (wallet not eligible for free access)",
    eligibility: { attestationId: data.attestation.id, pass: false },
    settlement: "delegated to x402 facilitator (settle step)",
  });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`x402 condition gate listening on http://localhost:${PORT}/premium`);
    console.log(`Conditions: ${CONDITIONS.map((c) => c.label).join(", ")}`);
    console.log(`Add ?gate=ratio to gate on a self-scaling rule (hold >= 10x the payment).`);
  });
}

module.exports = { app, authenticatePayer, attest, selfScalingConditions, paymentRequired, EIP3009_DOMAIN, EIP3009_TYPES };
