/**
 * InsumerAPI — Node.js example
 *
 * A lightweight Express server that:
 * 1. Verifies on-chain token holdings via POST /v1/attest
 * 2. Checks merchant discounts via GET /v1/discount/check
 * 3. Returns the signed attestation response exactly as issued, under `signed`
 *    ({ ok, data: { attestation, sig, kid, pqSig, pqKid } }), so the caller can
 *    verify it offline: `await verifyAttestation(body.signed)` with insumer-verify
 *
 * Usage:
 *   INSUMER_API_KEY=insr_live_... node verify.js
 *   curl -X POST http://localhost:3000/verify -H "Content-Type: application/json" \
 *     -d '{"wallet": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"}'
 */

const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const API = "https://api.insumermodel.com";
const KEY = process.env.INSUMER_API_KEY;

if (!KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

const headers = { "Content-Type": "application/json", "X-API-Key": KEY };

// The attestation response exactly as the API issued it: the attestation object,
// its ECDSA signature and kid, and the post-quantum signature (pqSig, pqKid).
// Pass it unchanged to insumer-verify's verifyAttestation(); do not rebuild or
// re-order the attestation, because the v1 scheme signs bare JSON.stringify output.
function signedResponse(result) {
  const { attestation, sig, kid, pqSig, pqKid } = result.data;
  return { ok: true, data: { attestation, sig, kid, pqSig, pqKid } };
}

// --- 1. Verify token holdings ---
// POST /verify { wallet, conditions? }
// If no conditions provided, checks SHIB on Ethereum as a demo.

app.post("/verify", async (req, res) => {
  const { wallet, conditions } = req.body;

  if (!wallet) {
    return res.status(400).json({ error: "wallet is required" });
  }

  const defaultConditions = [
    {
      type: "token_balance",
      contractAddress: "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",
      chainId: 1,
      threshold: "1000000",
      label: "SHIB holder",
    },
  ];

  const attestRes = await fetch(`${API}/v1/attest`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      wallet,
      conditions: conditions || defaultConditions,
    }),
  });

  const result = await attestRes.json();

  if (!result.ok) {
    // rpc_failure = data source unavailable, retryable after 2-5s
    // NOT a verification failure — do not treat as pass: false
    if (attestRes.status === 503 && result.error?.code === "rpc_failure") {
      return res.status(503).json({
        error: "rpc_failure",
        message: "Data source temporarily unavailable — retry after 2-5 seconds",
        failedConditions: result.error.failedConditions,
      });
    }
    return res.status(attestRes.status).json(result);
  }

  res.json({
    wallet,
    pass: result.data.attestation.pass,
    results: result.data.attestation.results,
    signed: signedResponse(result),
  });
});

// --- 2. Check merchant discount ---
// GET /discount?wallet=0x...&merchant=MERCHANT_ID

app.get("/discount", async (req, res) => {
  const { wallet, merchant } = req.query;

  if (!wallet || !merchant) {
    return res.status(400).json({ error: "wallet and merchant are required" });
  }

  const discountRes = await fetch(
    `${API}/v1/discount/check?wallet=${wallet}&merchant=${merchant}`,
    { headers }
  );

  const result = await discountRes.json();

  if (!result.ok) {
    return res.status(discountRes.status).json(result);
  }

  const { data } = result;

  if (!data.eligible) {
    return res.json({ eligible: false, message: "No qualifying tokens found" });
  }

  res.json({
    eligible: true,
    totalDiscount: data.totalDiscount,
    // Present only when the store gives wallets without proof less: the
    // discount this wallet gets once it proves ownership (walletProof).
    ...(data.discountIfProven !== undefined && { discountIfProven: data.discountIfProven }),
    merchant: data.merchantName,
    breakdown: data.breakdown.map((t) => ({
      token: t.symbol,
      tier: t.tier,
      discount: t.discount,
    })),
  });
});

// --- 3. Multi-condition verification ---
// POST /multi-verify { wallet, conditions: [...] }
// Example: check both token balance AND NFT ownership in one call.

app.post("/multi-verify", async (req, res) => {
  const { wallet, conditions } = req.body;

  if (!wallet || !conditions || !conditions.length) {
    return res.status(400).json({ error: "wallet and conditions[] are required" });
  }

  if (conditions.length > 10) {
    return res.status(400).json({ error: "Maximum 10 conditions per call" });
  }

  const attestRes = await fetch(`${API}/v1/attest`, {
    method: "POST",
    headers,
    body: JSON.stringify({ wallet, conditions }),
  });

  const result = await attestRes.json();

  if (!result.ok) {
    return res.status(attestRes.status).json(result);
  }

  const { attestation } = result.data;

  res.json({
    wallet,
    allPassed: attestation.pass,
    results: attestation.results.map((r) => ({
      label: r.label,
      met: r.met,
    })),
    signed: signedResponse(result),
  });
});

// --- 4. XRPL verification ---
// POST /verify-xrpl { xrplWallet, conditions? }
// If no conditions provided, checks native XRP >= 100 as a demo.

app.post("/verify-xrpl", async (req, res) => {
  const { xrplWallet, conditions } = req.body;

  if (!xrplWallet) {
    return res.status(400).json({ error: "xrplWallet is required" });
  }

  const defaultConditions = [
    {
      type: "token_balance",
      contractAddress: "native",
      chainId: "xrpl",
      threshold: "100",
      label: "XRP >= 100",
    },
  ];

  const attestRes = await fetch(`${API}/v1/attest`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      xrplWallet,
      conditions: conditions || defaultConditions,
    }),
  });

  const result = await attestRes.json();

  if (!result.ok) {
    return res.status(attestRes.status).json(result);
  }

  res.json({
    xrplWallet,
    pass: result.data.attestation.pass,
    results: result.data.attestation.results,
    signed: signedResponse(result),
  });
});

app.listen(3000, () => {
  console.log("InsumerAPI example server running on http://localhost:3000");
  console.log("");
  console.log("Endpoints:");
  console.log("  POST /verify         — Verify EVM token holdings");
  console.log("  GET  /discount       — Check merchant discount");
  console.log("  POST /multi-verify   — Multi-condition verification");
  console.log("  POST /verify-xrpl    — Verify XRPL token holdings");
});
