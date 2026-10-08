/**
 * InsumerAPI — Stellar verification examples
 *
 * Demonstrates Stellar verification scenarios:
 * 1. Native XLM balance check
 * 2. USDC classic-trustline token verification (Centre issuer)
 * 3. BENJI classic-trustline token verification (Franklin issuer)
 * 4. Multi-condition (XLM + USDC trustline in one call)
 * 5. Trust profile with Stellar rows evaluated (requires EVM wallet + stellarWallet)
 *
 * Soroban (smart-contract) balances are NOT visible — classic trustlines only.
 *
 * Usage:
 *   INSUMER_API_KEY=insr_live_... node verify-stellar.js
 *
 * Get a free key:
 *   curl -X POST https://api.insumermodel.com/v1/keys/create \
 *     -H "Content-Type: application/json" \
 *     -d '{"email": "you@example.com", "appName": "stellar-demo", "tier": "free"}'
 */

const API = "https://api.insumermodel.com";
const KEY = process.env.INSUMER_API_KEY;

if (!KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

const headers = { "Content-Type": "application/json", "X-API-Key": KEY };

// Well-known Stellar issuers (classic trustlines)
const USDC_ISSUER = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const BENJI_ISSUER = "GBHNGLLIE3KWGKCHIKMHJ5HVZHYIK7WTBE4QF5PLAKL4CJGSEU7HZIW5";

// Demo wallet — replace with any G-address that holds a Stellar trustline
const STELLAR_WALLET = "GA222ECMS2ASZYKWS3ALJ2SS66IJ72EP5QOCX5RIZCHDNU57YFLC2WSO";

async function attest(body) {
  const res = await fetch(`${API}/v1/attest`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  return res.json();
}

async function trust(body) {
  const res = await fetch(`${API}/v1/trust`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  return res.json();
}

function printResult(label, result) {
  console.log(`\n${"=".repeat(60)}`);
  console.log(label);
  console.log("=".repeat(60));

  if (!result.ok) {
    console.log("Error:", result.error || result.message || "Unknown error");
    return;
  }

  if (result.data.attestation) {
    const { pass, results } = result.data.attestation;
    console.log(`Pass: ${pass}`);
    for (const r of results) {
      console.log(`  ${r.label}: ${r.met ? "PASS" : "FAIL"}`);
    }
    console.log(`Signature: ${result.data.sig.slice(0, 50)}...`);
  } else if (result.data.trust) {
    const tp = result.data.trust;
    console.log(`Trust ID: ${tp.id}`);
    const dims = Object.keys(tp.dimensions);
    console.log(`Dimensions: ${dims.length}`);
    for (const name of dims) {
      const dim = tp.dimensions[name];
      console.log(`  ${name}: ${dim.passCount}/${dim.total} passed`);
      for (const c of dim.checks) {
        console.log(`    ${c.met ? "[+]" : "[-]"} ${c.label}`);
      }
    }
    console.log(`Overall: ${tp.summary.totalPassed}/${tp.summary.totalChecks} checks passed`);
    console.log(`Signature: ${result.data.sig.slice(0, 50)}...`);
  } else {
    console.log(JSON.stringify(result.data, null, 2));
  }
}

async function main() {
  console.log(`Stellar wallet: ${STELLAR_WALLET}\n`);

  // 1. Native XLM
  printResult(
    "1. Native XLM balance (>= 1 XLM)",
    await attest({
      stellarWallet: STELLAR_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: "native",
          chainId: "stellar",
          threshold: "1",
          label: "XLM >= 1",
        },
      ],
    })
  );

  // 2. USDC trustline (Centre)
  printResult(
    "2. USDC trustline (>= 1 USDC)",
    await attest({
      stellarWallet: STELLAR_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: USDC_ISSUER,
          chainId: "stellar",
          assetCode: "USDC",
          threshold: "1",
          label: "USDC >= 1",
        },
      ],
    })
  );

  // 3. BENJI trustline (Franklin)
  printResult(
    "3. BENJI trustline (>= 1 BENJI)",
    await attest({
      stellarWallet: STELLAR_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: BENJI_ISSUER,
          chainId: "stellar",
          assetCode: "BENJI",
          threshold: "1",
          label: "BENJI >= 1",
        },
      ],
    })
  );

  // 4. Multi-condition: XLM + USDC trustline in one call
  printResult(
    "4. Multi-condition: XLM + USDC in one call",
    await attest({
      stellarWallet: STELLAR_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: "native",
          chainId: "stellar",
          threshold: "1",
          label: "XLM >= 1",
        },
        {
          type: "token_balance",
          contractAddress: USDC_ISSUER,
          chainId: "stellar",
          assetCode: "USDC",
          threshold: "1",
          label: "USDC >= 1",
        },
      ],
    })
  );

  // 5. Wallet trust profile with Stellar rows evaluated
  // Trust profiles require an EVM wallet as the base. Pass stellarWallet
  // to evaluate the Stellar trustline rows (USDC, BENJI) that sit inside
  // institutional_stablecoins. Stellar adds no dimension of its own.
  printResult(
    "5. Trust profile with Stellar rows evaluated",
    await trust({
      wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      stellarWallet: STELLAR_WALLET,
    })
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
