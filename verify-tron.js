/**
 * InsumerAPI — Tron verification examples
 *
 * Demonstrates Tron verification scenarios:
 * 1. Native TRX balance check
 * 2. USDT-TRC20 token balance
 * 3. Multi-condition (TRX + USDT-TRC20 in one call)
 * 4. Trust profile with Tron dimension (requires EVM wallet + tronWallet)
 *
 * Usage:
 *   INSUMER_API_KEY=insr_live_... node verify-tron.js
 *
 * Get a free key:
 *   curl -X POST https://api.insumermodel.com/v1/keys/create \
 *     -H "Content-Type: application/json" \
 *     -d '{"email": "you@example.com", "appName": "tron-demo", "tier": "free"}'
 */

const API = "https://api.insumermodel.com";
const KEY = process.env.INSUMER_API_KEY;

if (!KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

const headers = { "Content-Type": "application/json", "X-API-Key": KEY };

// Well-known Tron contracts
const USDT_TRC20 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

// Demo wallet — Binance hot wallet, holds USDT-TRC20. Replace with any T-address.
const TRON_WALLET = "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX";

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
  console.log(`Tron wallet: ${TRON_WALLET}\n`);

  // 1. Native TRX balance
  printResult(
    "1. Native TRX balance (>= 1 TRX)",
    await attest({
      tronWallet: TRON_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: "native",
          chainId: "tron",
          threshold: "1",
          label: "TRX >= 1",
        },
      ],
    })
  );

  // 2. USDT-TRC20
  printResult(
    "2. USDT-TRC20 balance (>= 1 USDT)",
    await attest({
      tronWallet: TRON_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: USDT_TRC20,
          chainId: "tron",
          threshold: "1",
          label: "USDT-TRC20 >= 1",
        },
      ],
    })
  );

  // 3. Multi-condition: TRX + USDT-TRC20 in one call
  printResult(
    "3. Multi-condition: TRX + USDT-TRC20 in one call",
    await attest({
      tronWallet: TRON_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: "native",
          chainId: "tron",
          threshold: "1",
          label: "TRX >= 1",
        },
        {
          type: "token_balance",
          contractAddress: USDT_TRC20,
          chainId: "tron",
          threshold: "1",
          label: "USDT-TRC20 >= 1",
        },
      ],
    })
  );

  // 4. Wallet trust profile with Tron dimension
  // Trust profiles require an EVM wallet as the base. Pass tronWallet
  // to add the tron dimension: three checks (USDT, USD1, WBTC on Tron).
  printResult(
    "4. Trust profile with Tron dimension",
    await trust({
      wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      tronWallet: TRON_WALLET,
    })
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
