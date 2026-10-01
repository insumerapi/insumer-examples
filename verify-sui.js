/**
 * InsumerAPI — Sui verification examples
 *
 * Demonstrates Sui verification scenarios:
 * 1. Native SUI balance check
 * 2. USDC on Sui (Sui-native token) balance
 * 3. Multi-condition (SUI + USDC in one call)
 * 4. Trust profile with Sui institutional dimension (requires EVM wallet + suiWallet)
 *
 * Sui conditions take a coin type (`address::module::Name`) as `contractAddress`:
 * "0x2::sui::SUI" for native SUI, "0xdba34672...::usdc::USDC" for USDC.
 *
 * Usage:
 *   INSUMER_API_KEY=insr_live_... node verify-sui.js
 *
 * Get a free key:
 *   curl -X POST https://api.insumermodel.com/v1/keys/create \
 *     -H "Content-Type: application/json" \
 *     -d '{"email": "you@example.com", "appName": "sui-demo", "tier": "free"}'
 */

const API = "https://api.insumermodel.com";
const KEY = process.env.INSUMER_API_KEY;

if (!KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

const headers = { "Content-Type": "application/json", "X-API-Key": KEY };

// Well-known Sui coin type strings. Native SUI is a coin type too: the string
// "native" is not accepted on Sui.
const SUI_NATIVE = "0x2::sui::SUI";
const USDC_SUI = "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC";

// Demo wallet — Sui Foundation address `0x5` (always has SUI + USDC).
// Replace with any Sui address (0x + 64 hex).
const SUI_WALLET = "0x0000000000000000000000000000000000000000000000000000000000000005";

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
  console.log(`Sui wallet: ${SUI_WALLET}\n`);

  // 1. Native SUI
  printResult(
    "1. Native SUI balance (>= 1 SUI)",
    await attest({
      suiWallet: SUI_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: SUI_NATIVE,
          chainId: "sui",
          threshold: "1",
          label: "SUI >= 1",
        },
      ],
    })
  );

  // 2. USDC on Sui
  printResult(
    "2. USDC on Sui (>= 1 USDC)",
    await attest({
      suiWallet: SUI_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: USDC_SUI,
          chainId: "sui",
          threshold: "1",
          label: "USDC on Sui >= 1",
        },
      ],
    })
  );

  // 3. Multi-condition: SUI + USDC in one call
  printResult(
    "3. Multi-condition: SUI + USDC in one call",
    await attest({
      suiWallet: SUI_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: SUI_NATIVE,
          chainId: "sui",
          threshold: "1",
          label: "SUI >= 1",
        },
        {
          type: "token_balance",
          contractAddress: USDC_SUI,
          chainId: "sui",
          threshold: "1",
          label: "USDC >= 1",
        },
      ],
    })
  );

  // 4. Wallet trust profile with Sui rows evaluated
  // Trust profiles require an EVM wallet as the base. Pass suiWallet
  // to evaluate the Sui rows that sit inside the base dimensions (USDC in
  // institutional_stablecoins, USDY in tokenized_treasuries). Sui adds no
  // dimension of its own.
  printResult(
    "4. Trust profile with Sui rows evaluated",
    await trust({
      wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      suiWallet: SUI_WALLET,
    })
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
