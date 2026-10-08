/**
 * InsumerAPI — XRPL verification examples
 *
 * Demonstrates every XRPL verification scenario:
 * 1. Native XRP balance check
 * 2. RLUSD trust line token verification
 * 3. USDC trust line token verification
 * 4. Multi-condition (XRP + RLUSD in one call)
 * 5. NFT ownership on XRPL
 * 6. Trust profile with the XRPL dimension (requires EVM wallet + xrplWallet)
 *
 * Usage:
 *   INSUMER_API_KEY=insr_live_... node verify-xrpl.js
 *
 * Get a free key:
 *   curl -X POST https://api.insumermodel.com/v1/keys/create \
 *     -H "Content-Type: application/json" \
 *     -d '{"email": "you@example.com", "appName": "xrpl-demo", "tier": "free"}'
 */

const API = "https://api.insumermodel.com";
const KEY = process.env.INSUMER_API_KEY;

if (!KEY) {
  console.error("Set INSUMER_API_KEY environment variable");
  process.exit(1);
}

const headers = { "Content-Type": "application/json", "X-API-Key": KEY };

// Well-known XRPL issuers
const RLUSD_ISSUER = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De";
const USDC_ISSUER = "rGm7WCVp9gb4jZHWTEtGUr4dd74z2XuWhE";

// Demo wallet — replace with any r-address
const XRPL_WALLET = "rG1QQv2nh2gr7RCZ1P8YYcBUKCCN633jCn";

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
  console.log(`XRPL wallet: ${XRPL_WALLET}\n`);

  // 1. Native XRP balance
  printResult(
    "1. Native XRP balance (>= 100 XRP)",
    await attest({
      xrplWallet: XRPL_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: "native",
          chainId: "xrpl",
          threshold: "100",
          label: "XRP >= 100",
        },
      ],
    })
  );

  // 2. RLUSD trust line
  printResult(
    "2. RLUSD trust line (>= 10 RLUSD)",
    await attest({
      xrplWallet: XRPL_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: RLUSD_ISSUER,
          chainId: "xrpl",
          currency: "RLUSD",
          threshold: "10",
          label: "RLUSD >= 10",
        },
      ],
    })
  );

  // 3. USDC trust line
  printResult(
    "3. USDC trust line (>= 1 USDC)",
    await attest({
      xrplWallet: XRPL_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: USDC_ISSUER,
          chainId: "xrpl",
          currency: "USDC",
          threshold: "1",
          label: "USDC >= 1",
        },
      ],
    })
  );

  // 4. Multi-condition: XRP + RLUSD in one call
  printResult(
    "4. Multi-condition: XRP + RLUSD in one call",
    await attest({
      xrplWallet: XRPL_WALLET,
      conditions: [
        {
          type: "token_balance",
          contractAddress: "native",
          chainId: "xrpl",
          threshold: "50",
          label: "XRP >= 50",
        },
        {
          type: "token_balance",
          contractAddress: RLUSD_ISSUER,
          chainId: "xrpl",
          currency: "RLUSD",
          threshold: "10",
          label: "RLUSD >= 10",
        },
      ],
    })
  );

  // 5. NFT ownership
  // contractAddress is the issuer r-address of the collection (add taxon to
  // narrow it to one collection). This issuer is a live XRPL NFT issuer; the
  // example wallet holds none of its NFTs, so the signed answer is false.
  printResult(
    "5. NFT ownership on XRPL",
    await attest({
      xrplWallet: XRPL_WALLET,
      conditions: [
        {
          type: "nft_ownership",
          contractAddress: "rUDRQfn1hr84kVqQ42BoLgBsLtRgMWD4k5",
          chainId: "xrpl",
          label: "XRPL NFT holder",
        },
      ],
    })
  );

  // 6. Wallet trust profile with the XRPL dimension
  // Trust profiles require an EVM wallet as the base. Pass xrplWallet
  // to add the xrpl dimension (RLUSD, USDC, OUSG trust lines).
  printResult(
    "6. Trust profile with the XRPL dimension",
    await trust({
      wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      xrplWallet: XRPL_WALLET,
    })
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
