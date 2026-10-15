/**
 * AgentTalk Example — Condition-Gated Agent Sessions
 *
 * Demonstrates both AgentTalk flows:
 *
 *   Bilateral (default):
 *     1. Agent A proves control of its wallet, then declares a channel (capacity 2)
 *     2. Agent B proves control, then joins — both wallets attested via InsumerAPI
 *     3. Session established — verify on demand
 *
 *   Multi-party (town hall):
 *     1. Creator proves control, declares a channel with capacity + autoStart
 *     2. Agents prove control and join a live session — each attested on entry
 *     3. Re-verify ejects agents who lose credentials
 *     4. Creator can kick (action: "kick"), agents can leave (action: "leave")
 *        — each action signed by the wallet whose authority it invokes
 *
 * Proof-of-control: on-chain holdings are public, so naming a wallet proves
 * nothing. Before any action, the agent signs a one-time challenge with the
 * wallet's key. Control of the wallet — not knowledge of its address — is what
 * grants entry.
 *
 * Wallets: by default this generates fresh, throwaway keypairs. A fresh wallet
 * holds nothing, so the attestation honestly returns pass:false against a real
 * token condition — that is the security property, not a bug: you cannot fake
 * holdings, and you cannot borrow someone else's qualifying address. To see a
 * real PASS, point at a wallet you actually control and fund:
 *
 *     DEMO_PRIVATE_KEY=0xYOURKEY node agenttalk-example.js
 *
 * That key is read only at runtime and never leaves your machine. In production
 * each agent uses its own funded wallet and its own key, which it never ships.
 *
 * API: https://agenttalk.skyemeta.com/api/agenttalk/
 * Docs: https://agenttalk.skyemeta.com/llms-full.txt
 *
 * Requires: viem (already a dependency of this repo) for keypair + signing.
 *
 * Usage:
 *   node agenttalk-example.js                                    # bilateral (2 agents)
 *   node agenttalk-example.js multiparty                         # multi-party (3 agents)
 *   DEMO_PRIVATE_KEY=0x... node agenttalk-example.js             # gate on a real wallet
 *
 * No API key: the service authenticates each action by the wallet signature over
 * its one-time challenge, and bills declare calls to the declaring wallet (a free
 * allowance, then credits bought with USDC via POST /api/agenttalk/buy-key).
 */

const https = require("https");
const { privateKeyToAccount, generatePrivateKey } = require("viem/accounts");

const BASE_URL = "https://agenttalk.skyemeta.com/api/agenttalk";

// A real token condition: hold >= 1 USDC on Ethereum. A fresh wallet fails it
// honestly; a funded wallet (via DEMO_PRIVATE_KEY) passes it.
const CONDITIONS = [
  {
    type: "token_balance",
    contractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    chainId: 1,
    threshold: "1",
    label: "USDC on Ethereum",
  },
];

/**
 * POST or GET request. Returns parsed JSON.
 */
function request(url, options) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const opts = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: options.method || "GET",
      headers: options.headers || {},
    };

    const req = https.request(opts, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch (e) {
          reject(new Error(`Invalid JSON from ${url}: ${data}`));
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(15000, () => {
      req.destroy();
      reject(new Error(`Timeout: ${url}`));
    });
    if (options.body) req.write(options.body);
    req.end();
  });
}

/**
 * Build an account from an env-supplied private key, or a fresh throwaway one.
 * `envName` lets each agent optionally use its own funded wallet.
 */
function makeAccount(envName) {
  const pk =
    (envName && process.env[envName]) ||
    process.env.DEMO_PRIVATE_KEY ||
    generatePrivateKey();
  return privateKeyToAccount(pk);
}

/**
 * Prove control of `account` for `action`: fetch a one-time challenge, sign the
 * returned message (EIP-191), return the signature to pass to the action.
 */
async function proveControl(account, action) {
  const res = await request(`${BASE_URL}/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ wallet: account.address, action }),
  });
  if (res.status !== 200 || !res.data.message) {
    throw new Error(`challenge failed: ${JSON.stringify(res.data)}`);
  }
  return account.signMessage({ message: res.data.message });
}

// Interpret a declare/join response. Returns the data on success (HTTP 200), or
// null after explaining the outcome.
//
// A 403 with pass:false means the signature was accepted (control proven) but the
// wallet was not admitted: either a condition is not met, or no verdict could be
// produced for it at that moment. The body does not say which, so treat it as
// "not admitted" — expected for a fresh throwaway wallet — and retry later if you
// expect the wallet to qualify. A 503 is handled the same way: retry later.
function handleGate(label, res) {
  if (res.status === 200 && (res.data.channelId || res.data.sessionId)) return res.data;
  if (res.status === 403 && res.data && res.data.pass === false) {
    console.log(`\n   Proof-of-control accepted — the signature passed server verification.`);
    console.log(`   Not admitted: ${label} did not open a session. Either the wallet does not`);
    console.log(`   meet the condition (expected for a fresh throwaway wallet), or no verdict`);
    console.log(`   could be produced just now. If this wallet should qualify, retry later.`);
    console.log(`   Set DEMO_PRIVATE_KEY to a funded wallet that satisfies the condition to`);
    console.log(`   complete the full flow.`);
    return null;
  }
  if (res.status === 503) {
    console.log(`\n   Service temporarily unavailable (503): ${label} was not decided. Retry later.`);
    return null;
  }
  console.log(`   FAILED (${res.status}):`, JSON.stringify(res.data));
  return null;
}

function printAgents(agents) {
  console.log(`   Agents attested: ${agents.length}`);
  for (const agent of agents) {
    const att = agent.attestation.attestation;
    console.log(`     ${agent.wallet}`);
    console.log(`       pass: ${att.pass}, id: ${att.id}`);
    console.log(`       sig: ${agent.attestation.sig.substring(0, 30)}...`);
    console.log(`       kid: ${agent.attestation.kid}`);
    console.log(`       jwt: ${agent.attestation.jwt ? "present" : "none"}`);
  }
}

// ─── Bilateral flow (capacity 2, default) ───────────────────────

async function bilateral() {
  console.log("AgentTalk — Bilateral Session (2 agents)");
  console.log("=".repeat(60));
  console.log("");

  const agentA = makeAccount("DEMO_PRIVATE_KEY_A");
  const agentB = makeAccount("DEMO_PRIVATE_KEY_B");

  // --- Step 1: Prove control + declare channel ---
  console.log("1. Agent A proves control and declares a bilateral channel...");
  console.log(`   Wallet: ${agentA.address}`);
  console.log(`   Condition: Hold >= 1 USDC on Ethereum\n`);

  const headers = { "Content-Type": "application/json" };

  const declareSig = await proveControl(agentA, "declare");
  const declareRes = await request(`${BASE_URL}/declare`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      wallet: agentA.address,
      signature: declareSig,
      conditions: CONDITIONS,
      expiresIn: 300,
    }),
  });

  if (!handleGate("declare", declareRes)) return;

  const { channelId, conditionsHash, expiresAt } = declareRes.data;
  console.log(`   Channel: ${channelId}`);
  console.log(`   Capacity: ${declareRes.data.capacity || 2}`);
  console.log(`   Conditions hash: ${conditionsHash}`);
  console.log(`   Expires: ${expiresAt}\n`);

  // --- Step 2: Prove control + join channel ---
  console.log("2. Agent B proves control and joins the channel...");
  console.log(`   Wallet: ${agentB.address}\n`);

  const joinSig = await proveControl(agentB, "join");
  const joinRes = await request(`${BASE_URL}/join`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ channelId, wallet: agentB.address, signature: joinSig }),
  });

  if (!handleGate("join", joinRes)) return;

  const { sessionId, agents } = joinRes.data;
  console.log(`   Session: ${sessionId}`);
  printAgents(agents);

  // --- Step 3: Verify session ---
  console.log("\n3. Verify session...");

  const verifyRes = await request(`${BASE_URL}/session?id=${sessionId}`, {
    method: "GET",
  });

  if (verifyRes.status === 200) {
    const s = verifyRes.data;
    console.log(`   Valid: ${s.valid}`);
    console.log(`   Agents: ${s.agents.length}`);
    console.log(`   Conditions: ${s.conditions.length}`);
    console.log(`   Issued: ${s.issuedAt}`);
    console.log(`   Expires: ${s.expiresAt}`);
  }

  console.log("\n" + "=".repeat(60));
  console.log("Summary:");
  console.log(`  Channel: ${channelId}`);
  console.log(`  Session: ${sessionId}`);
  console.log(`  Both wallets proved control and were attested.`);
  console.log(`  Attestation signatures: ECDSA ES256 (kid: insumer-attest-v2)`);
  console.log(`  JWKS: https://insumermodel.com/.well-known/jwks.json`);
  console.log(`  Conditions hash: ${conditionsHash}`);
  console.log("");
  console.log("Every agent proved control of its wallet and was verified against");
  console.log("the same on-chain conditions. Each attestation is independently");
  console.log("verifiable via JWKS. Lose the credential, get ejected from the room.");
}

// ─── Multi-party flow (capacity N, autoStart) ──────────────────

async function multiparty() {
  console.log("AgentTalk — Multi-Party Session (3 agents, autoStart)");
  console.log("=".repeat(60));
  console.log("");

  const creator = makeAccount("DEMO_PRIVATE_KEY_A");
  const agentB = makeAccount("DEMO_PRIVATE_KEY_B");
  const agentC = makeAccount("DEMO_PRIVATE_KEY_C");

  // --- Step 1: Prove control + declare with capacity + autoStart ---
  console.log("1. Creator proves control and declares a multi-party channel (capacity: 5, autoStart: true)...");
  console.log(`   Wallet: ${creator.address}`);
  console.log(`   Condition: Hold >= 1 USDC on Ethereum\n`);

  const headers = { "Content-Type": "application/json" };

  const declareSig = await proveControl(creator, "declare");
  const declareRes = await request(`${BASE_URL}/declare`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      wallet: creator.address,
      signature: declareSig,
      conditions: CONDITIONS,
      capacity: 5,
      autoStart: true,
      expiresIn: 300,
    }),
  });

  if (!handleGate("declare", declareRes)) return;

  const { channelId, conditionsHash, sessionId, expiresAt } = declareRes.data;
  console.log(`   Channel: ${channelId}`);
  console.log(`   Session (live immediately): ${sessionId}`);
  console.log(`   Capacity: ${declareRes.data.capacity}`);
  console.log(`   Conditions hash: ${conditionsHash}`);
  console.log(`   Expires: ${expiresAt}\n`);

  // --- Step 2: Agent B proves control + joins the live session ---
  console.log("2. Agent B proves control and joins the live session...");
  console.log(`   Wallet: ${agentB.address}\n`);

  const joinSigB = await proveControl(agentB, "join");
  const joinB = await request(`${BASE_URL}/join`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ channelId, wallet: agentB.address, signature: joinSigB }),
  });

  if (!handleGate("join", joinB)) return;

  console.log(`   Session: ${joinB.data.sessionId}`);
  printAgents(joinB.data.agents);
  console.log("");

  // --- Step 3: Agent C proves control + joins too ---
  console.log("3. Agent C proves control and joins the live session...");
  console.log(`   Wallet: ${agentC.address}\n`);

  const joinSigC = await proveControl(agentC, "join");
  const joinC = await request(`${BASE_URL}/join`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ channelId, wallet: agentC.address, signature: joinSigC }),
  });

  if (!handleGate("join", joinC)) return;

  console.log(`   Session: ${joinC.data.sessionId}`);
  printAgents(joinC.data.agents);
  console.log("");

  // --- Step 4: Verify session (all 3 agents) ---
  console.log("4. Verify session (all 3 agents)...");

  const verifyRes = await request(`${BASE_URL}/session?id=${sessionId}`, {
    method: "GET",
  });

  if (verifyRes.status === 200) {
    const s = verifyRes.data;
    console.log(`   Valid: ${s.valid}`);
    console.log(`   Agents: ${s.agents.length}`);
    console.log(`   Capacity: ${s.capacity}`);
    console.log(`   Conditions: ${s.conditions.length}`);
    console.log(`   Issued: ${s.issuedAt}`);
    console.log(`   Expires: ${s.expiresAt}`);
  }

  // --- Step 5: Creator proves control + kicks Agent C ---
  console.log("\n5. Creator proves control and kicks Agent C...");

  const kickSig = await proveControl(creator, "kick");
  const kickRes = await request(`${BASE_URL}/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action: "kick",
      channelId,
      wallet: agentC.address,
      creatorWallet: creator.address,
      signature: kickSig,
    }),
  });

  if (kickRes.status === 200) {
    console.log(`   Kicked: ${kickRes.data.kicked}`);
    console.log(`   Remaining: ${kickRes.data.remainingAgents.join(", ")}`);
  } else {
    console.log("   FAILED:", JSON.stringify(kickRes.data));
  }

  // --- Step 6: Agent B proves control + leaves voluntarily ---
  console.log("\n6. Agent B proves control and leaves voluntarily...");

  const leaveSig = await proveControl(agentB, "leave");
  const leaveRes = await request(`${BASE_URL}/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action: "leave",
      channelId,
      wallet: agentB.address,
      signature: leaveSig,
    }),
  });

  if (leaveRes.status === 200) {
    console.log(`   Left: ${leaveRes.data.left}`);
    console.log(`   Remaining: ${leaveRes.data.remainingAgents?.join(", ") || "(creator only)"}`);
  } else {
    console.log("   FAILED:", JSON.stringify(leaveRes.data));
  }

  console.log("\n" + "=".repeat(60));
  console.log("Summary:");
  console.log(`  Channel: ${channelId}`);
  console.log(`  Session: ${sessionId}`);
  console.log(`  Capacity: 5 (3 joined, 1 kicked, 1 left)`);
  console.log(`  Every action signed by the wallet whose authority it invoked.`);
  console.log(`  Attestation signatures: ECDSA ES256 (kid: insumer-attest-v2)`);
  console.log(`  JWKS: https://insumermodel.com/.well-known/jwks.json`);
  console.log("");
  console.log("Multi-party session: agents prove control, join, get kicked, or leave.");
  console.log("Re-verify ejects anyone who loses a credential. The room stays clean.");
}

// ─── Entry point ────────────────────────────────────────────────

const mode = process.argv[2];

if (mode === "multiparty") {
  multiparty().catch((err) => {
    console.error("Error:", err.message);
    process.exit(1);
  });
} else {
  bilateral().catch((err) => {
    console.error("Error:", err.message);
    process.exit(1);
  });
}
