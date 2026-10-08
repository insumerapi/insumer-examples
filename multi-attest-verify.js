/**
 * Multi-Attestation Verifier
 *
 * Verifies an array of independent attestations from multiple issuers.
 * Each attestation has its own signature, key ID, algorithm, and JWKS endpoint.
 * The verifier resolves each issuer's key from the JWKS the relying party has
 * pinned for that issuer (TRUSTED_ISSUERS below, extendable via options); the
 * entry's own `jwks` is a discovery hint that must match the pinned origin, never
 * the trust root. Unknown issuers fail closed unless discovery mode is opted in.
 *
 * Supported algorithms:
 *   - ES256 (ECDSA P-256) — InsumerAPI, RNWY, Maiat, Revettr, TrustLayer
 *   - EdDSA (Ed25519) — ThoughtProof, APS, AgentID, AgentGraph, SAR
 *
 * No dependencies — uses Node.js built-in crypto and https modules.
 *
 * Usage:
 *   node multi-attest-verify.js
 *
 * Or import as a module:
 *   const { verifyMultiAttestation } = require('./multi-attest-verify');
 *   const result = await verifyMultiAttestation(payload, { requiredTypes: ['wallet_state'] });
 *   // Accept an issuer that is not in the default pin set:
 *   await verifyMultiAttestation(payload, { trustedIssuers: { 'https://issuer.example': 'https://issuer.example/.well-known/jwks.json' } });
 *   // Discovery mode (take `jwks` from the entry for unpinned issuers), opt-in only:
 *   await verifyMultiAttestation(payload, { allowUnpinnedIssuers: true });
 */

const crypto = require("crypto");
const https = require("https");

// --- JWKS cache (in-memory, per-process) ---
const jwksCache = new Map();
const JWKS_CACHE_TTL = 3600 * 1000; // 1 hour

// --- Relying-party key configuration ---
// The trust anchor for each entry is the JWKS the relying party holds for that
// issuer, selected by `kid`. The entry's `jwks` field must match the pinned
// origin; it never selects the key on its own (spec section 4, step 3).
const TRUSTED_ISSUERS = {
  "https://api.insumermodel.com": "https://insumermodel.com/.well-known/jwks.json",
  "https://insumermodel.com": "https://insumermodel.com/.well-known/jwks.json",
  "https://api.thoughtproof.ai": "https://api.thoughtproof.ai/.well-known/jwks.json",
  "https://rnwy.com": "https://rnwy.com/.well-known/jwks.json",
  "https://getagentid.dev": "https://getagentid.dev/.well-known/jwks.json",
  "https://agentgraph.co": "https://agentgraph.co/.well-known/jwks.json",
  "https://gateway.aeoess.com": "https://gateway.aeoess.com/.well-known/jwks.json",
  "https://app.maiat.io": "https://app.maiat.io/.well-known/jwks.json",
  "https://defaultverifier.com": "https://defaultverifier.com/.well-known/jwks.json",
  "https://revettr.com": "https://revettr.com/.well-known/jwks.json",
  "did:web:revettr.com": "https://revettr.com/.well-known/jwks.json",
  "https://api.thetrustlayer.xyz": "https://api.thetrustlayer.xyz/.well-known/jwks.json",
};

function originOf(url) {
  try { return new URL(url).origin; } catch (_) { return null; }
}

/**
 * Resolve which JWKS URL verifies an entry. Returns { jwksUrl } or { error }.
 * Pinned issuer: the entry's `jwks` must share the pinned origin. Unpinned
 * issuer: fail closed unless the relying party opted into discovery mode.
 */
function resolveKeySource(att, trustedIssuers, allowUnpinnedIssuers) {
  const pinned = att.issuer ? trustedIssuers[att.issuer] : undefined;
  if (pinned) {
    if (originOf(att.jwks) !== originOf(pinned)) {
      return { error: `jwks origin mismatch for ${att.issuer}: entry names ${att.jwks}, relying party pins ${pinned}` };
    }
    return { jwksUrl: pinned };
  }
  if (allowUnpinnedIssuers) return { jwksUrl: att.jwks };
  return { error: `Issuer not pinned by the relying party: ${att.issuer || "(missing)"}` };
}

/**
 * Fetch JSON over HTTPS. Returns parsed JSON.
 */
function fetchJSON(url, maxRedirects) {
  maxRedirects = maxRedirects === undefined ? 3 : maxRedirects;
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && maxRedirects > 0) {
        const next = res.headers.location.startsWith("http")
          ? res.headers.location
          : new URL(res.headers.location, url).href;
        return resolve(fetchJSON(next, maxRedirects - 1));
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
      }
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Invalid JSON from ${url}`));
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(20000, () => {
      req.destroy();
      reject(new Error(`Timeout fetching ${url}`));
    });
  });
}

/**
 * Fetch a public key from a JWKS endpoint by kid. Caches results.
 * Returns a Node.js KeyObject ready for verification.
 */
async function getPublicKey(jwksUrl, kid, alg) {
  const cacheKey = `${jwksUrl}:${kid}`;
  const cached = jwksCache.get(cacheKey);
  if (cached && Date.now() - cached.fetchedAt < JWKS_CACHE_TTL) {
    return cached.key;
  }

  const jwks = await fetchJSON(jwksUrl);
  const keys = jwks.keys || [];
  const jwk = keys.find((k) => k.kid === kid);

  if (!jwk) {
    throw new Error(`Key ${kid} not found in JWKS at ${jwksUrl}`);
  }

  let keyObject;

  if (alg === "ES256" && jwk.kty === "EC" && jwk.crv === "P-256") {
    keyObject = crypto.createPublicKey({ key: jwk, format: "jwk" });
  } else if (alg === "EdDSA" && jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    keyObject = crypto.createPublicKey({ key: jwk, format: "jwk" });
  } else {
    throw new Error(
      `Unsupported key type: alg=${alg}, kty=${jwk.kty}, crv=${jwk.crv}`
    );
  }

  jwksCache.set(cacheKey, { key: keyObject, fetchedAt: Date.now() });
  return keyObject;
}

/**
 * Canonical JSON: sorted keys, compact separators.
 * Matches Python's json.dumps(sort_keys=True, separators=(",", ":")).
 */
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJSON).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k])).join(",") + "}";
}

/**
 * Decode base64url string to Buffer.
 */
function base64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

/**
 * Convert P1363 signature (r || s, 64 bytes for P-256) to DER format.
 * Node.js crypto.verify with EC keys expects DER.
 */
function p1363ToDer(sig, keySize) {
  keySize = keySize || 32;
  const r = sig.subarray(0, keySize);
  const s = sig.subarray(keySize, keySize * 2);

  function encodeInt(buf) {
    // Strip leading zeros, add 0x00 if high bit set
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) i++;
    buf = buf.subarray(i);
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
    return Buffer.concat([Buffer.from([0x02, buf.length]), buf]);
  }

  const rDer = encodeInt(r);
  const sDer = encodeInt(s);
  const body = Buffer.concat([rDer, sDer]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/**
 * An entry carries its payload one of two ways and never both: inside a compact
 * JWS, or as the `signed` object a raw signature covers. A JWS with an object
 * beside it is malformed — that object bears no signature, and a relying party
 * reading claims from it is reading whatever the sender wrote. Spec section 4,
 * step 0.
 *
 * Comparing `signed` against the JWT payload rather than rejecting the entry is
 * not a control a verifier here can enforce, because the relationship between
 * the two is issuer-specific. For APS the object is a strict subset of its own
 * JWS payload and the comparison is well defined; for InsumerAPI the JWT is a
 * different projection of the attestation and there is nothing to compare. This
 * format is deliberately registry-free — section 1, no coordination between
 * issuers — so a verifier cannot know which convention a given issuer follows.
 * A check that is meaningful for some issuers and meaningless for others has
 * only one safe fallback in the meaningless case, which is to accept, and that
 * reinstates the hole. Rejection is the only rule enforceable uniformly.
 */
function isCompactJWS(sig) {
  return typeof sig === "string" && sig.split(".").length === 3;
}

/**
 * The expiry of a JWS, read from the token itself.
 *
 * Used twice: by isExpired, so the verifier can age a JWS entry with no
 * entry-level `expiry` beside it, and by the adapters below, so the entries they
 * build carry the `expiry` the spec asks for and are self-describing to other
 * verifiers.
 *
 * A JWS entry has `signed: null`, so there is no `attestedAt` beside the
 * signature for isExpired to fall back to, and the token's own expiry sits
 * inside the signature where isExpired does not look. Spec section 3, the
 * `expiry` row: an entry in that form SHOULD carry `expiry`, or a relying party
 * has no freshness signal at all.
 *
 * Issuers here spell that expiry two ways, so read both. AgentID, APS and
 * Revettr use the registered numeric `exp`; AgentGraph carries an ISO
 * `expiresAt` and no `exp` at all. Reading only `exp` would return undefined
 * for the second group, which reads as a freshness fix and is not one.
 *
 * Returns undefined when the token carries neither, leaving the entry exactly
 * as it would have been.
 */
function jwsExpiry(token) {
  if (!isCompactJWS(token)) return undefined;
  try {
    const payload = JSON.parse(base64urlDecode(token.split(".")[1]).toString());
    if (typeof payload.exp === "number") {
      return new Date(payload.exp * 1000).toISOString();
    }
    const iso = payload.expiresAt || payload.expires_at;
    if (typeof iso === "string") {
      const parsed = new Date(iso);
      // isExpired matches on /^\d{4}-/, so normalise rather than pass through.
      if (!isNaN(parsed.getTime())) return parsed.toISOString();
    }
    return undefined;
  } catch (e) {
    return undefined;
  }
}

function hasStapledPayload(sig, signed) {
  return isCompactJWS(sig) && signed !== null && signed !== undefined;
}

const STAPLED_PAYLOAD_ERROR =
  "`signed` must be null when `sig` is a compact JWS";

/**
 * Verify a single attestation's signature.
 *
 * For ES256 (P1363 base64): decode base64, convert P1363→DER, verify with SHA-256.
 * For EdDSA (Ed25519): decode base64, verify directly (no hash needed).
 * For JWT format: decode header.payload, verify signature part.
 */
async function verifySignature(attestation) {
  const { kid, alg, jwks, signed, sig } = attestation;

  if (!kid || !alg || !jwks || !sig) {
    return { valid: false, error: "Missing kid, alg, jwks, or sig" };
  }

  // verifyMultiAttestation classifies this at step 0, before expiry. Repeated
  // here because verifySignature is exported and callable on its own.
  if (hasStapledPayload(sig, signed)) {
    return { valid: false, error: STAPLED_PAYLOAD_ERROR };
  }

  try {
    const publicKey = await getPublicKey(jwks, kid, alg);

    if (isCompactJWS(sig)) {
      // JWT format — verify the whole JWT
      const parts = sig.split(".");
      const signingInput = parts[0] + "." + parts[1];
      const sigBytes = base64urlDecode(parts[2]);

      if (alg === "ES256") {
        const derSig = p1363ToDer(sigBytes, 32);
        const ok = crypto.verify(
          "SHA256",
          Buffer.from(signingInput),
          publicKey,
          derSig
        );
        return { valid: ok, error: ok ? null : "ES256 JWT signature invalid" };
      } else if (alg === "EdDSA") {
        const ok = crypto.verify(null, Buffer.from(signingInput), publicKey, sigBytes);
        return { valid: ok, error: ok ? null : "EdDSA JWT signature invalid" };
      }
    }

    // Raw signature format — sig is base64 over JSON.stringify(signed)
    if (!signed) {
      return { valid: false, error: "Missing signed payload" };
    }

    const sigBuffer = base64urlDecode(sig);

    if (alg === "ES256") {
      // Try insertion-order JSON first, then canonical (sorted keys) for
      // issuers that sign with sorted-key recursive JSON (e.g., TrustLayer).
      // Mirrors the EdDSA dual-mode below.
      const derSig = p1363ToDer(sigBuffer, 32);
      const message = JSON.stringify(signed);
      let ok = crypto.verify("SHA256", Buffer.from(message), publicKey, derSig);
      if (!ok) {
        const canonical = canonicalJSON(signed);
        ok = crypto.verify("SHA256", Buffer.from(canonical), publicKey, derSig);
      }
      return { valid: ok, error: ok ? null : "ES256 signature invalid" };
    } else if (alg === "EdDSA") {
      // Try insertion-order JSON first, then canonical (sorted keys) for
      // issuers that sign with Python json.dumps(sort_keys=True)
      const message = JSON.stringify(signed);
      let ok = crypto.verify(null, Buffer.from(message), publicKey, sigBuffer);
      if (!ok) {
        const canonical = canonicalJSON(signed);
        ok = crypto.verify(null, Buffer.from(canonical), publicKey, sigBuffer);
      }
      return { valid: ok, error: ok ? null : "EdDSA signature invalid" };
    }

    return { valid: false, error: `Unsupported algorithm: ${alg}` };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

/**
 * Check if an attestation has expired.
 */
function isExpired(attestation) {
  const { signed, expiry, sig } = attestation;

  // Check explicit expiry timestamp
  if (expiry && typeof expiry === "string" && !expiry.startsWith("TBD")) {
    const match = expiry.match(/^\d{4}-/);
    if (match) {
      if (new Date(expiry) < new Date()) return true;
    }
  }

  // A JWS carries its own expiry inside the signature, where the checks above
  // and below cannot see it: `signed` is null on a conformant JWS entry, so all
  // four fallbacks are unavailable and this function would otherwise return
  // false for every such entry, however old. That is the whole population of
  // entries the spec's `signed` row now requires, so without this a conformant
  // JWS entry with no `expiry` beside it is permanently fresh.
  //
  // Checked after the entry-level `expiry` rather than instead of it, and only
  // ever to expire: whichever of the two says expired wins. The envelope is
  // unsigned, so an entry-level `expiry` can be set by whoever relays it, while
  // the token's `exp` is inside signature scope. Taking the stricter of the two
  // means a relayed entry cannot extend a stale attestation.
  const tokenExpiry = jwsExpiry(sig);
  if (tokenExpiry) {
    return new Date(tokenExpiry) < new Date();
  }

  // Check attestedAt + known TTLs. Issuers spell this field both ways, so read
  // both: TrustLayer signs `attested_at` and nothing else this list matches, and
  // reading only the camelCase form left its entries permanently unexpirable —
  // the spec's own TrustLayer section records the field as present and the
  // 30-minute consumer default as applicable. `scored_at` is deliberately not
  // consulted: it is when the background pipeline computed the score, not when
  // the attestation was made, so ageing against it would report entries stale
  // that are not.
  const attestedAt =
    signed?.attestedAt || signed?.attested_at || signed?.timestamp || signed?.iat;
  if (!attestedAt) return false;

  const attestTime = new Date(attestedAt).getTime();
  if (isNaN(attestTime)) return false;

  const now = Date.now();
  const age = now - attestTime;

  // Default: 30 minutes if no explicit expiry
  return age > 30 * 60 * 1000;
}

/**
 * Verify a multi-attestation payload.
 *
 * @param {object} payload - The multi-attestation object with `version` and `attestations[]`
 * @param {object} options
 * @param {string[]} options.requiredTypes - Array of type strings that must be present and valid
 * @param {boolean} options.checkExpiry - Whether to check expiration (default: true)
 * @param {object} options.trustedIssuers - issuer URI -> JWKS URL, merged over TRUSTED_ISSUERS
 * @param {boolean} options.allowUnpinnedIssuers - Take `jwks` from the entry for issuers not pinned (default: false, fail closed)
 * @returns {object} { valid, results[], summary }
 *   Each result includes `verifiedAt` (ISO 8601) — when the signature was checked against the issuer's JWKS.
 */
async function verifyMultiAttestation(payload, options) {
  options = options || {};
  const requiredTypes = options.requiredTypes || [];
  const checkExpiry = options.checkExpiry !== false;
  const trustedIssuers = Object.assign({}, TRUSTED_ISSUERS, options.trustedIssuers || {});
  const allowUnpinnedIssuers = options.allowUnpinnedIssuers === true;

  if (!payload || !Array.isArray(payload.attestations)) {
    return {
      valid: false,
      error: "Invalid payload: missing attestations array",
      results: [],
    };
  }

  const results = [];

  // Verify each attestation in parallel. Slot independence is the point: a
  // malformed or throwing entry must fail its own slot only, and must never
  // suppress the verdicts of the others.
  const verifications = payload.attestations.map(async (att) => {
    if (!att || typeof att !== "object") {
      return {
        issuer: null,
        type: null,
        kid: null,
        signatureValid: false,
        expired: false,
        verifiedAt: new Date().toISOString(),
        error: "Invalid attestation entry: expected an object",
      };
    }

    // Spec section 4 step 0: a structurally incomplete entry is malformed,
    // classified before the expiry check ever runs.
    if (!att.kid || !att.alg || !att.jwks || !att.sig) {
      return {
        issuer: att.issuer || null,
        type: att.type || null,
        kid: att.kid || null,
        signatureValid: false,
        expired: false,
        verifiedAt: new Date().toISOString(),
        error: "Missing kid, alg, jwks, or sig",
      };
    }

    // Also step 0: an unsigned object stapled beside a JWS. Classified here
    // with the other malformed entries rather than at the signature check, so a
    // stapled entry is refused whether or not it is also stale.
    if (hasStapledPayload(att.sig, att.signed)) {
      return {
        issuer: att.issuer || null,
        type: att.type || null,
        kid: att.kid || null,
        signatureValid: false,
        expired: false,
        verifiedAt: new Date().toISOString(),
        error: STAPLED_PAYLOAD_ERROR,
      };
    }

    const result = {
      issuer: att.issuer,
      type: att.type,
      kid: att.kid,
      signatureValid: false,
      expired: false,
      verifiedAt: new Date().toISOString(),
      error: null,
    };

    // Check expiry
    if (checkExpiry && isExpired(att)) {
      result.expired = true;
      result.error = "Attestation expired";
      return result;
    }

    // Resolve the verifying key from the relying party's own configuration
    // (spec section 4, step 3): the entry's jwks is a hint, not the trust root.
    const source = resolveKeySource(att, trustedIssuers, allowUnpinnedIssuers);
    if (source.error) {
      result.error = source.error;
      return result;
    }

    // Verify signature against the pinned JWKS
    const sigResult = await verifySignature(Object.assign({}, att, { jwks: source.jwksUrl }));
    result.signatureValid = sigResult.valid;
    result.verifiedAt = new Date().toISOString();
    if (!sigResult.valid) {
      result.error = sigResult.error;
    }

    return result;
  });

  // allSettled, not all: an unexpected throw inside one slot is contained to
  // that slot instead of rejecting the whole call and returning no verdicts.
  const settled = await Promise.allSettled(verifications);
  results.push(
    ...settled.map((s) =>
      s.status === "fulfilled"
        ? s.value
        : {
            issuer: null,
            type: null,
            kid: null,
            signatureValid: false,
            expired: false,
            verifiedAt: new Date().toISOString(),
            error:
              "Verification threw: " +
              (s.reason && s.reason.message ? s.reason.message : String(s.reason)),
          }
    )
  );

  // Check required types
  const missingTypes = [];
  for (const reqType of requiredTypes) {
    const match = results.find(
      (r) => r.type === reqType && r.signatureValid && !r.expired
    );
    if (!match) {
      missingTypes.push(reqType);
    }
  }

  const allValid = results.every((r) => r.signatureValid && !r.expired);
  const requiredMet = missingTypes.length === 0;

  return {
    valid: requiredMet && (requiredTypes.length > 0 || allValid),
    results,
    summary: {
      total: results.length,
      verified: results.filter((r) => r.signatureValid).length,
      expired: results.filter((r) => r.expired).length,
      failed: results.filter((r) => !r.signatureValid && !r.expired).length,
      missingRequired: missingTypes,
    },
  };
}

// --- CLI demo ---
async function main() {
  console.log("Multi-Attestation Verifier");
  console.log("=".repeat(60));
  console.log("");

  // Fetch live attestations from all ten issuers
  console.log("Fetching live attestations from all ten issuers...\n");

  // 1. InsumerAPI — requires API key
  const INSUMER_KEY = process.env.INSUMER_API_KEY;
  let insumerAttestation;
  if (INSUMER_KEY) {
    try {
      const res = await new Promise((resolve, reject) => {
        const postData = JSON.stringify({
          wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
          conditions: [
            {
              type: "token_balance",
              contractAddress: "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",
              chainId: 1,
              threshold: "1000000",
              label: "SHIB holder",
            },
          ],
          format: "jwt",
        });
        const req = https.request(
          "https://api.insumermodel.com/v1/attest",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-API-Key": INSUMER_KEY,
            },
          },
          (resp) => {
            let data = "";
            resp.on("data", (c) => (data += c));
            resp.on("end", () => {
              try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
            });
          }
        );
        req.on("error", reject);
        req.write(postData);
        req.end();
      });

      if (res.ok && res.data) {
        const { attestation, jwt, kid } = res.data;
        insumerAttestation = {
          issuer: "https://api.insumermodel.com",
          type: "wallet_state",
          kid: kid,
          alg: "ES256",
          jwks: "https://insumermodel.com/.well-known/jwks.json",
          signed: null, // JWT format — payload is in the JWS
          sig: jwt,
          expiry: attestation.expiresAt,
        };
        console.log(
          "[+] InsumerAPI: fetched (pass: " + attestation.pass + ", id: " + attestation.id + ")"
        );
      } else {
        console.log("[-] InsumerAPI: " + (res.error || res.message || "unexpected response"));
      }
    } catch (e) {
      console.log("[-] InsumerAPI: " + e.message);
    }
  } else {
    console.log(
      "[~] InsumerAPI: set INSUMER_API_KEY to include in demo"
    );
    console.log(
      "    (JWKS verified at insumermodel.com/.well-known/jwks.json)"
    );
  }

  // 3. RNWY — returns envelope directly
  let rnwyAttestation;
  try {
    const rnwy = await fetchJSON(
      "https://rnwy.com/api/trust-check?id=16907&chain=base"
    );
    if (rnwy.attestation) {
      rnwyAttestation = rnwy.attestation;
      console.log("[+] RNWY: fetched (score: " + rnwy.score + ")");
    } else {
      console.log("[-] RNWY: no attestation envelope in response");
    }
  } catch (e) {
    console.log("[-] RNWY: " + e.message);
  }

  // 4. Maiat — returns JWT
  let maiatAttestation;
  try {
    const maiat = await fetchJSON(
      "https://app.maiat.io/api/v1/attest?address=0xE6ac05D2b50cd525F793024D75BB6f519a52Af5D"
    );
    if (maiat.token) {
      maiatAttestation = {
        issuer: "https://app.maiat.io",
        type: "job_performance",
        kid: maiat.kid || "maiat-trust-v1",
        alg: "ES256",
        jwks: "https://app.maiat.io/.well-known/jwks.json",
        signed: null, // JWT format — payload is in the JWS
        sig: maiat.token,
        expiry: jwsExpiry(maiat.token),
      };
      console.log("[+] Maiat: fetched (score: " + maiat.payload?.score + ")");
    } else {
      console.log("[-] Maiat: unexpected response format");
    }
  } catch (e) {
    console.log("[-] Maiat: " + e.message);
  }

  // 2. ThoughtProof — wallet-bound issuer lookup (no API key needed since Apr 11 2026).
  // GET /v1/issuer/wallet/{wallet} returns a wallet_reasoning_integrity/v1 envelope
  // with the wallet in the signed bytes; detached EdDSA over sorted-key compact JSON.
  let tpAttestation;
  try {
    const TP_DEMO_WALLET = "0x0000000000000000000000000000000000001004";
    const tp = await fetchJSON(
      "https://api.thoughtproof.ai/v1/issuer/wallet/" + TP_DEMO_WALLET
    );
    if (tp.signature && tp.signature.value) {
      const tpSigned = Object.assign({}, tp);
      delete tpSigned.signature;
      tpAttestation = {
        issuer: "https://api.thoughtproof.ai",
        type: "reasoning_integrity",
        kid: tp.signature.kid || "tp-attestor-v1",
        alg: tp.signature.alg || "EdDSA",
        jwks: "https://api.thoughtproof.ai/.well-known/jwks.json",
        signed: tpSigned,
        sig: tp.signature.value,
        expiry: tp.expiresAt,
      };
      console.log(
        "[+] ThoughtProof: fetched (verdict: " + tp.verdict + ", found: " + tp.found + ")"
      );
    } else {
      console.log("[-] ThoughtProof: no signature in response");
    }
  } catch (e) {
    console.log("[-] ThoughtProof: " + e.message);
  }

  // 5. APS (Agent Passport System) — public, no API key
  let apsAttestation;
  try {
    // Warm the cache first (attestation endpoint requires a prior profile fetch)
    await fetchJSON("https://gateway.aeoess.com/api/v1/public/trust/claude-operator");
    const aps = await fetchJSON(
      "https://gateway.aeoess.com/api/v1/public/trust/claude-operator/attestation"
    );
    if (aps.jws) {
      apsAttestation = {
        issuer: aps.issuer,
        type: aps.type,
        kid: aps.kid,
        alg: aps.alg,
        jwks: aps.jwks,
        signed: null, // JWT format — payload is in the JWS
        sig: aps.jws, // APS returns "jws", verifier expects "sig"
        expiry: jwsExpiry(aps.jws),
      };
      console.log("[+] APS: fetched (grade: " + aps.signed?.grade + ", " + aps.signed?.grade_label + ")");
    } else {
      console.log("[-] APS: unexpected response format");
    }
  } catch (e) {
    console.log("[-] APS: " + e.message);
  }

  // 6. AgentID — public, no API key
  let agentidAttestation;
  try {
    const agentid = await fetchJSON(
      "https://getagentid.dev/api/v1/agents/trust-header?agent_id=agent_d1b7ef01f9af191f"
    );
    if (agentid.header) {
      agentidAttestation = {
        issuer: "https://getagentid.dev",
        type: "trust_verification",
        kid: "agentid-2026-03",
        alg: "EdDSA",
        jwks: "https://getagentid.dev/.well-known/jwks.json",
        signed: null, // JWT format
        sig: agentid.header,
        expiry: jwsExpiry(agentid.header),
      };
      console.log("[+] AgentID: fetched (trust_level: " + agentid.payload?.trust_level + ", " + agentid.payload?.trust_level_label + ")");
    } else {
      console.log("[-] AgentID: unexpected response format");
    }
  } catch (e) {
    console.log("[-] AgentID: " + e.message);
  }

  // 7. AgentGraph — public, no API key
  let agentgraphAttestation;
  try {
    const ag = await fetchJSON(
      "https://agentgraph.co/api/v1/entities/1e7b584d-2621-47a8-a314-20b9a908353a/attestation/security"
    );
    if (ag.payload && ag.jws) {
      agentgraphAttestation = {
        issuer: "https://agentgraph.co",
        type: "security_posture",
        kid: ag.key_id || "agentgraph-security-v1",
        alg: ag.algorithm || "EdDSA",
        jwks: "https://agentgraph.co/.well-known/jwks.json",
        signed: null, // JWT format — payload is in the JWS
        sig: ag.jws,
        expiry: jwsExpiry(ag.jws),
      };
      console.log("[+] AgentGraph: fetched (result: " + ag.payload?.scan?.result + ", findings: " + ag.payload?.scan?.findings?.total + ")");
    } else {
      console.log("[-] AgentGraph: unexpected response format");
    }
  } catch (e) {
    console.log("[-] AgentGraph: " + e.message);
  }

  // 8. SAR (SettlementWitness) — enrolled caller key since 2026-08-29:
  // Bearer key + unix-seconds timestamp + fresh nonce per request (SAR_API_KEY)
  let sarAttestation;
  try {
    const sar = await new Promise((resolve, reject) => {
      const postData = JSON.stringify({
        task_id: "attest-001",
        spec: { checks: [{ kind: "field_equals", inputs: { output_path: "$.status" }, expected: "ok" }] },
        output: { status: "ok" },
        receipt_profile: "settlement-witness-verified-v0.2-counterparty-bound",
      });
      const sarHeaders = { "Content-Type": "application/json" };
      if (process.env.SAR_API_KEY) {
        sarHeaders["Authorization"] = "Bearer " + process.env.SAR_API_KEY;
        sarHeaders["X-Settlement-Timestamp"] = String(Math.floor(Date.now() / 1000));
        sarHeaders["X-Settlement-Nonce"] = crypto.randomBytes(16).toString("hex");
      }
      const req = https.request(
        "https://defaultverifier.com/settlement-witness/attest",
        {
          method: "POST",
          headers: sarHeaders,
        },
        (resp) => {
          let data = "";
          resp.on("data", (c) => (data += c));
          resp.on("end", () => {
            try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
          });
        }
      );
      req.on("error", reject);
      req.setTimeout(20000, () => { req.destroy(); reject(new Error("Timeout")); });
      req.write(postData);
      req.end();
    });
    if (sar.jws) {
      sarAttestation = {
        issuer: sar.issuer || "https://defaultverifier.com",
        type: sar.type || "settlement_witness",
        kid: sar.kid || "sar-prod-ed25519-03",
        alg: sar.alg || "EdDSA",
        jwks: "https://defaultverifier.com/.well-known/jwks.json",
        signed: null, // JWT format
        sig: sar.jws,
        expiry: jwsExpiry(sar.jws),
      };
      console.log("[+] SAR: fetched (verdict: " + sar.payload?.verdict + ", confidence: " + sar.payload?.confidence + ")");
    } else if (sar?.detail?.result === "UNAUTHORIZED") {
      console.log("[-] SAR: needs an enrolled caller key (set SAR_API_KEY)");
    } else {
      console.log("[-] SAR: unexpected response format");
    }
  } catch (e) {
    console.log("[-] SAR: " + e.message);
  }

  // 9. Revettr — public, no API key, returns compact JWS
  let revettrAttestation;
  try {
    const rev = await new Promise((resolve, reject) => {
      const postData = JSON.stringify({
        wallet_address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      });
      const req = https.request(
        "https://revettr.com/v1/attest",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        },
        (resp) => {
          let data = "";
          resp.on("data", (c) => (data += c));
          resp.on("end", () => {
            try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
          });
        }
      );
      req.on("error", reject);
      req.setTimeout(20000, () => { req.destroy(); reject(new Error("Timeout")); });
      req.write(postData);
      req.end();
    });
    if (rev.jws) {
      revettrAttestation = {
        issuer: rev.provider?.id || "did:web:revettr.com",
        type: "compliance_risk",
        kid: rev.kid || "revettr-attest-v1",
        alg: rev.algorithm || "ES256",
        jwks: "https://revettr.com/.well-known/jwks.json",
        signed: null, // JWT format — payload is in the JWS
        sig: rev.jws,
        expiry: rev.expires_at ? new Date(rev.expires_at * 1000).toISOString() : undefined,
      };
      console.log("[+] Revettr: fetched (tier: " + rev.attestation?.payload?.tier + ", score: " + rev.attestation?.payload?.score + ")");
    } else {
      console.log("[-] Revettr: unexpected response format");
    }
  } catch (e) {
    console.log("[-] Revettr: " + e.message);
  }

  // 10. TrustLayer — public, no API key, wallet-bound endpoint
  let trustlayerAttestation;
  try {
    const tl = await fetchJSON(
      "https://api.thetrustlayer.xyz/attest/wallet/0xda977767452c5dd021624511f14df67b6c9c2c1b"
    );
    if (tl.signed && tl.sig) {
      trustlayerAttestation = tl;
      console.log(
        "[+] TrustLayer: fetched (score: " + tl.signed.score +
        ", chains: " + (tl.signed.chains_present ? tl.signed.chains_present.length : 0) +
        ", group: " + tl.signed.identity_group_id + ")"
      );
    } else {
      console.log("[-] TrustLayer: unexpected response format");
    }
  } catch (e) {
    console.log("[-] TrustLayer: " + e.message);
  }

  // Build multi-attestation payload from available attestations
  const attestations = [];
  if (insumerAttestation) attestations.push(insumerAttestation);
  if (tpAttestation) attestations.push(tpAttestation);
  if (rnwyAttestation) attestations.push(rnwyAttestation);
  if (maiatAttestation) attestations.push(maiatAttestation);
  if (apsAttestation) attestations.push(apsAttestation);
  if (agentidAttestation) attestations.push(agentidAttestation);
  if (agentgraphAttestation) attestations.push(agentgraphAttestation);
  if (sarAttestation) attestations.push(sarAttestation);
  if (revettrAttestation) attestations.push(revettrAttestation);
  if (trustlayerAttestation) attestations.push(trustlayerAttestation);

  if (attestations.length === 0) {
    console.log("\nNo live attestations available to verify.");
    return;
  }

  const payload = { version: "1", attestations, expired: [] };

  console.log(`\nVerifying ${attestations.length} attestation(s)...\n`);

  // Verify all
  const result = await verifyMultiAttestation(payload);

  console.log("Results:");
  console.log("-".repeat(60));
  for (const r of result.results) {
    const status = r.expired
      ? "EXPIRED"
      : r.signatureValid
        ? "VERIFIED"
        : "FAILED";
    console.log(`  ${r.issuer}`);
    console.log(`    Type: ${r.type}`);
    console.log(`    Kid:  ${r.kid}`);
    console.log(`    Status: ${status}`);
    if (r.verifiedAt) console.log(`    Verified: ${r.verifiedAt}`);
    if (r.error) console.log(`    Error: ${r.error}`);
    console.log("");
  }

  console.log("Summary:");
  console.log(`  Total: ${result.summary.total}`);
  console.log(`  Verified: ${result.summary.verified}`);
  console.log(`  Expired: ${result.summary.expired}`);
  console.log(`  Failed: ${result.summary.failed}`);
  console.log(`  Overall: ${result.valid ? "PASS" : "FAIL"}`);

  // Demo: verify with requiredTypes
  console.log("\n" + "=".repeat(60));
  console.log("Required types check: ['behavioral_trust']");
  const required = await verifyMultiAttestation(payload, {
    requiredTypes: ["behavioral_trust"],
  });
  console.log(
    `  Result: ${required.valid ? "PASS" : "FAIL"} (missing: ${required.summary.missingRequired.join(", ") || "none"})`
  );
}

// Export for use as module
module.exports = { verifyMultiAttestation, verifySignature, getPublicKey, resolveKeySource, TRUSTED_ISSUERS };

// Run CLI if executed directly
if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
