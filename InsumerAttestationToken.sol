// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title InsumerAttestationToken
/// @notice Reads an InsumerAPI attestation token on-chain: verifies its
///         ES256 signature and returns the claims from the signed payload.
///
/// @dev The token is the Wallet Auth JWT that `POST /v1/attest` returns
///      with `"format": "jwt"`, passed as ASCII bytes, unchanged:
///        base64url(header) "." base64url(payload) "." base64url(signature)
///      `read` returns `ok == true` only when the signature verifies under
///      the given P-256 key and the payload yields every claim below. The
///      caller applies its own policy to the claims; nothing is taken from
///      the caller beside the token, so no caller-written value can stand
///      beside a genuine signature.
///        sub            the wallet a condition evaluated (EVM addresses only;
///                       any other subject makes `ok` false)
///        pass           the issuer's verdict
///        conditionHash  the token's single condition hash (a token carrying
///                       more than one makes `ok` false)
///        exp            expiry, Unix seconds
///
///      Signature: ECDSA P-256 over SHA-256 of `header.payload`, checked
///      through the `P256VERIFY` precompile at `0x0100` (RIP-7212 on L2s,
///      EIP-7951 on L1). On a chain without it every token reads `ok ==
///      false`. The attestation kids (`insumer-attest-v1`,
///      `insumer-attest-v2`) share one EC key, published at
///      https://api.insumermodel.com/.well-known/jwks.json. The ML-DSA-65
///      post-quantum key in the same set has no on-chain verifier and is not read.
///
///      Only a token reads as one. The attestation endpoint is the only
///      place the key signs a JWT. Everything else it signs (raw v1 and v2
///      attestation preimages, trust profiles, merchant verification
///      results, the post-quantum key binding) either starts with `{` or
///      starts with `insumer.` followed by another dot within the next 160
///      characters, so presented as a token its header or payload holds
///      bytes that are not base64url and it reads `ok == false`. This rests
///      on what the issuer signs today.
///
///      Cost: only the first 160 and the last 200 to 203 characters (aligned
///      to the base64 grouping) of the payload are decoded, about 130,000 gas for a typical single-condition token. The
///      signature hash still covers the whole token, so cost grows slowly
///      with length and stays under 200,000 gas up to the 64 KB limit.
///      Tokens over 64 KB, or whose header runs past 256 characters, read
///      `ok == false`.
///
///      The payload is issuer-written JSON with no whitespace and no
///      repeated keys, with `pass` and `conditionHash` leading and `sub` and
///      `exp` trailing. The reader requires the first two among the leading
///      members and the last two among the trailing members, and does not
///      read the middle; if the issuer ever moved them, tokens would read
///      `ok == false` rather than being guessed at.
///
/// @custom:audit status=unaudited
library InsumerAttestationToken {
    struct Claims {
        address sub;
        bool pass;
        bytes32 conditionHash;
        uint256 exp;
    }

    /// @dev P256VERIFY precompile address (RIP-7212 / EIP-7951).
    address internal constant P256_VERIFIER = address(0x0100);

    /// @dev Length of a base64url-encoded 64-byte P-256 signature.
    uint256 private constant SIG_B64_LENGTH = 86;

    /// @dev Largest token read.
    uint256 private constant MAX_TOKEN_LENGTH = 65536;

    /// @dev Longest header searched for its closing dot. The issuer's header
    ///      is 71 characters; bounding the search keeps a malformed input's
    ///      cost within the reference registry's 200,000-gas call.
    uint256 private constant MAX_HEADER_LENGTH = 256;

    /// @dev Payload characters decoded from each end (multiples of 4).
    uint256 private constant HEAD_CHARS = 160;
    uint256 private constant TAIL_CHARS = 200;

    bytes32 private constant KEY_SUB = keccak256("sub");
    bytes32 private constant KEY_PASS = keccak256("pass");
    bytes32 private constant KEY_CONDITION_HASH = keccak256("conditionHash");
    bytes32 private constant KEY_EXP = keccak256("exp");

    /// @notice Verify `token` under the P-256 key `(pubKeyX, pubKeyY)` and
    ///         return its claims. Never reverts on malformed input.
    function read(bytes calldata token, uint256 pubKeyX, uint256 pubKeyY)
        internal
        view
        returns (bool ok, Claims memory c)
    {
        // header "." payload "." signature: the signature segment is the
        // last 86 bytes and the header runs to the first dot. The signature
        // covers everything before the second dot.
        if (token.length < SIG_B64_LENGTH + 4 || token.length > MAX_TOKEN_LENGTH) return (false, c);
        uint256 dot2 = token.length - SIG_B64_LENGTH - 1;
        if (token[dot2] != ".") return (false, c);
        uint256 dot1 = _indexOfDot(token, dot2 < MAX_HEADER_LENGTH ? dot2 : MAX_HEADER_LENGTH);
        if (dot1 == 0 || dot1 + 1 >= dot2) return (false, c);
        if (!_isBase64Url(token[:dot1])) return (false, c);

        (bool sigOk, bytes memory sig) = _base64UrlDecode(token[dot2 + 1:]);
        if (!sigOk) return (false, c);
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
        }
        if (!_verifyP256(sha256(token[:dot2]), r, s, pubKeyX, pubKeyY)) return (false, c);

        return _readPayload(token[dot1 + 1:dot2]);
    }

    function _readPayload(bytes calldata payload) private pure returns (bool ok, Claims memory c) {
        uint256 len = payload.length;
        uint256 headLen = len < HEAD_CHARS ? len : HEAD_CHARS;
        uint256 tailFrom = len > TAIL_CHARS ? ((len - TAIL_CHARS) / 4) * 4 : 0;

        (bool headOk, bytes memory head) = _base64UrlDecode(payload[:headLen]);
        if (!headOk) return (false, c);
        (ok, c.pass, c.conditionHash) = _readHead(head);
        if (!ok) return (false, c);
        (bool tailOk, bytes memory tail) = _base64UrlDecode(payload[tailFrom:]);
        if (!tailOk) return (false, c);
        (ok, c.sub, c.exp) = _readTail(tail);
    }

    /// @dev Reads the leading top-level members, forward from `{`, until
    ///      both `pass` and `conditionHash` are seen. Values it steps over
    ///      must be plain strings, numbers or `true`/`false`; anything else
    ///      (such as the `results` array) before both are seen fails.
    function _readHead(bytes memory h) private pure returns (bool ok, bool pass, bytes32 cond) {
        uint256 n = h.length;
        if (n == 0 || h[0] != "{") return (false, false, 0);
        uint256 i = 1;
        bool sawPass;
        bool sawCondition;
        while (!(sawPass && sawCondition)) {
            // key
            if (i >= n || h[i] != '"') return (false, false, 0);
            uint256 k = _skipForward(h, i + 1, LETTER);
            if (k + 1 >= n || h[k] != '"' || h[k + 1] != ":") return (false, false, 0);
            bytes32 key = _hashRange(h, i + 1, k);
            i = k + 2;
            // value
            if (key == KEY_PASS) {
                if (sawPass) return (false, false, 0);
                if (_isTrue(h, i)) {
                    pass = true;
                    i += 4;
                } else if (_isFalse(h, i)) {
                    i += 5;
                } else {
                    return (false, false, 0);
                }
                sawPass = true;
            } else if (key == KEY_CONDITION_HASH) {
                bool condOk;
                if (sawCondition) return (false, false, 0);
                (condOk, cond) = _singleConditionHash(h, i);
                if (!condOk) return (false, false, 0);
                sawCondition = true;
                i += 70;
            } else {
                i = _skipScalar(h, i);
                if (i == 0) return (false, false, 0);
            }
            if (i >= n || h[i] != ",") return (false, false, 0);
            i++;
        }
        ok = true;
    }

    /// @dev Reads the trailing top-level members, backward from the closing
    ///      `}`, until both `sub` and `exp` are seen. Every string it steps
    ///      over must be free of quotes and backslashes, so each token
    ///      boundary it finds is a real one.
    function _readTail(bytes memory t) private pure returns (bool ok, address sub, uint256 exp) {
        uint256 i = t.length;
        if (i == 0 || t[i - 1] != "}") return (false, address(0), 0);
        i--;
        bool sawSub;
        bool sawExp;
        while (!(sawSub && sawExp)) {
            // value, ending just before t[i]
            if (i == 0) return (false, address(0), 0);
            uint256 valueAt;
            if (t[i - 1] == '"') {
                uint256 k = _skipBackward(t, i - 1, PLAIN);
                if (k == 0 || t[k - 1] != '"') return (false, address(0), 0);
                valueAt = k - 1;
            } else {
                uint256 k = _skipBackward(t, i, DIGIT);
                if (k == i) return (false, address(0), 0);
                valueAt = k;
            }
            // ':' and key
            if (valueAt < 3 || t[valueAt - 1] != ":" || t[valueAt - 2] != '"') return (false, address(0), 0);
            uint256 keyEnd = valueAt - 2;
            uint256 k2 = _skipBackward(t, keyEnd, LETTER);
            if (k2 < 2 || t[k2 - 1] != '"') return (false, address(0), 0);
            bytes1 sep = t[k2 - 2];
            if (sep != "," && sep != "{") return (false, address(0), 0);
            bytes32 key = _hashRange(t, k2, keyEnd);
            if (key == KEY_SUB) {
                bool subOk;
                if (sawSub) return (false, address(0), 0);
                (subOk, sub) = _addressAt(t, valueAt);
                if (!subOk) return (false, address(0), 0);
                sawSub = true;
            } else if (key == KEY_EXP) {
                bool expOk;
                if (sawExp) return (false, address(0), 0);
                (expOk, exp) = _uintAt(t, valueAt);
                if (!expOk) return (false, address(0), 0);
                sawExp = true;
            }
            if (sep == "{") break;
            i = k2 - 2;
        }
        ok = sawSub && sawExp;
    }

    /// @dev Index just past a plain string, number or `true`/`false`
    ///      starting at `i`; 0 if the value is anything else.
    function _skipScalar(bytes memory h, uint256 i) private pure returns (uint256) {
        uint256 n = h.length;
        if (i >= n) return 0;
        bytes1 c = h[i];
        if (c == '"') {
            uint256 k = _skipForward(h, i + 1, PLAIN);
            return (k < n && h[k] == '"') ? k + 1 : 0;
        }
        if (c >= "0" && c <= "9") return _skipForward(h, i, DIGIT);
        if (_isTrue(h, i)) return i + 4;
        if (i + 5 < n && h[i] == "f" && h[i + 1] == "a" && h[i + 2] == "l" && h[i + 3] == "s" && h[i + 4] == "e") {
            return i + 5;
        }
        return 0;
    }

    function _hashRange(bytes memory p, uint256 from, uint256 to) private pure returns (bytes32 h) {
        assembly {
            h := keccak256(add(add(p, 32), from), sub(to, from))
        }
    }

    /// @dev `true` followed by `,` or `}`.
    function _isTrue(bytes memory p, uint256 at) private pure returns (bool) {
        return at + 4 < p.length
            && p[at] == "t" && p[at + 1] == "r" && p[at + 2] == "u" && p[at + 3] == "e"
            && (p[at + 4] == "," || p[at + 4] == "}");
    }

    /// @dev `false` followed by `,` or `}`.
    function _isFalse(bytes memory p, uint256 at) private pure returns (bool) {
        return at + 5 < p.length
            && p[at] == "f" && p[at + 1] == "a" && p[at + 2] == "l" && p[at + 3] == "s" && p[at + 4] == "e"
            && (p[at + 5] == "," || p[at + 5] == "}");
    }

    /// @dev `"0x` + 40 hex digits (either case) + `"`.
    function _addressAt(bytes memory p, uint256 at) private pure returns (bool ok, address a) {
        if (at + 44 > p.length) return (false, address(0));
        assembly {
            let base := add(add(p, 32), at)
            let w := mload(base)
            if and(
                and(eq(byte(0, w), 0x22), eq(byte(1, w), 0x30)),
                and(eq(byte(2, w), 0x78), eq(byte(0, mload(add(base, 43))), 0x22))
            ) {
                let v := 0
                let bad := 0
                for { let i := 3 } lt(i, 43) { i := add(i, 1) } {
                    let c := byte(0, mload(add(base, i)))
                    let d := 0x10
                    if and(gt(c, 47), lt(c, 58)) { d := sub(c, 48) }
                    if and(gt(c, 96), lt(c, 103)) { d := sub(c, 87) }
                    if and(gt(c, 64), lt(c, 71)) { d := sub(c, 55) }
                    bad := or(bad, eq(d, 0x10))
                    v := or(shl(4, v), and(d, 0x0f))
                }
                ok := iszero(bad)
                a := v
            }
        }
    }

    /// @dev `["0x` + 64 lowercase hex digits + `"]`.
    function _singleConditionHash(bytes memory p, uint256 at) private pure returns (bool ok, bytes32 v) {
        if (at + 70 >= p.length) return (false, 0);
        if (p[at] != "[" || p[at + 1] != '"' || p[at + 2] != "0" || p[at + 3] != "x") return (false, 0);
        if (p[at + 68] != '"' || p[at + 69] != "]") return (false, 0);
        assembly {
            let base := add(add(p, 32), add(at, 4))
            let bad := 0
            for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                let c := byte(0, mload(add(base, i)))
                let d := 0x10
                if and(gt(c, 47), lt(c, 58)) { d := sub(c, 48) }
                if and(gt(c, 96), lt(c, 103)) { d := sub(c, 87) }
                bad := or(bad, eq(d, 0x10))
                v := or(shl(4, v), and(d, 0x0f))
            }
            ok := iszero(bad)
        }
    }

    /// @dev A run of 1-12 decimal digits followed by `,` or `}`.
    function _uintAt(bytes memory p, uint256 at) private pure returns (bool ok, uint256 v) {
        uint256 i = at;
        while (i < p.length && i < at + 12 && p[i] >= "0" && p[i] <= "9") {
            v = v * 10 + (uint8(p[i]) - 48);
            unchecked { ++i; }
        }
        ok = i != at && i < p.length && (p[i] == "," || p[i] == "}");
    }

    // ─────────────────────────────────────────────
    // base64url (RFC 4648 §5, unpadded) and byte classes
    // ─────────────────────────────────────────────

    /// @dev Byte classes for the claim reader: 0x01 letter, 0x02 digit,
    ///      0x04 byte allowed in a plain string (letters, digits, `-_.:/+`).
    bytes private constant CHAR_CLASS =
        hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000040004040406060606060606060606040000000000000505050505050505050505050505050505050505050505050505000000000400050505050505050505050505050505050505050505050505050500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    uint256 private constant LETTER = 0x01;
    uint256 private constant DIGIT = 0x02;
    uint256 private constant PLAIN = 0x04;

    /// @dev First index `k >= i` such that `p[k]` is not in `mask`.
    function _skipForward(bytes memory p, uint256 i, uint256 mask) private pure returns (uint256 k) {
        bytes memory cls = CHAR_CLASS;
        assembly {
            let base := add(p, 32)
            let n := mload(p)
            let tbl := add(cls, 32)
            k := i
            for {} and(lt(k, n), iszero(iszero(and(byte(0, mload(add(tbl, byte(0, mload(add(base, k)))))), mask)))) {} {
                k := add(k, 1)
            }
        }
    }

    /// @dev Smallest `k <= i` such that `p[k..i)` is entirely in `mask`.
    function _skipBackward(bytes memory p, uint256 i, uint256 mask) private pure returns (uint256 k) {
        bytes memory cls = CHAR_CLASS;
        assembly {
            let base := add(p, 32)
            let tbl := add(cls, 32)
            k := i
            for {} and(gt(k, 0), iszero(iszero(and(byte(0, mload(add(tbl, byte(0, mload(add(base, sub(k, 1))))))), mask)))) {} {
                k := sub(k, 1)
            }
        }
    }

    /// @dev base64url alphabet value per byte; 0x40 marks an invalid byte.
    bytes private constant B64URL_TABLE =
        hex"4040404040404040404040404040404040404040404040404040404040404040404040404040404040404040403e40403435363738393a3b3c3d40404040404040000102030405060708090a0b0c0d0e0f10111213141516171819404040403f401a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323340404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040";

    function _indexOfDot(bytes calldata s, uint256 limit) private pure returns (uint256 idx) {
        assembly {
            for { let i := 0 } lt(i, limit) { i := add(i, 1) } {
                if eq(byte(0, calldataload(add(s.offset, i))), 0x2e) {
                    idx := i
                    break
                }
            }
        }
    }

    function _isBase64Url(bytes calldata s) private pure returns (bool ok) {
        bytes memory table = B64URL_TABLE;
        assembly {
            let tbl := add(table, 32)
            let bad := 0
            for { let i := 0 } lt(i, s.length) { i := add(i, 1) } {
                bad := or(bad, byte(0, mload(add(tbl, byte(0, calldataload(add(s.offset, i)))))))
            }
            ok := and(gt(s.length, 0), iszero(and(bad, 0x40)))
        }
    }

    /// @dev Unpadded base64url (RFC 4648 §5). Four characters per step;
    ///      a trailing group of two or three characters is allowed, and its
    ///      unused low bits must be zero (one canonical spelling per value).
    ///      Each step stores a full word, so the buffer is allocated with 32
    ///      bytes of slack and its length set to the decoded size afterwards.
    function _base64UrlDecode(bytes calldata s) private pure returns (bool ok, bytes memory out) {
        uint256 len = s.length;
        if (len == 0 || len % 4 == 1) return (false, out);
        uint256 outLen = (len * 3) / 4;
        out = new bytes(outLen + 32);
        bytes memory table = B64URL_TABLE;
        assembly {
            let tbl := add(table, 32)
            let dst := add(out, 32)
            let src := s.offset
            let end := add(src, len)
            let bad := 0
            for {} lt(src, end) { src := add(src, 4) } {
                let w := calldataload(src)
                let a := byte(0, mload(add(tbl, byte(0, w))))
                let b := byte(0, mload(add(tbl, byte(1, w))))
                let c := 0
                let d := 0
                let rem := sub(end, src)
                if gt(rem, 2) { c := byte(0, mload(add(tbl, byte(2, w)))) }
                if gt(rem, 3) { d := byte(0, mload(add(tbl, byte(3, w)))) }
                if eq(rem, 2) { if and(b, 0x0f) { bad := or(bad, 0x40) } }
                if eq(rem, 3) { if and(c, 0x03) { bad := or(bad, 0x40) } }
                bad := or(bad, or(or(a, b), or(c, d)))
                mstore(dst, shl(232, or(or(shl(18, a), shl(12, b)), or(shl(6, c), d))))
                dst := add(dst, 3)
            }
            mstore(out, outLen)
            ok := iszero(and(bad, 0x40))
        }
    }

    // ─────────────────────────────────────────────
    // P-256
    // ─────────────────────────────────────────────

    /// @dev Input layout: `messageHash || r || s || x || y` (5 x 32 bytes).
    ///      True iff the precompile returned `1`.
    function _verifyP256(bytes32 messageHash, bytes32 r, bytes32 s, uint256 x, uint256 y)
        private
        view
        returns (bool)
    {
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(abi.encodePacked(messageHash, r, s, x, y));
        return success && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }
}
