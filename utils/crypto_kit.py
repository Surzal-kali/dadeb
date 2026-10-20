"""Offline crypto/encoding workbench — zero network, by design.

Decode, identify, and attack the encoded/cryptographic blobs that recon
surfaces: session cookies that are base64-JSON, JWTs with suspicious
``alg`` choices, hex garbage in parameters, "obfuscated" client-side
config, unsalted password hashes found in dumps.  Everything here is pure
local compute (stdlib hashlib/base64/binascii + itertools; RSA uses plain
int math — no pycryptodome/Cryptography import needed) and makes NO
network calls ever: no gate check is required because nothing here touches
a target, and engagement data can never leave the box through this module.

Honest limits (docstring is the contract):

- ``decode_blob`` is heuristic — it chains the COMMON encodings (URL,
  base64/base64url, hex) with a printability score; exotic encodings
  (uu, ascii85, custom alphabets) are not attempted.
- ``jwt_decode`` DECODES only — it never verifies a signature and never
  fabricates one.  Suspicious ``alg`` values are flagged, not exploited.
- ``check_hash_wordlist`` covers UNSALTED md5/sha1/sha256 against a local
  wordlist only.  Salted/slow formats ($1$/$6$/bcrypt/ntlm-in-the-wild)
  are identified but refused — they need john/hashcat via the
  payloads/hash_crack.py tools (run_john/run_hashcat; the operator
  installs those binaries, and each tool preflight-checks at launch).
- ``rsa_decrypt`` needs the factors (p, q) or the private exponent; there
  is NO factoring.  Weak-crypto findings still need the operator's math.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool

_PRINTABLE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    " \t\n\r.,:;!?()[]{}<>\"'`~-_+=/\\|@#$%^&*"
)

# ---- wordlist default (resolved at call time, gateway-side) ----------------
_ROCKYOU_REL = "SecLists/Passwords/Leaked-Databases/rockyou.txt"
_MAX_WORDLIST_LINES = 14_500_000


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    return sum(1 for c in text if c in _PRINTABLE) / len(text)


_EN_FREQ = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23,
    "g": 2.02, "h": 6.09, "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03,
    "m": 2.41, "n": 6.75, "o": 7.51, "p": 1.93, "q": 0.10, "r": 5.99,
    "s": 6.33, "t": 9.06, "u": 2.76, "v": 0.98, "w": 2.36, "x": 0.15,
    "y": 1.97, "z": 0.07, " ": 17.0,
}


def _english_score(s: str) -> float:
    """Chi-square against English letter frequencies; LOWER = more English.

    Heavily penalizes non-alphabetic/control coverage so garbage previews
    never outrank real text on short inputs.
    """
    if not s:
        return 9999.0
    low = s.lower()
    n = len(low)
    clean = sum(1 for c in low if c in _EN_FREQ)
    if not clean:
        return 9999.0
    chi = sum(((low.count(c) / n) * 100.0 - f) ** 2 for c, f in _EN_FREQ.items())
    return chi + (1.0 - clean / n) * 2000.0


# --------------------------------------------------------------------------- #
# decode_blob — chained URL/base64/hex auto-decoder
# --------------------------------------------------------------------------- #

_DECODERS = (
    ("url", lambda s: urllib.parse.unquote(s)),
    ("base64", lambda s: base64.b64decode(
        s + "=" * (-len(s) % 4), validate=False).decode("utf-8")),
    ("base64url", lambda s: base64.urlsafe_b64decode(
        s + "=" * (-len(s) % 4)).decode("utf-8")),
    ("hex", lambda s: binascii.unhexlify(s).decode("utf-8")),
    ("rot13", lambda s: codecs_rot13(s)),
)


def codecs_rot13(s: str) -> str:
    import codecs

    return codecs.decode(s, "rot13")


def _looks_hex(s: str) -> bool:
    return bool(s) and len(s) % 2 == 0 and bool(re.fullmatch(r"[0-9a-fA-F]+", s))


@framework_tool(
    "Auto-decode an encoded/obfuscated blob by chaining the common "
    "transformations — URL-encoding, base64/base64url, hex, rot13 — scored "
    "by printable output, with the full step chain returned. Offline only "
    "(zero network). Use on session cookies, encoded parameters, config "
    "blobs, or anything that looks like layered encoding. Decode-chain "
    "results often expose user IDs, roles, and internal names (IDOR/authorization leads).",
    next_hints=["report_finding", "jwt_decode"],
)
def decode_blob(blob: str, max_rounds: int = 6) -> Dict[str, Any]:
    """Iteratively decode ``blob`` while printability improves.

    Each round tries URL-unquote, base64 (std + urlsafe, padding-fixed),
    hex, and rot13; a candidate replaces the current value only when it
    decodes cleanly to UTF-8 with a printable ratio >= the current one.

    Args:
        blob: The encoded value (cookie value, param, config string).
        max_rounds: Max decode rounds (default 6).
    """
    current = (blob or "").strip()
    if not current:
        return {"status": "Failed", "error": "empty blob"}
    steps: List[Dict[str, str]] = []
    best_ratio = _printable_ratio(current.encode())
    for _ in range(max(1, max_rounds)):
        improved = None
        for name, fn in _DECODERS:
            try:
                candidate = fn(current)
            except Exception:  # noqa: BLE001 - wrong decoder for this input
                continue
            if not candidate or candidate == current:
                continue
            ratio = _printable_ratio(candidate.encode())
            if ratio >= best_ratio and ratio > 0.0:
                improved = (name, candidate, ratio)
                break
        if improved is None:
            break
        name, candidate, ratio = improved
        steps.append({"scheme": name, "preview": candidate[:120]})
        current = candidate
        best_ratio = ratio
        if best_ratio > 0.99 and not re.fullmatch(
            r"[0-9a-fA-F]{8,}|[A-Za-z0-9+/=_-]{12,}", current
        ):
            break  # plain text that no longer looks encodable
    return {
        "status": "Success",
        "input_preview": (blob or "")[:120],
        "steps": steps,
        "final": current,
        "final_printable_ratio": round(best_ratio, 3),
    }


# --------------------------------------------------------------------------- #
# jwt_decode — header/payload decode, alg triage (no verification)
# --------------------------------------------------------------------------- #

_SUSPICIOUS_ALGS = {"none", "HS256", "HS384", "HS512"}


@framework_tool(
    "Decode a JWT (header + payload claims) WITHOUT verifying the signature "
    "and flag suspicious algorithms: 'none' (alg-stripping candidates) and "
    "HS256/HS384/HS512 (HMAC-on-asymmetric-confusion candidates when the "
    "issuer uses RSA keys). Offline only. exp/iat/nbf timestamps are "
    "human-readable. This is triage for auth findings, not a bypass tool.",
    next_hints=["report_finding", "decode_blob"],
)
def jwt_decode(token: str) -> Dict[str, Any]:
    """Split ``token`` on '.', base64url-decode header + payload as JSON.

    Args:
        token: The JWT string (all three parts, or two for unsigned).
    """
    tok = (token or "").strip()
    parts = tok.split(".")
    if not 2 <= len(parts) <= 3:
        return {
            "status": "Failed",
            "error": f"expected 2-3 dot-separated parts, got {len(parts)}",
        }

    def _b64d(part: str) -> Optional[Dict[str, Any]]:
        import json

        padded = part + "=" * (-len(part) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
            return json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None

    header = _b64d(parts[0])
    payload = _b64d(parts[1])
    if header is None or payload is None:
        return {"status": "Failed", "error": "header/payload not valid b64url JSON"}

    alg = str(header.get("alg", ""))
    flags: List[str] = []
    if alg.lower() == "none":
        flags.append("alg=none: signature may be strippable — TEST with the "
                     "signature removed (operator decision, gated traffic)")
    if alg in _SUSPICIOUS_ALGS:
        flags.append(
            f"{alg} is HMAC — if the API normally uses RSA/ECDSA keys, "
            "key-confusion (sign with the public key as HMAC secret) is a "
            "candidate to TEST"
        )
    claims = {k: payload.get(k) for k in ("sub", "iss", "aud", "exp", "iat", "nbf", "role", "admin") if k in payload}
    times = {
        k: time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(payload[k])))
        for k in ("exp", "iat", "nbf")
        if isinstance(payload.get(k), (int, float))
    }
    return {
        "status": "Success",
        "header": header,
        "payload": payload,
        "claims_of_interest": claims,
        "timestamps_utc": times,
        "signature_present": len(parts) == 3,
        "suspicious": flags,
        "note": "DECODE ONLY — no signature verification performed here.",
    }


# --------------------------------------------------------------------------- #
# hash identification + unsalted wordlist check
# --------------------------------------------------------------------------- #

_HASH_SHAPES = (
    (32, "md5 (or NTLM if from Windows dumps)"),
    (40, "sha1"),
    (56, "sha224"),
    (64, "sha256"),
    (96, "sha384"),
    (128, "sha512"),
)


@framework_tool(
    "Identify a hash string by shape: 32-hex (md5/NTLM), 40-hex (sha1), "
    "64-hex (sha256), plus bcrypt/md5crypt/sha512crypt prefixes. Offline "
    "heuristic only. Pairs with check_hash_wordlist for unsalted hashes.",
    next_hints=["check_hash_wordlist", "suggest_crack_mode", "run_john"],
)
def identify_hash(hash_string: str) -> Dict[str, Any]:
    """Return candidate hash types for ``hash_string`` (no cracking)."""
    s = (hash_string or "").strip()
    if not s:
        return {"status": "Failed", "error": "empty hash"}
    candidates: List[str] = []
    if s.startswith("$2a$") or s.startswith("$2b$") or s.startswith("$2y$"):
        candidates.append("bcrypt")
    elif s.startswith("$1$"):
        candidates.append("md5crypt (salted — needs john/hashcat)")
    elif s.startswith("$6$"):
        candidates.append("sha512crypt (salted — needs john/hashcat)")
    elif re.fullmatch(r"[0-9a-fA-F]+", s):
        candidates.extend(label for length, label in _HASH_SHAPES if length == len(s))
        if not candidates:
            candidates.append(f"unknown {len(s)}-hex shape")
    else:
        candidates.append("not a plain hex hash — prefix/encoding unknown")
    return {
        "status": "Success",
        "input_preview": s[:80],
        "candidates": candidates,
        "unsalted_check_supported": any(
            "md5" in c or "sha1" in c or "sha256" in c for c in candidates
        )
        and not s.startswith("$"),
    }


@framework_tool(
    "Check an UNSALTED md5/sha1/sha256 hash against a local wordlist "
    "(defaults to rockyou under the framework wordlist tree) by recomputing "
    "the digest per line. Fully offline, one pass, early-stops on a hit; "
    "capped at 14.5M lines. Salted or slow formats are refused — they need "
    "Salted or slow formats are refused — they need run_john/run_hashcat "
    "(payloads/hash_crack.py; hashcat on GPU here, preflight-checked at "
    "launch). Zero network.",
    next_hints=["report_finding"],
)
def check_hash_wordlist(
    hash_string: str,
    wordlist: str = "",
    max_lines: int = _MAX_WORDLIST_LINES,
) -> Dict[str, Any]:
    """Recompute ``hash_string`` over wordlist lines until it matches.

    Args:
        hash_string: Unsalted md5 (32 hex) / sha1 (40) / sha256 (64).
        wordlist: Optional absolute path; empty = framework default
            (rockyou under WORDLISTS_ROOT).
        max_lines: Hard cap on lines scanned.
    """
    from utils.wordlists import resolve_wordlist

    s = (hash_string or "").strip().lower()
    alg = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(s))
    if not alg or not re.fullmatch(r"[0-9a-f]+", s):
        return {
            "status": "Failed",
            "error": (
                "only unsalted md5 (32 hex) / sha1 (40) / sha256 (64) are "
                "supported here; run identify_hash, then run_john/"
                "run_hashcat (payloads/hash_crack.py) for salted/slow formats"
            ),
        }
    path = resolve_wordlist(wordlist) if wordlist else resolve_wordlist(_ROCKYOU_REL)
    if not path:
        return {
            "status": "Failed",
            "error": (
                f"wordlist not found ({wordlist or _ROCKYOU_REL}); use "
                "list_wordlists to pick one"
            ),
        }
    started = time.time()
    hfun = getattr(hashlib, alg)
    scanned = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                scanned += 1
                candidate = line.rstrip("\r\n")
                if not candidate:
                    continue
                if hfun(candidate.encode("utf-8")).hexdigest() == s:
                    return {
                        "status": "Success",
                        "found": True,
                        "plaintext": candidate,
                        "alg": alg,
                        "lines_scanned": scanned,
                        "elapsed_s": round(time.time() - started, 1),
                    }
                if scanned >= max_lines:
                    break
    except OSError as e:
        return {"status": "Failed", "error": f"wordlist read error: {e}"}
    return {
        "status": "Success",
        "found": False,
        "alg": alg,
        "lines_scanned": scanned,
        "elapsed_s": round(time.time() - started, 1),
        "note": "not in the first N lines — salted/slow format? use run_john/run_hashcat",
    }


# --------------------------------------------------------------------------- #
# xor_brute / rot_brute — single-key classical brutes
# --------------------------------------------------------------------------- #

def _decode_input(data: str) -> Optional[bytes]:
    s = (data or "").strip()
    if not s:
        return None
    if _looks_hex(s):
        try:
            return binascii.unhexlify(s)
        except binascii.Error:
            pass
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        pass
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:  # noqa: BLE001
        return None


@framework_tool(
    "Brute-force single-byte XOR keys against hex/base64 ciphertext and "
    "rank candidates by printable ratio. Offline only. Classic for CTF "
    "'obfuscated' config strings and occasionally for vendor 'encoded' "
    "client-side data in bounties.",
    next_hints=["decode_blob", "report_finding"],
)
def xor_brute(data: str, top: int = 5) -> Dict[str, Any]:
    """Try all 256 single-byte keys on ``data`` (hex or base64 input).

    Args:
        data: Ciphertext as a hex string (preferred) or base64.
        top: Number of candidates to return (default 5, cap 16).
    """
    raw = _decode_input(data)
    if raw is None:
        return {
            "status": "Failed",
            "error": "input is neither valid hex nor base64",
        }
    scored: List[tuple] = []
    for key in range(256):
        out = bytes(b ^ key for b in raw)
        ratio = _printable_ratio(out)
        if ratio > 0.5:
            scored.append((ratio, key, out))
    # Rank by English-likeness among highly-printable candidates; fall back
    # to raw printable ratio when nothing clears the bar.
    english = [(k, out, _english_score(out.decode("utf-8", errors="replace")))
               for r, k, out in scored if r >= 0.9]
    english.sort(key=lambda t: t[2])
    ranked = english if english else [
        (k, out, 9999.0 - r) for r, k, out in sorted(scored, reverse=True)
    ]
    top_n = max(1, min(int(top), 16)) if isinstance(top, int) else 5
    return {
        "status": "Success",
        "bytes": len(raw),
        "candidates": [
            {
                "key": k,
                "key_ascii": chr(k) if 32 <= k < 127 else "",
                "english_score": round(sc, 1),
                "preview": out[:120].decode("utf-8", errors="replace"),
            }
            for k, out, sc in ranked[:top_n]
        ],
        "note": "lower english_score = more English-like; eyeball the top few",
    }


@framework_tool(
    "Brute-force ROT-n letter rotations (0-25) plus ROT47 on a string and "
    "rank by a simple English-likeness score (vowels + spaces). Offline "
    "only. For 'Uryyb jbeyq'-class CTF strings and encoded breadcrumbs.",
    next_hints=["decode_blob"],
)
def rot_brute(text: str) -> Dict[str, Any]:
    """Try all letter rotations on ``text``; report the top candidates."""
    text = (text or "").strip()
    if not text:
        return {"status": "Failed", "error": "empty input"}

    def _score(s: str) -> float:
        if not s:
            return 0.0
        vowels = sum(1 for c in s.lower() if c in "aeiou ")
        return vowels / len(s)

    letters = [c for c in text if c.isalpha()]
    if not letters:
        return {"status": "Failed", "error": "no letters to rotate"}

    candidates: List[Dict[str, Any]] = []
    for shift in range(26):
        out = "".join(
            chr((ord(c) - base + shift) % 26 + base)
            if c.isalpha() and c.isascii()
            else c
            for c, base in [(c, ord("a") if c.islower() else ord("A")) for c in text]
        )
        candidates.append({"shift": shift, "score": round(_score(out), 3), "preview": out[:120]})
    rot47 = "".join(
        chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c
        for c in text
    )
    candidates.append({"shift": "rot47", "score": round(_score(rot47), 3), "preview": rot47[:120]})
    scored = [c for c in candidates if c["shift"] != 0 and c["shift"] != "rot47"]
    scored.sort(key=lambda c: _english_score(c["preview"]))
    rot47_row = {
        "shift": "rot47",
        "score": round(_score(rot47), 3),
        "preview": rot47[:120],
    }
    return {
        "status": "Success",
        "input_preview": text[:80],
        "top": scored[:8] + [rot47_row],
        "note": "shift 13 = ROT13; ranked by English-likeness (lower=better, noisy on very short strings) — eyeball the previews",
    }


# --------------------------------------------------------------------------- #
# rsa_decrypt — factors-only RSA math (no factoring, no network)
# --------------------------------------------------------------------------- #

@framework_tool(
    "Decrypt RSA ciphertext GIVEN the prime factors (p, q) — computes n, "
    "d = e^-1 mod phi, m = c^d mod n with plain int math (to_bytes, no "
    "external crypto library). Offline only. There is NO factoring: if you "
    "only have n/e, this refuses. Classic CTF 'small-factor' helper and a "
    "clean way to demonstrate weak-crypto findings.",
    next_hints=["report_finding"],
)
def rsa_decrypt(p: int, q: int, e: int, c: int) -> Dict[str, Any]:
    """RSA decrypt from prime factors.

    Args:
        p, q: The two prime factors (int).
        e: Public exponent (int).
        c: Ciphertext as an int.
    """
    try:
        p, q, e, c = int(p), int(q), int(e), int(c)
    except (TypeError, ValueError):
        return {"status": "Failed", "error": "p/q/e/c must be integers"}
    if p <= 1 or q <= 1 or e <= 1:
        return {"status": "Failed", "error": "p, q, e must be > 1"}
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        return {"status": "Failed", "error": f"e={e} not coprime with phi"}
    d = pow(e, -1, phi)
    if not 0 <= c < n:
        return {"status": "Failed", "error": f"c out of range [0, n={n})"}
    m = pow(c, d, n)
    raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
    return {
        "status": "Success",
        "n": n,
        "d": d,
        "plaintext_int": m,
        "plaintext_bytes": raw.hex(),
        "plaintext_utf8": raw.decode("utf-8", errors="replace"),
        "note": "factors were given — no factoring performed",
    }