"""HESO/1.0 reference verifier (Grade 0).

Implements the plat content hash (§1.8) and the sealed-envelope verification
order (§3.4) from HESO-1.0.md. A stranger holding only a sealed envelope and
this file can independently decide whether the envelope is Valid — no network,
no clock, no key distribution.

Dependencies (see requirements.txt): rfc8785, blake3, cryptography.

Ed25519 strictness (§3.4.1): cryptography's Ed25519PublicKey.verify is backed
by OpenSSL, which enforces the RFC 8032 §5.1.7 canonical scalar-range check
(rejects s >= ell as a bad signature). That satisfies §3.4.1's MUST. OpenSSL
does NOT additionally reject small-order / torsion public keys, so this verifier
does NOT implement §3.4.1's SHOULD (torsion rejection). Per §3.4.1 that is
conformant at Grade 0 (the signer presents their own key; a torsion-key attack
needs an attacker-chosen key, outside the Grade 0 threat model). This verifier
therefore implements the Grade 0 level.
"""

from __future__ import annotations

import base64

import rfc8785
from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# §3.2: the 12 ASCII bytes of "heso-plat/v1" followed by one NUL byte (0x00),
# exactly 13 bytes. The final byte is 0x00 (NUL), NOT 0x0A (newline).
SIGNING_DOMAIN = b"heso-plat/v1\x00"

# §3.3: the only algorithm tag accepted for v1.
ALG_V1 = "heso-plat/v1+ed25519"


def canonical_bytes(value) -> bytes:
    """RFC 8785 (JCS) canonical bytes of ``value`` (§1.7).

    Per §1.8 and §3.2, the canonical bytes used for BOTH the content hash and
    the signature exclude a *top-level* ``plat_hash`` field — a hash field
    cannot contain its own digest, and the reference implementation signs over
    these same plat_hash-excluded bytes. Nested ``plat_hash`` values (e.g. in
    ``linked_pages[*]``) are ordinary content and are retained.
    """
    if isinstance(value, dict) and "plat_hash" in value:
        value = {k: v for k, v in value.items() if k != "plat_hash"}
    return rfc8785.dumps(value)


def plat_hash(plat_dict: dict) -> str:
    """Compute the §1.8 content hash of a plat body.

    Lowercase-hex BLAKE3 (64 chars / 256 bits) of the canonical bytes, which
    exclude the top-level ``plat_hash`` field (see :func:`canonical_bytes`).
    """
    return blake3(canonical_bytes(plat_dict)).hexdigest()


def verify_sealed_plat(envelope_dict: dict) -> str:
    """Verify a sealed envelope per the §3.4 normative order.

    Returns exactly one of:
      - "WrongAlgorithm"  — ``alg`` is not ``heso-plat/v1+ed25519`` (§3.4 step 1)
      - "HashMismatch"    — ``content.plat_hash`` != recomputed hash (step 2);
                            the signature is intentionally NOT checked, because
                            HashMismatch is the clearer diagnostic for a mutated
                            body.
      - "InvalidSignature"— Ed25519 verification failed over
                            SIGNING_DOMAIN ++ canonical_bytes(content) (step 3),
                            OR the envelope was structurally unusable (missing
                            fields, malformed base64, bad key/signature length).
      - "Valid"           — all three checks passed.
    """
    # Step 1 (§3.4): algorithm tag. A verifier MUST refuse any other tag rather
    # than silently assume Ed25519.
    if envelope_dict.get("alg") != ALG_V1:
        return "WrongAlgorithm"

    content = envelope_dict.get("content")
    if not isinstance(content, dict):
        # No content to hash or verify; treat as unverifiable signature.
        return "InvalidSignature"

    # Step 2 (§3.4): recompute the content hash and compare against the embedded
    # value. A missing or non-string embedded hash cannot match a 64-char hex
    # digest, so it falls through to HashMismatch.
    embedded = content.get("plat_hash")
    recomputed = plat_hash(content)
    if not isinstance(embedded, str) or embedded.lower() != recomputed:
        return "HashMismatch"

    # Step 3 (§3.4): Ed25519 verification over SIGNING_DOMAIN ++ canonical
    # bytes of the FULL content (including its plat_hash field — only the
    # top-level envelope is unsigned; content is signed verbatim).
    sig_obj = envelope_dict.get("signature")
    if not isinstance(sig_obj, dict):
        return "InvalidSignature"
    if sig_obj.get("algorithm") != "Ed25519":
        return "InvalidSignature"

    try:
        public_key = base64.b64decode(sig_obj["public_key"], validate=True)
        signature = base64.b64decode(sig_obj["signature"], validate=True)
    except (KeyError, ValueError, TypeError):
        return "InvalidSignature"

    message = SIGNING_DOMAIN + canonical_bytes(content)

    try:
        # from_public_bytes raises ValueError if the key is not 32 bytes.
        # verify enforces the RFC 8032 §5.1.7 scalar-range check via OpenSSL
        # (§3.4.1 MUST) and raises InvalidSignature on any failure.
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return "InvalidSignature"

    return "Valid"


# ---------------------------------------------------------------------------
# CLI: `python heso_verify.py <file>` (or stdin). Mirrors the Rust
# `heso-verify` binary: exit 0 valid / 1 invalid signature / 2 wrong
# algorithm, hash mismatch, or malformed input.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    import sys

    argv = sys.argv[1:]
    if any(a in ("-h", "--help") for a in argv):
        print("usage: python heso_verify.py [<file>]   (omit <file> or use - for stdin)")
        sys.exit(0)

    try:
        if argv and argv[0] != "-":
            raw = open(argv[0], encoding="utf-8").read()
        else:
            raw = sys.stdin.read()
        obj = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    if isinstance(obj, dict) and {"alg", "content", "signature"} <= obj.keys():
        outcome = verify_sealed_plat(obj)
    elif isinstance(obj, dict) and isinstance(obj.get("plat_hash"), str):
        outcome = "Valid" if obj["plat_hash"].lower() == plat_hash(obj) else "HashMismatch"
    else:
        print("error: input is neither a sealed envelope nor a hashable plat", file=sys.stderr)
        sys.exit(2)

    if outcome == "Valid":
        print(f"OK {outcome}")
        sys.exit(0)
    print(f"FAIL {outcome}", file=sys.stderr)
    sys.exit(1 if outcome == "InvalidSignature" else 2)
