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
import datetime
import hashlib
import os
import tomllib
import uuid

import rfc8785
from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# §3.2: the 12 ASCII bytes of "heso-plat/v1" followed by one NUL byte (0x00),
# exactly 13 bytes. The final byte is 0x00 (NUL), NOT 0x0A (newline).
SIGNING_DOMAIN = b"heso-plat/v1\x00"

# §3.3: the only algorithm tag accepted for v1.
ALG_V1 = "heso-plat/v1+ed25519"

# ── ActionReceipt v2 frozen constants (modules/action-receipt.md, chain.md) ──
# Domain-separation tags are the ASCII tag followed by one NUL (0x00). They are
# pairwise-disjoint from SIGNING_DOMAIN so a plat seal can never be replayed as an
# action authorization (and vice-versa). Mirrors heso-action/src/domain.rs.
ACTION_SIGNING_DOMAIN = b"heso-action/v1\x00"
APPROVAL_SIGNING_DOMAIN = b"heso-approval/v1\x00"
RECEIPT_CHAIN_DOMAIN = b"heso-rcpt-chain/v1\x00"
# The commitment-envelope detached-signing domain (CORE-WIRE design §0.3, ADR-0003).
# NUL-terminated + pairwise-disjoint from every other signing domain so a commitment
# signature can never be replayed as a receipt/approval signature. Mirrors
# heso-action/src/domain.rs::COMMITMENT_SIGNING_DOMAIN. FOUNDER-RATIFY-BEFORE-PUBLISH:
# this byte string becomes a frozen wire contract once the vectors ship.
COMMITMENT_SIGNING_DOMAIN = b"heso-commitment/v1\x00"
ACTION_ENVELOPE_ALG = "heso-action/v2+ed25519"
ACTION_ENVELOPE_ALG_V1 = "heso-action/v1+ed25519"
ACTION_VERSION = "heso-action/2.0"
ACTION_VERSION_V1 = "heso-action/1.0"
REDACT_COMMIT_ALG = "salted-blake3/v1"
OPERATOR_KEY_ID = "operator"
APPROVER_KEY_ID = "approver"


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


def verify_receipt(receipt_dict: dict) -> str:
    """Verify a legacy HESO/1.0 §3.5 sandbox-replay Receipt (web-observation.md
    §3.5) — the artifact detected by a ``trace_hash`` field.

    A §3.5 Receipt is signed over its canonical JSON with ``signature`` set to
    ``null`` before canonicalization (and, in pre-anchor scope, ``tsa_anchor``),
    with **no** domain-separation prefix (§3.5.1: cross-type transplant is
    prevented by schema divergence — the distinct ``trace_hash``/``seed``/``cost``
    fields — assessed LOW risk at Grade 0). Algorithm: Ed25519, same scalar-range
    rule as §3.4.1.

    Returns "Valid" / "InvalidSignature" — the two outcomes a Grade-0 §3.5
    Receipt can have (there is no envelope ``alg`` tag and no embedded content
    hash to mismatch; the structure itself is the type discriminator).
    """
    sig_obj = receipt_dict.get("signature")
    if not isinstance(sig_obj, dict) or sig_obj.get("algorithm") != "Ed25519":
        return "InvalidSignature"

    # Canonicalize the receipt with `signature` nulled (the §3.5 signing rule),
    # then verify Ed25519 over the bare canonical bytes (no domain prefix).
    to_sign = {k: v for k, v in receipt_dict.items()}
    to_sign["signature"] = None
    message = rfc8785.dumps(to_sign)

    if not _ed25519_verify(sig_obj.get("public_key", ""), sig_obj.get("signature", ""), message):
        return "InvalidSignature"
    return "Valid"


# ===========================================================================
# ActionReceipt v2 (modules/action-receipt.md)
#
# The crown-jewel artifact: a signed claim about ONE agent action. The verify
# order below mirrors the kernel's `open_receipt` (heso-action/src/verify.rs)
# step-for-step and NAMES every failure, so the clean-room verdict is the same
# string the Rust reference emits.
# ===========================================================================


def _ed25519_verify(public_key_b64: str, signature_b64: str, message: bytes) -> bool:
    """Ed25519 ``verify_strict`` over ``message`` with base64 key + signature.

    Returns ``False`` on any structural problem (bad base64, wrong key/sig
    length) or signature failure — the caller maps that to ``InvalidSignature``.
    """
    try:
        pk = base64.b64decode(public_key_b64, validate=True)
        sig = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def action_canonical_bytes(content: dict) -> bytes:
    """RFC-8785 (JCS) canonical bytes of an ActionReceipt ``content`` with the
    top-level ``action_hash`` self-field removed (a hash field cannot contain its
    own digest). Mirrors ``receipt.rs::action_canonical_bytes``.
    """
    projected = {k: v for k, v in content.items() if k != "action_hash"}
    return rfc8785.dumps(projected)


def action_content_hash(content: dict) -> str:
    """Lowercase-hex BLAKE3 of :func:`action_canonical_bytes` — the value that
    belongs in ``content.action_hash``."""
    return blake3(action_canonical_bytes(content)).hexdigest()


def anchored_content_hash(content: dict) -> str:
    """The PRE-ANCHOR content hash a trusted-time anchor certifies (the value the
    TSA signs): lowercase-hex BLAKE3 of the canonical bytes with BOTH the
    ``action_hash`` self-field AND ``time_anchor`` removed. Mirrors
    ``receipt.rs::anchored_content_hash`` — an anchor lives inside signed content,
    so it cannot certify the very ``action_hash`` that would include it.

    For an anchorless body this equals :func:`action_content_hash` (there is no
    ``time_anchor`` key to remove), which is exactly why an anchorless receipt's
    pre-anchor hash is its own ``action_hash``.
    """
    projected = {k: v for k, v in content.items() if k not in ("action_hash", "time_anchor")}
    return blake3(rfc8785.dumps(projected)).hexdigest()


def quorum_operator_base(suspended: dict, threshold: int, roster: list) -> dict:
    """Build the OPERATOR-leg quorum base from a suspended L0 content — the body the
    operator signs and the verifier recomputes each approver leg against. Mirrors
    ``receipt.rs::build_quorum_base``: sort the roster, stamp
    ``multi_approval = {threshold, roster, approvers: []}`` (EMPTY list), derive
    ``trust_level = "L1"``, and recompute ``action_hash`` over the result.

    Raises ``ValueError`` for the kernel's reject conditions (anchor on the async
    path, already-decided / not-L0 body, ``threshold < 1``, empty roster) so a
    degenerate quorum never produces a base.
    """
    if suspended.get("time_anchor") is not None:
        raise ValueError("quorum base rejects a suspended body carrying a time_anchor")
    if (
        suspended.get("approver_decision") is not None
        or suspended.get("multi_approval") is not None
        or suspended.get("trust_level") != "L0"
    ):
        raise ValueError("quorum base rejects an already-decided / non-L0 body")
    if threshold < 1:
        raise ValueError("quorum threshold must be >= 1")
    if not roster:
        raise ValueError("quorum roster must be non-empty")

    base = dict(suspended)
    base["multi_approval"] = {
        "threshold": threshold,
        "roster": sorted(roster),
        "approvers": [],
    }
    base["trust_level"] = "L1"
    base["action_hash"] = action_content_hash(base)
    return base


def multi_approval_cosign_payload(base: dict, record: dict) -> bytes:
    """The exact bytes one approver co-signs for ``record``:
    ``APPROVAL_SIGNING_DOMAIN ++ action_canonical_bytes(base with
    multi_approval.approvers = [record])``. Mirrors
    ``receipt.rs::multi_approval_cosign_payload`` over
    ``multi_approver_canonical`` — each approver vouches ONLY their own record, so
    the per-leg canonical folds in exactly that one record. The ``base`` is the
    operator base from :func:`quorum_operator_base`; the ``action_hash`` carried on
    the base is dropped by :func:`action_canonical_bytes`.
    """
    one = dict(base)
    ma = dict(base["multi_approval"])
    ma["approvers"] = [record]
    one["multi_approval"] = ma
    return APPROVAL_SIGNING_DOMAIN + action_canonical_bytes(one)


def _verify_entry(entry: dict, domain: bytes, canonical: bytes) -> bool:
    """Verify one ``SignatureEntry`` over ``domain ++ canonical``. The inner
    ``algorithm`` MUST be ``"Ed25519"`` (refused before verify, like the kernel)."""
    if entry.get("algorithm") != "Ed25519":
        return False
    return _ed25519_verify(
        entry.get("public_key", ""), entry.get("signature", ""), domain + canonical
    )


def _is_64_lower_hex(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _check_redaction(content: dict):
    """Redaction-marker well-formedness (verify.rs::check_redaction). Returns a
    reason string on a malformed marker, else ``None``."""
    redaction = content.get("redaction")
    if not isinstance(redaction, dict):
        return None
    mode = redaction.get("mode")
    for marker in redaction.get("markers", []):
        path = marker.get("field_path", "?")
        if mode == "commit_and_reveal":
            if marker.get("algorithm") != REDACT_COMMIT_ALG:
                return f"redaction marker `{path}` uses an unexpected algorithm"
            if not _is_64_lower_hex(marker.get("commitment")):
                return f"redaction marker `{path}` commitment is not 64 lowercase-hex"
        elif mode == "destructive":
            if marker.get("algorithm") == REDACT_COMMIT_ALG or marker.get("commitment"):
                return f"destructive redaction marker `{path}` must carry no commitment"
        else:
            return f"redaction record has unknown mode `{mode}`"
    return None


def verify_action_receipt(receipt: dict) -> str:
    """Verify an ActionReceipt v2 per the modules/action-receipt.md order.

    Returns exactly one of (mirroring ``ActionOutcome``):
      - "WrongAlgorithm"     — ``alg`` != ``heso-action/v2+ed25519`` (step 1)
      - "Unsupported"        — ``content.action_version`` is not recognized (step 2)
      - "HashMismatch"       — ``content.action_hash`` != recomputed (step 3)
      - "Malformed"          — structurally unusable (missing operator entry,
                               unknown signature role, both single + multi blocks)
      - "InvalidSignature"   — an operator/approver signature failed (steps 4/5)
      - "SelfApproval"       — operator key co-signed as approver (step 5)
      - "TrustLevelMismatch" — embedded trust_level != re-derived level
      - "MalformedRedaction" — a redaction marker the verifier cannot interpret
      - "Valid"              — every check passed
    """
    # Step 1: envelope algorithm.
    if receipt.get("alg") != ACTION_ENVELOPE_ALG:
        return "WrongAlgorithm"

    content = receipt.get("content")
    if not isinstance(content, dict):
        return "Malformed"

    # Step 2: format version (fail closed on an unknown layout).
    if content.get("action_version") != ACTION_VERSION:
        return "Unsupported"

    # Step 3: content self-hash.
    if content.get("action_hash") != action_content_hash(content):
        return "HashMismatch"

    signatures = receipt.get("signatures")
    if not isinstance(signatures, list):
        return "Malformed"

    # Reject any signature entry whose role is neither operator nor approver.
    for entry in signatures:
        if entry.get("key_id") not in (OPERATOR_KEY_ID, APPROVER_KEY_ID):
            return "Malformed"

    # This clean-room verifier implements the single-approver (L0/L1) lane; a
    # multi_approval quorum block is out of scope and refused rather than vouched.
    if content.get("multi_approval") is not None:
        return "Malformed"

    operators = [e for e in signatures if e.get("key_id") == OPERATOR_KEY_ID]
    approvers = [e for e in signatures if e.get("key_id") == APPROVER_KEY_ID]
    if len(operators) != 1:
        return "Malformed"
    if len(approvers) > 1:
        return "Malformed"

    canonical = action_canonical_bytes(content)
    operator = operators[0]

    # Step 4: operator signature, under ACTION_SIGNING_DOMAIN.
    if not _verify_entry(operator, ACTION_SIGNING_DOMAIN, canonical):
        return "InvalidSignature"

    # Step 5: approver co-signature (if present), under APPROVAL_SIGNING_DOMAIN.
    if approvers:
        approver = approvers[0]
        if not _verify_entry(approver, APPROVAL_SIGNING_DOMAIN, canonical):
            return "InvalidSignature"
        # An operator cannot approve its own action (domain separation alone does
        # not stop the same key signing under both domains).
        if approver.get("public_key") == operator.get("public_key"):
            return "SelfApproval"

    derived = "L1" if approvers else "L0"

    # Trust level: the embedded field is display-only; the verified roles are the
    # truth. A disagreement is refused.
    if content.get("trust_level") != derived:
        return "TrustLevelMismatch"

    # Step 6: redaction-marker well-formedness.
    redaction_err = _check_redaction(content)
    if redaction_err is not None:
        return "MalformedRedaction"

    return "Valid"


# ===========================================================================
# BLAKE3 session chain (modules/chain.md)
# ===========================================================================


def _push_field(buf: bytearray, b: bytes) -> None:
    """Append one length-prefixed field: an 8-byte LE length then the raw bytes.
    The length prefix is what makes the concatenation unambiguous (no
    field-boundary sliding). Mirrors ``chain.rs::push_field``."""
    buf += len(b).to_bytes(8, "little")
    buf += b


def link_input(content: dict) -> bytes:
    """``RECEIPT_CHAIN_DOMAIN ++ LP(session_id) ++ LP(seq_le) ++ LP(action_hash)``
    where ``LP(x) = len(x) as u64-le ++ x``. ``session_id`` defaults to empty when
    absent; ``seq`` is its 8-byte LE value; ``action_hash`` is its UTF-8 hex bytes.
    Mirrors ``chain.rs::link_input``."""
    buf = bytearray(RECEIPT_CHAIN_DOMAIN)
    _push_field(buf, (content.get("session_id") or "").encode())
    _push_field(buf, int(content.get("seq") or 0).to_bytes(8, "little"))
    _push_field(buf, content["action_hash"].encode())
    return bytes(buf)


def link_hash(content: dict) -> str:
    """The link digest a successor records in ``prev_receipt_hash``: lowercase-hex
    BLAKE3 of :func:`link_input`."""
    return blake3(link_input(content)).hexdigest()


# ── Commitment envelope (CORE-WIRE design §0, ADR-0003) ─────────────────────
def commitment_envelope_canonical_bytes(env: dict) -> bytes:
    """RFC-8785 (JCS) canonical bytes of a commitment envelope. The envelope has
    no top-level hash-region key, so this is the plain JCS of the field set.
    Mirrors ``commitment.rs::commitment_envelope_canonical_bytes`` (which delegates
    to the single ``heso_verify::canonical_bytes`` JCS impl)."""
    return canonical_bytes(env)


def commitment_fpr(public_key_b64: str) -> str | None:
    """The commitment fingerprint of an Ed25519 public key: ``blake3(raw_pubkey)``,
    full 32-byte digest, lowercase 64-hex, NO prefix (CORE-WIRE design §0.3). This
    is the value the cloud's ``derive.py`` joins ``approver_keys`` on — NOT the
    ``heso:``-prefixed Grade-0 ``signer_fingerprint``. Returns ``None`` when the
    key is not standard-base64 of exactly 32 bytes (fail closed, no partial
    digest)."""
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except (ValueError, TypeError):
        return None
    if len(raw) != 32:
        return None
    return blake3(raw).hexdigest()


def verify_commitment(
    envelope: dict,
    operator_public_key_b64: str,
    detached_sig_b64: str,
    claimed_signer_fpr: str,
) -> str:
    """REJECT-MORE-ONLY clean-room mirror of ``commitment.rs::verify_commitment``.

    Re-canonicalize the envelope, Ed25519 ``verify_strict`` the detached signature
    over ``COMMITMENT_SIGNING_DOMAIN ++ canonical``, then (LAST, only after the
    signature verified) confirm the recomputed ``blake3(pubkey)`` fingerprint equals
    the claimed one. Returns the same kind-tagged verdict string the kernel does:
    ``Valid`` | ``InvalidSignature`` | ``FingerprintMismatch`` | ``WrongAlgorithm``
    | ``Malformed``.
    """
    if not isinstance(envelope, dict):
        return "Malformed"
    try:
        canonical = commitment_envelope_canonical_bytes(envelope)
    except (ValueError, TypeError):
        return "Malformed"
    payload = COMMITMENT_SIGNING_DOMAIN + canonical

    # Distinguish a structurally-invalid key/sig (WrongAlgorithm — the stale-wheel
    # lever) from a well-formed-but-failing signature (InvalidSignature).
    try:
        pk = base64.b64decode(operator_public_key_b64, validate=True)
        sig = base64.b64decode(detached_sig_b64, validate=True)
        loaded = Ed25519PublicKey.from_public_bytes(pk)
    except (ValueError, TypeError):
        return "WrongAlgorithm"
    try:
        loaded.verify(sig, payload)
    except InvalidSignature:
        return "InvalidSignature"
    except (ValueError, TypeError):
        return "WrongAlgorithm"

    fpr = commitment_fpr(operator_public_key_b64)
    if fpr is None:
        return "WrongAlgorithm"
    if fpr != claimed_signer_fpr:
        return "FingerprintMismatch"
    return "Valid"


def verify_chain(receipts: list) -> str:
    """Verify a per-session chain of ActionReceipts (modules/chain.md).

    Runs the full per-receipt :func:`verify_action_receipt` on every link AND the
    inter-link invariants, and NAMES the failure:
      - "Empty"        — no receipts (fail closed, never Valid)
      - "ContentTamper"— a receipt's own crypto failed
      - "LinkBroken"   — every receipt self-verifies, but the ordering is wrong:
                         a bad genesis, a seq gap/repeat/regression, a session_id
                         that changes mid-chain, or a prev_receipt_hash that does
                         not equal the recomputed link of the actual predecessor
      - "Valid"        — every link verifies AND the order is intact
    """
    if not receipts:
        return "Empty"

    for i, receipt in enumerate(receipts):
        outcome = verify_action_receipt(receipt)
        if outcome != "Valid":
            return "ContentTamper"
        content = receipt["content"]
        seq = content.get("seq")

        if i == 0:
            # Genesis: seq 0, no predecessor link.
            if seq != 0:
                return "LinkBroken"
            if content.get("prev_receipt_hash"):
                return "LinkBroken"
        else:
            prev_content = receipts[i - 1]["content"]
            if seq != (prev_content.get("seq") or 0) + 1:
                return "LinkBroken"
            if content.get("session_id") != prev_content.get("session_id"):
                return "LinkBroken"
            if content.get("prev_receipt_hash") != link_hash(prev_content):
                return "LinkBroken"

    return "Valid"


# ===========================================================================
# Commit-and-reveal redaction (modules/action-receipt.md — redaction reveal)
# ===========================================================================


def redaction_commit(salt: bytes, field_path: str, value_json: bytes) -> str:
    """``BLAKE3(salt ++ field_path ++ value_json)`` as lowercase hex. Mirrors
    ``redact.rs::commit``."""
    h = blake3()
    h.update(salt)
    h.update(field_path.encode())
    h.update(value_json)
    return h.hexdigest()


def verify_reveal(field_path: str, salt_hex: str, value_json: bytes, marker: dict) -> bool:
    """Recompute the commitment for one revealed field and check it matches the
    marker — the reveal verification a sidecar holder performs. Mirrors
    ``redact.rs::verify_reveal``."""
    if marker.get("field_path") != field_path:
        return False
    if marker.get("algorithm") != REDACT_COMMIT_ALG:
        return False
    if not _is_64_lower_hex(salt_hex):
        return False
    salt = bytes.fromhex(salt_hex)
    return redaction_commit(salt, field_path, value_json) == marker.get("commitment")


# ===========================================================================
# RFC-6962 SHA-256 Merkle primitives (modules/transparency.md)
# ===========================================================================


def rfc6962_leaf_hash(value: bytes) -> bytes:
    """``SHA-256(0x00 || value)``."""
    return hashlib.sha256(b"\x00" + value).digest()


def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    """``SHA-256(0x01 || left || right)``."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def rfc6962_empty_root() -> bytes:
    """``SHA-256("")`` — the empty-tree root."""
    return hashlib.sha256(b"").digest()


def rfc6962_verify_inclusion(
    leaf_value: bytes, index: int, tree_size: int, proof: list, root: bytes
) -> bool:
    """RFC-6962 §2.1.1 inclusion verification: recompute the root from
    ``leaf_value`` at ``index`` in a ``tree_size`` tree using ``proof`` (ordered
    sibling hashes) and compare to ``root``."""
    if index >= tree_size or not (0 <= index):
        return False
    fn, sn = index, tree_size
    node = rfc6962_leaf_hash(leaf_value)
    it = iter(proof)
    while sn > 1:
        try:
            sibling = next(it)
        except StopIteration:
            return False
        if fn % 2 == 1 or fn == sn - 1:
            node = rfc6962_node_hash(sibling, node)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn = (sn + 1) >> 1
        else:
            node = rfc6962_node_hash(node, sibling)
        fn >>= 1
        sn = (sn + 1) >> 1
    # No leftover proof nodes.
    if next(it, None) is not None:
        return False
    return node == root


def rfc6962_verify_consistency(
    old_size: int,
    old_root: bytes,
    new_size: int,
    new_root: bytes,
    proof: list,
) -> bool:
    """RFC-6962 §2.1.2 consistency verification (modules/transparency.md §3.2).

    A PURE function of (sizes | roots | proof) — no tree state. Returns ``True``
    iff ``proof`` is well-formed and reconstructs BOTH the supplied ``old_root``
    (over the first ``old_size`` leaves) and ``new_root`` (over all ``new_size``
    leaves), proving the new tree is an append-only extension of the old one.

    Mirrors the kernel ``heso_action::transparency::verify_consistency`` byte for
    byte: reject ``old_size == 0`` or ``old_size > new_size``; an equal-size proof
    must be empty AND the roots equal; otherwise rebuild both roots and require an
    exact match on each.
    """
    if old_size == 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root

    # Seed: the old root is the implicit first node only when old_size is a power
    # of two (the old tree is a perfect subtree the proof does not re-send).
    seed = []
    if old_size & (old_size - 1) == 0:  # power of two (old_size >= 1 here)
        seed.append(old_root)
    seed.extend(proof)
    if not seed:
        return False

    fr = seed[0]
    sr = seed[0]
    fne = old_size - 1
    sne = new_size - 1
    while fne % 2 == 1:
        fne //= 2
        sne //= 2

    for step in seed[1:]:
        if sne == 0:
            return False
        if fne % 2 == 1 or fne == sne:
            fr = rfc6962_node_hash(step, fr)
            sr = rfc6962_node_hash(step, sr)
            while fne != 0 and fne % 2 == 0:
                fne //= 2
                sne //= 2
        else:
            sr = rfc6962_node_hash(sr, step)
        fne //= 2
        sne //= 2

    return sne == 0 and fr == old_root and sr == new_root


# ===========================================================================
# DSSE / in-toto PAE (modules/envelope.md — the §5 byte-identical guarantee)
# ===========================================================================

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def dsse_pae(payload_type: str, body: bytes) -> bytes:
    """The DSSE Pre-Authentication Encoding the signature is computed over:

    ``"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body``

    ``SP`` is one 0x20 space; ``LEN(x)`` is the byte-length as ASCII decimal with
    NO leading zeros; ``body`` is the RAW pre-base64 Statement bytes.
    """
    pt = payload_type.encode()
    return (
        b"DSSEv1 "
        + str(len(pt)).encode()
        + b" "
        + pt
        + b" "
        + str(len(body)).encode()
        + b" "
        + body
    )


def verify_dsse(envelope: dict, public_key_b64: str) -> bool:
    """Verify a single-signer DSSE envelope: base64-decode the payload back to the
    raw body, recompute :func:`dsse_pae`, and Ed25519-verify the signature against
    it. The signature does NOT cover the base64 transport text."""
    # §verify step 2: payloadType MUST be the fixed in-toto Statement type.
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return False
    try:
        body = base64.b64decode(envelope["payload"], validate=True)
    except (KeyError, ValueError, TypeError):
        return False
    pae = dsse_pae(envelope["payloadType"], body)
    for sig in envelope.get("signatures", []):
        if _ed25519_verify(public_key_b64, sig.get("sig", ""), pae):
            return True
    return False


# ===========================================================================
# Clean-room taxonomy classify() (modules/taxonomy.md, ADR-0001)
#
# An independent reference classifier driven by the open ``taxonomy.toml`` —
# NOT the Rust ``taxonomy.rs``. classify() is a TOTAL function over a CLOSED
# predicate vocabulary: classes are evaluated in priority (file) order and the
# FIRST matching class wins; the last `always` class makes residual total.
# ===========================================================================

# ADR-0001 normative mapping: the FROZEN-7 coarse verb -> the 5-primitive spine.
# `llm_call` defaults to `execute` at the spine (a model call is non-destructive
# but collapses with the other mechanism verbs at the coarse level); the gate
# re-classifies a disclosing payload to `disclose` where it can detect one.
VERB_TO_PRIMITIVE = {
    "payment": "move-value",
    "delete": "destroy",
    "account_change": "change-authority",
    "data_export": "disclose",
    "llm_call": "execute",
    "http_request": "execute",
    "tool_call": "execute",
}

KNOWN_PREDICATE_KINDS = {
    "host_set",
    "path_glob",
    "method_set",
    "argv_token",
    "row_threshold",
    "fact_flag",
    "always",
}

KNOWN_FACT_FLAGS = {
    "is_payment",
    "effect_destructive",
    "is_identity_change",
    "is_secret",
    "is_model_call",
    "row_count_unknown",
    "has_host",
    "is_local_compute",
}


def _glob_match(glob: str, path: str) -> bool:
    """Anchored glob over a request path: ``*`` matches within one path segment,
    ``**`` matches across segments. A simplified RE2-translatable matcher
    sufficient for the taxonomy's anchored path globs."""
    import re

    # Build an anchored regex: ** -> .*, * -> [^/]*, escape the rest.
    out = ["^"]
    i = 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.match("".join(out), path) is not None


def _predicate_matches(pred: dict, facts: dict) -> bool:
    kind = pred.get("kind")
    if kind == "host_set":
        host = facts.get("host")
        if not host:
            return False
        host = str(host).strip().lower()
        if host in {str(h).strip().lower() for h in pred.get("hosts", [])}:
            return True
        return any(host.endswith(str(sfx).strip().lower()) for sfx in pred.get("host_suffixes", []))
    if kind == "path_glob":
        path = facts.get("path")
        if not path:
            return False
        return any(_glob_match(g, path) for g in pred.get("path_globs", []))
    if kind == "method_set":
        method = facts.get("method")
        methods = {str(m).strip().upper() for m in pred.get("methods", [])}
        return method is not None and str(method).strip().upper() in methods
    if kind == "argv_token":
        tokens = {str(t).strip().lower() for t in facts.get("argv_tokens", [])}
        return any(str(t).strip().lower() in tokens for t in pred.get("tokens", []))
    if kind == "row_threshold":
        rows = facts.get("row_count_estimate")
        # The predicate matches only when a row count was observed and crosses the
        # bound. An absent row count is a no-match; an observed but indeterminate
        # count is represented by the row_count_unknown fact.
        if rows is None:
            return False
        return rows >= pred.get("threshold", 0)
    if kind == "fact_flag":
        return bool(facts.get(pred.get("flag", "")))
    if kind == "always":
        return True
    # Closed vocabulary: an unknown kind is a load error, never a runtime guess.
    raise ValueError(f"unknown predicate kind `{kind}` (closed vocabulary)")


# The taxonomy's `has_host` fact maps onto the generic structural observation
# "a host was resolved" so the open facts dict need not pre-compute it.
def _normalize_facts(facts: dict) -> dict:
    f = dict(facts)
    if "host" in f and f.get("host"):
        f.setdefault("has_host", True)
    return f


def _load_toml(path: str) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _repo_root_for_taxonomy(toml_path: str) -> str:
    return os.path.dirname(os.path.abspath(toml_path))


def _registry_path(toml_path: str) -> str:
    return os.path.join(_repo_root_for_taxonomy(toml_path), "registry.toml")


def _active_extension_entries(toml_path: str) -> list[dict]:
    path = _registry_path(toml_path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"taxonomy bundle missing registry.toml next to {toml_path}")
    registry = _load_toml(path)
    namespaces = {ns["ns"] for ns in registry.get("namespace", [])}
    entries = []
    active_ids = set()
    for entry in registry.get("extension", []):
        status = entry.get("status")
        if status == "deprecated":
            continue
        if status != "active":
            raise ValueError(f"extension `{entry.get('id', '')}` has unsupported status `{status}`")
        extension_id = entry.get("id", "")
        if "/" not in extension_id:
            raise ValueError(f"extension id `{extension_id}` is not namespaced")
        ns, _ = extension_id.split("/", 1)
        if ns not in namespaces:
            raise ValueError(f"extension `{extension_id}` uses unregistered namespace `{ns}`")
        if entry.get("kind") != "extend":
            raise ValueError(f"extension `{extension_id}` has unsupported kind `{entry.get('kind')}`")
        if extension_id in active_ids:
            raise ValueError(f"duplicate active extension id `{extension_id}`")
        active_ids.add(extension_id)
        if not entry.get("manifest"):
            raise ValueError(f"extension `{extension_id}` is missing manifest")
        entries.append(entry)
    return entries


def _extension_manifest_path(toml_path: str, entry: dict) -> str:
    return os.path.join(_repo_root_for_taxonomy(toml_path), entry["manifest"])


def _load_extension_manifest(toml_path: str, entry: dict) -> dict:
    path = _extension_manifest_path(toml_path, entry)
    manifest = _load_toml(path)
    extension_id = entry["id"]
    if manifest.get("id") != extension_id:
        raise ValueError(
            f"extension manifest `{path}` id `{manifest.get('id')}` does not match registry `{extension_id}`"
        )
    for key in ("version", "status", "target_class", "primitive", "predicate"):
        if key not in manifest:
            raise ValueError(f"extension `{extension_id}` is missing `{key}`")
    if manifest["status"] != entry["status"]:
        raise ValueError(f"extension `{extension_id}` status differs between registry and manifest")
    if manifest["target_class"] != entry["target_class"]:
        raise ValueError(f"extension `{extension_id}` target_class differs between registry and manifest")
    if manifest["primitive"] != entry["primitive"]:
        raise ValueError(f"extension `{extension_id}` primitive differs between registry and manifest")
    for pred in manifest.get("predicate", []):
        _validate_taxonomy_predicate(f"extension `{extension_id}`", pred)
        if pred.get("kind") == "always":
            raise ValueError(f"extension `{extension_id}` may not add an always predicate")
    return manifest


def taxonomy_extensions(toml_path: str) -> list[dict]:
    """Load active registry extension manifests in deterministic registry order."""
    return [_load_extension_manifest(toml_path, entry) for entry in _active_extension_entries(toml_path)]


def load_taxonomy(toml_path: str) -> list:
    """Parse ``taxonomy.toml`` plus active registry extensions into classes.

    Priority order remains the core class order. Active `extend` manifests append
    predicate rows to their target core class, so provider knowledge can grow
    without becoming part of the spine itself.
    """
    data = _load_toml(toml_path)
    classes = [{**cls, "predicate": list(cls.get("predicate", []))} for cls in data.get("class", [])]
    classes_by_id = {cls["id"]: cls for cls in classes}
    for cls in classes:
        for pred in cls.get("predicate", []):
            _validate_taxonomy_predicate(f"class `{cls['id']}`", pred)

    for ext in taxonomy_extensions(toml_path):
        target_class = ext["target_class"]
        if target_class not in classes_by_id:
            raise ValueError(f"extension `{ext['id']}` targets unknown class `{target_class}`")
        cls = classes_by_id[target_class]
        expected_primitive = VERB_TO_PRIMITIVE[cls["coarse_verb"]]
        if ext["primitive"] != expected_primitive:
            raise ValueError(
                f"extension `{ext['id']}` primitive `{ext['primitive']}` does not match "
                f"target class `{target_class}` primitive `{expected_primitive}`"
            )
        cls["predicate"].extend(ext.get("predicate", []))
    return classes


def classify(facts: dict, classes: list) -> dict:
    """Deterministic classify() over the open taxonomy. Returns the matched class
    id, its coarse verb, the ADR-0001 destructive primitive, the structural
    effect, and whether the result is the deny-unknown residual.

    Classes are tried in priority (file) order; predicate rows within a class OR
    together; the FIRST matching class wins; the final ``always`` class makes the
    function TOTAL (deny-unknown on residual).
    """
    f = _normalize_facts(facts)
    for cls in classes:
        rows = cls.get("predicate", [])
        if any(_predicate_matches(p, f) for p in rows):
            verb = cls["coarse_verb"]
            deny_unknown = cls["id"] == "unresolved"
            if deny_unknown:
                outcome = "residual"
            elif cls["effect"] == "observe":
                outcome = "observe"
            else:
                outcome = "destructive"
            return {
                "class": cls["id"],
                "verb": verb,
                "primitive": VERB_TO_PRIMITIVE[verb],
                "effect": cls["effect"],
                "outcome": outcome,
                "deny_unknown": deny_unknown,
            }
    # Unreachable for a well-formed taxonomy (the `always` residual is total).
    raise ValueError("taxonomy is not total: no class matched and no residual")


_KNOWN_HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}


def _validate_taxonomy_predicate(owner: str, p: dict) -> None:
    kind = p.get("kind")
    if kind not in KNOWN_PREDICATE_KINDS:
        raise ValueError(f"{owner} names unknown predicate kind `{kind}`")
    if kind == "host_set":
        _reject_unexpected_predicate_params(owner, p, {"hosts", "host_suffixes"})
        if not p.get("hosts", []) and not p.get("host_suffixes", []):
            raise ValueError(f"{owner} host_set names no hosts and no host_suffixes")
        _require_nonempty_strings(owner, "hosts", p.get("hosts", []))
        _require_nonempty_strings(owner, "host_suffixes", p.get("host_suffixes", []))
        return
    if kind == "path_glob":
        _reject_unexpected_predicate_params(owner, p, {"path_globs"})
        if not p.get("path_globs", []):
            raise ValueError(f"{owner} path_glob names no globs")
        _require_nonempty_strings(owner, "path_globs", p.get("path_globs", []))
        return
    if kind == "method_set":
        _reject_unexpected_predicate_params(owner, p, {"methods"})
        if not p.get("methods", []):
            raise ValueError(f"{owner} method_set names no methods")
        for method in p["methods"]:
            if not isinstance(method, str):
                raise ValueError(f"{owner} method_set contains non-string method {method!r}")
            up = str(method).strip().upper()
            if not up:
                raise ValueError(f"{owner} method_set contains empty method")
            if up not in _KNOWN_HTTP_METHODS:
                raise ValueError(f"{owner} method_set names unknown HTTP method {method!r}")
        return
    if kind == "argv_token":
        _reject_unexpected_predicate_params(owner, p, {"tokens"})
        if not p.get("tokens", []):
            raise ValueError(f"{owner} argv_token names no tokens")
        _require_nonempty_strings(owner, "tokens", p.get("tokens", []))
        return
    if kind == "row_threshold":
        _reject_unexpected_predicate_params(owner, p, {"threshold"})
        threshold = p.get("threshold")
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold <= 0:
            raise ValueError(f"{owner} row_threshold must have threshold > 0")
        return
    if kind == "fact_flag":
        _reject_unexpected_predicate_params(owner, p, {"flag"})
        flag = p.get("flag")
        if not isinstance(flag, str):
            raise ValueError(f"{owner} fact_flag names non-string flag `{flag}`")
        if not flag.strip():
            raise ValueError(f"{owner} fact_flag names empty flag")
        if flag != flag.strip():
            raise ValueError(f"{owner} fact_flag flag has surrounding whitespace")
        if flag not in KNOWN_FACT_FLAGS:
            raise ValueError(f"{owner} fact_flag names unknown flag `{flag}`")
        return
    if kind == "always":
        list_params = ("hosts", "host_suffixes", "path_globs", "methods", "tokens")
        if any(p.get(param, []) for param in list_params) or "threshold" in p or "flag" in p:
            raise ValueError(f"{owner} always carries parameters")


def _reject_unexpected_predicate_params(owner: str, p: dict, allowed: set[str]) -> None:
    for field in ("hosts", "host_suffixes", "path_globs", "methods", "tokens"):
        if field not in allowed and p.get(field, []):
            raise ValueError(f"{owner} {p.get('kind')} has unexpected `{field}` parameter")
    for field in ("threshold", "flag"):
        if field not in allowed and field in p:
            raise ValueError(f"{owner} {p.get('kind')} has unexpected `{field}` parameter")


def _require_nonempty_strings(owner: str, field: str, values: list) -> None:
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"{owner} {field} contains non-string value {value!r}")
        if not value.strip():
            raise ValueError(f"{owner} {field} contains empty string")


def _taxonomy_predicate_to_value(p: dict) -> dict:
    """Project ONE raw taxonomy.toml predicate row to the normalized JSON the
    ``taxonomy_hash`` is taken over — byte-identical to the kernel's
    ``taxonomy.rs::predicate_to_value`` over its VALIDATED ``Predicate``.

    The kernel hashes the *validated* predicate, not the raw row, so this mirrors
    its normalization: host/argv tokens are trimmed + lower-cased (``lower_all``),
    HTTP methods trimmed + UPPER-cased, and each variant emits exactly the kernel's
    field set under its ``kind`` tag. A row whose case/whitespace differs from the
    gold-master therefore still hashes identically — the whole point of hashing the
    normative projection rather than the file bytes.
    """
    kind = p["kind"]
    if kind == "host_set":
        return {
            "kind": "host_set",
            "hosts": [h.strip().lower() for h in p.get("hosts", [])],
            "host_suffixes": [s.strip().lower() for s in p.get("host_suffixes", [])],
        }
    if kind == "path_glob":
        return {"kind": "path_glob", "globs": list(p.get("path_globs", []))}
    if kind == "method_set":
        methods = [m.strip().upper() for m in p.get("methods", [])]
        for m in methods:
            if m not in _KNOWN_HTTP_METHODS:
                raise ValueError(f"taxonomy method_set names unknown HTTP method {m!r}")
        return {"kind": "method_set", "methods": methods}
    if kind == "argv_token":
        return {"kind": "argv_token", "tokens": [t.strip().lower() for t in p.get("tokens", [])]}
    if kind == "row_threshold":
        return {"kind": "row_threshold", "threshold": p["threshold"]}
    if kind == "fact_flag":
        return {"kind": "fact_flag", "flag": p["flag"]}
    if kind == "always":
        return {"kind": "always"}
    raise ValueError(f"unknown taxonomy predicate kind {kind!r}")


def _extension_projection(ext: dict) -> dict:
    return {
        "id": ext["id"],
        "version": ext["version"],
        "target_class": ext["target_class"],
        "primitive": ext["primitive"],
        "predicates": [_taxonomy_predicate_to_value(p) for p in ext.get("predicate", [])],
    }


def extension_hash(ext: dict) -> str:
    return blake3(rfc8785.dumps(_extension_projection(ext))).hexdigest()


def taxonomy_hash(toml_path: str) -> str:
    """``taxonomy_hash`` = BLAKE3 over the RFC-8785 (JCS) canonical projection of
    the parsed, normative classification bundle — NOT comments, whitespace, or
    key order. The bundle is the core taxonomy plus active registry extension
    manifests.

    The projection is ``{"projection_version": 1, "coarse_verb_map": ...,
    "classes": [...], "extensions": [{id, hash}, ...]}``. The class list is
    projected after active `extend` manifests have been applied, and the extension
    hash list makes the source package boundary explicit for offline verifiers.
    """
    classes = load_taxonomy(toml_path)
    proj_classes = [
        {
            "id": cls["id"],
            "coarse_verb": cls["coarse_verb"],
            "effect": cls["effect"],
            "predicates": [_taxonomy_predicate_to_value(p) for p in cls.get("predicate", [])],
        }
        for cls in classes
    ]
    extensions = [
        {"id": ext["id"], "hash": extension_hash(ext)}
        for ext in sorted(taxonomy_extensions(toml_path), key=lambda item: item["id"])
    ]
    projection = {
        "projection_version": 1,
        "coarse_verb_map": VERB_TO_PRIMITIVE,
        "classes": proj_classes,
        "extensions": extensions,
    }
    return blake3(rfc8785.dumps(projection)).hexdigest()


# ===========================================================================
# HESO-attested-rail/1 (modules/attested-rail.md)
#
# The signed enclave-egress core (`content.enclave_egress`) + the unsigned
# sidecar (`ActionReceipt.enclave_window_proofs`), plus the §6 tri-state
# verifier. Two canonical disciplines, never mixed: JCS (RFC 8785) for the JSON
# tree (delegated to :func:`canonical_bytes`) and deterministic CBOR (RFC 8949
# §4.2.1) for the signature/registry *preimages* (this section).
#
# The four CBOR preimage encoders + two wire helpers reproduce the Rust kernel's
# round-trip goldens (RT-1..10) BYTE-FOR-BYTE — that byte-identity, asserted in
# `vectors/round-trip-goldens.json`, is the neutrality proof: a Python stranger
# computes the same operator-signed bytes the Rust enclave did.
# ===========================================================================

# Phase-0 immortal contract pins (FROZEN-WIRE-SCHEMA §0.7, §1, §3.4).
ENCLAVE_PROFILE_V1 = "heso-attested-rail/1"
ENCLAVE_EVIDENCE_TYPE_V1 = "aws-nitro-v1"
ENCLAVE_VERIFIER_VERSION = 0
ENCLAVE_TOKEN_FORMAT = "biscuit-v3"
ENCLAVE_HPKE_INFO_PREFIX = b"HESO-enclave-v1\x00"
# L4 leaf-type discriminators (§4); distinct from RFC-6962 separators 0x00/0x01.
L4_LEAF_ACTION = 0x10
L4_LEAF_WINDOW = 0x11
L4_LEAF_REGISTRY = 0x12
# Phase-0 launch registry is EMPTY (§5): no 1–99, no 100–9999 allocated, so any
# key in a signed `crit` list is must-understand-but-unknown ⇒ WITHHELD (PG-4).
KNOWN_EXT_KEYS: frozenset[int] = frozenset()


class EnclaveCborError(ValueError):
    """A deterministic-CBOR preimage could not be produced (e.g. a float, which
    is FORBIDDEN in every preimage — schema §0.1/§3.7 — so there is no
    cross-language float-canonicalization surface)."""


def _cbor_head(major: int, arg: int) -> bytes:
    """One CBOR head: the 3-bit major type + the shortest definite-length
    argument encoding (RFC 8949 §4.2.1 shortest-int)."""
    prefix = major << 5
    if arg < 24:
        return bytes([prefix | arg])
    if arg < 0x100:
        return bytes([prefix | 24, arg])
    if arg < 0x10000:
        return bytes([prefix | 25]) + arg.to_bytes(2, "big")
    if arg < 0x100000000:
        return bytes([prefix | 26]) + arg.to_bytes(4, "big")
    if arg < 0x10000000000000000:
        return bytes([prefix | 27]) + arg.to_bytes(8, "big")
    raise EnclaveCborError(f"integer {arg} is outside the representable CBOR range")


def det_cbor(value: object) -> bytes:
    """RFC 8949 §4.2.1 Core Deterministic Encoding of ``value``.

    Definite-length, shortest-int, map keys sorted by their full *encoded* bytes,
    text=mt3 / bytes=mt2 / uint=mt0 / nint=mt1, no duplicate keys, **floats
    FORBIDDEN**. ``bool`` is checked before ``int`` (``bool`` is an ``int``
    subclass in Python). Reproduces ``ciborium`` emitting maps in the given order
    *because* every frozen preimage pins a key order that already equals §4.2.1
    (all keys < 24 bytes ⇒ §4.2.1 order coincides with sort-by-length-then-content
    — see schema §0.1); sorting here makes that explicit rather than incidental.
    """
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, float):
        raise EnclaveCborError("floats are forbidden in a deterministic-CBOR preimage")
    if isinstance(value, int):
        if value >= 0:
            return _cbor_head(0, value)
        return _cbor_head(1, -1 - value)
    if isinstance(value, str):
        body = value.encode("utf-8")
        return _cbor_head(3, len(body)) + body
    if isinstance(value, (bytes, bytearray)):
        return _cbor_head(2, len(value)) + bytes(value)
    if isinstance(value, list):
        out = bytearray(_cbor_head(4, len(value)))
        for item in value:
            out += det_cbor(item)
        return bytes(out)
    if isinstance(value, dict):
        entries: list[tuple[bytes, bytes]] = []
        seen: set[bytes] = set()
        for key, val in value.items():
            enc_key = det_cbor(key)
            if enc_key in seen:
                raise EnclaveCborError("duplicate map key in deterministic-CBOR preimage")
            seen.add(enc_key)
            entries.append((enc_key, det_cbor(val)))
        entries.sort(key=lambda kv: kv[0])
        out = bytearray(_cbor_head(5, len(entries)))
        for enc_key, enc_val in entries:
            out += enc_key + enc_val
        return bytes(out)
    raise EnclaveCborError(f"unencodable value of type {type(value).__name__}")


def det_cbor_decode(data: bytes) -> object:
    """Decode one deterministic-CBOR item and require it consume ALL of ``data``.

    Supports exactly the preimage value space (uint / nint / tstr / bstr / bool /
    null / array / map); rejects indefinite-length, floats, tags, and trailing
    bytes. Used only to read the D1-anchored ``event_bytes`` body back for the §6
    Check-5 congruence compares (the encoder is the authority; this is its
    inverse over the frozen subset)."""
    value, offset = _cbor_decode_at(data, 0)
    if offset != len(data):
        raise EnclaveCborError("trailing bytes after deterministic-CBOR item")
    return value


def _cbor_decode_at(data: bytes, offset: int) -> tuple[object, int]:
    if offset >= len(data):
        raise EnclaveCborError("unexpected end of CBOR input")
    initial = data[offset]
    major = initial >> 5
    info = initial & 0x1F
    offset += 1
    if info < 24:
        arg = info
    elif info == 24:
        arg = data[offset]
        offset += 1
    elif info == 25:
        arg = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
    elif info == 26:
        arg = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
    elif info == 27:
        arg = int.from_bytes(data[offset : offset + 8], "big")
        offset += 8
    else:
        raise EnclaveCborError("indefinite-length or reserved CBOR not allowed")
    if major == 0:
        return arg, offset
    if major == 1:
        return -1 - arg, offset
    if major == 2:
        return bytes(data[offset : offset + arg]), offset + arg
    if major == 3:
        return data[offset : offset + arg].decode("utf-8"), offset + arg
    if major == 4:
        items: list[object] = []
        for _ in range(arg):
            item, offset = _cbor_decode_at(data, offset)
            items.append(item)
        return items, offset
    if major == 5:
        out: dict[object, object] = {}
        for _ in range(arg):
            key, offset = _cbor_decode_at(data, offset)
            val, offset = _cbor_decode_at(data, offset)
            out[key] = val
        return out, offset
    if major == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info == 22:
            return None, offset
        raise EnclaveCborError("float / simple value not allowed in a preimage")
    raise EnclaveCborError(f"unsupported CBOR major type {major}")


def promise_sig_preimage(
    boot_id: str,
    event_id: str,
    window_id: int,
    admitted_at: str,
    content_digest: str,
    max_merge_delay_secs: int,
) -> bytes:
    """The ``promise_sig`` preimage (schema §1.4): a 6-entry deterministic-CBOR
    map (RT-2). ``event_id``/``content_digest`` are pulled from the enclosing
    ``EnclaveEgress``; the rest from the ``EnclaveWindowCommitment``. Sign =
    ``ECDSA-P384(SHA-384(.))``, DER, base64 ⇒ ``promise_sig_b64``."""
    return det_cbor(
        {
            "boot_id": boot_id,
            "event_id": event_id,
            "window_id": window_id,
            "admitted_at": admitted_at,
            "content_digest": content_digest,
            "max_merge_delay_secs": max_merge_delay_secs,
        }
    )


def event_bytes_cbor(body: dict) -> bytes:
    """The D1-anchored ``event_bytes`` body (schema §3.6, RT-8). ``blake3(.) ==
    content_digest``. Carries ``tier``/``version`` uints plus the four BLAKE3-hex
    fields and ``fetch_content_digest`` (tier-3 only). ``det_cbor`` sorts the keys
    into §4.2.1 order (header ``A8`` tier 1/2, ``A9`` tier 3)."""
    fields: dict[str, object] = {
        "tier": int(body["tier"]),
        "version": int(body["version"]),
        "event_id": body["event_id"],
        "request_hash": body["request_hash"],
        "response_hash": body["response_hash"],
        "action_params_hash": body["action_params_hash"],
        "authorization_token": body["authorization_token"],
        "server_cert_chain_hash": body["server_cert_chain_hash"],
    }
    fcd = body.get("fetch_content_digest")
    if fcd is not None:
        fields["fetch_content_digest"] = fcd
    return det_cbor(fields)


def action_params_cbor(params: object) -> bytes:
    """The ``action_params_hash`` params CBOR (schema §3.7, RT-3): recursive
    §4.2.1 encoding of a JSON value; **floats FORBIDDEN**.
    ``action_params_hash = blake3_hex(.)``."""
    return det_cbor(params)


def boot_bindings_cbor(hpke_pubkey: bytes, app_key_spki: bytes) -> bytes:
    """The ``EnclaveBootBindings`` CBOR (schema §3.3, RT-10): a 2-entry map with
    ``hpke_pubkey`` (head ``6B``) emitted BEFORE ``app_key_spki`` (head ``6C``) —
    the §4.2.1 order the pinned Rust struct declaration also produces."""
    return det_cbor({"hpke_pubkey": hpke_pubkey, "app_key_spki": app_key_spki})


def hpke_info(pcr0: bytes) -> bytes:
    """The HPKE ``info`` string (schema §3.4, RT-7): ``b"HESO-enclave-v1\\x00" ‖
    pcr0`` = 16 + 48 (full SHA-384 PCR0) = 64 bytes. A 32-byte PCR0 is REJECTED."""
    if len(pcr0) != 48:
        raise EnclaveCborError("PCR0 must be 48 bytes (SHA-384); a 32-byte PCR0 is rejected")
    return ENCLAVE_HPKE_INFO_PREFIX + pcr0


def witness_key_id_hex(witness_name: str, algo: int, pubkey: bytes) -> str:
    """``WitnessCosig.key_id_hex`` (schema §3.2, RT-6): 8 lowercase hex =
    ``SHA-256(name ‖ 0x0A ‖ algo ‖ pubkey)[:4]``. ``algo ∈ {0x04 ts-Ed25519,
    0x06 ts-ML-DSA-44}`` is the ONLY place the algorithm is encoded on the wire."""
    preimage = witness_name.encode("utf-8") + b"\x0a" + bytes([algo]) + pubkey
    return hashlib.sha256(preimage).digest()[:4].hex()


# ── L4 log + window-tree primitives (schema §2.3, §4) ───────────────────────
def enclave_window_fold(event_bytes: bytes, merkle_path: list) -> bytes:
    """Window-tree fold (schema §2.3, duplicate-last-on-odd): ``acc =
    leaf_hash(event_bytes)``; per step ``acc = i_am_right ? node_hash(sibling,
    acc) : node_hash(acc, sibling)``. SHA-256 leaf/node (RFC-6962 separators).
    DISTINCT from the L4 split-point fold (:func:`rfc6962_verify_inclusion`)."""
    acc = rfc6962_leaf_hash(event_bytes)
    for step in merkle_path:
        sibling = bytes.fromhex(step["sibling_hex"])
        if step.get("i_am_right"):
            acc = rfc6962_node_hash(sibling, acc)
        else:
            acc = rfc6962_node_hash(acc, sibling)
    return acc


def l4_type_b_leaf(boot_id: str, window_id: int, seal_time_ms: int, window_root: bytes) -> bytes:
    """L4 Type-B window-root leaf bytes (schema §4): ``0x11 ‖ boot_id[16] ‖
    window_id[u64 BE] ‖ seal_time_ms[u64 BE] ‖ window_root[32]`` (fixed 65).
    ``leaf_hash_B = rfc6962_leaf_hash(.)``."""
    return (
        bytes([L4_LEAF_WINDOW])
        + uuid.UUID(boot_id).bytes
        + window_id.to_bytes(8, "big")
        + seal_time_ms.to_bytes(8, "big")
        + window_root
    )


def l4_type_c_leaf(registry_entry_bytes: bytes) -> bytes:
    """L4 Type-C registry leaf bytes (schema §4): ``0x12 ‖ registry_entry_bytes``
    (the sidecar omits the ``0x12``; the verifier re-prepends it).
    ``leaf_hash_C = rfc6962_leaf_hash(.)``."""
    return bytes([L4_LEAF_REGISTRY]) + registry_entry_bytes


def parse_registry_entry(entry: bytes) -> dict | None:
    """Decode the L4 Type-C entry (schema §4): ``entry_schema_version[u8=0x01] ‖
    pcr0[48] ‖ pcr1[48] ‖ pcr2[48] ‖ pcr8[48] ‖ valid_from_secs[u64 BE] ‖
    valid_until_secs[u64 BE] ‖ repro_ref_len[u16 BE] ‖ repro_ref[UTF-8]`` (fixed
    211 + ``repro_ref_len``). Returns ``None`` on any length/version violation."""
    if len(entry) < 211 or entry[0] != 0x01:
        return None
    valid_from = int.from_bytes(entry[193:201], "big")
    valid_until = int.from_bytes(entry[201:209], "big")
    ref_len = int.from_bytes(entry[209:211], "big")
    if len(entry) != 211 + ref_len:
        return None
    return {
        "valid_from_secs": valid_from,
        "valid_until_secs": valid_until,
        "repro_ref": entry[211 : 211 + ref_len].decode("utf-8", "replace"),
    }


def parse_checkpoint_note(note_text: str) -> dict | None:
    """Parse a C2SP checkpoint signed-note (schema §4): body ``<origin>\\n
    <tree_size>\\n<base64std(root[32])>\\n``, a blank line, then ``— <name>
    <b64>`` sig lines. Returns ``{origin, tree_size, root(bytes), body(str),
    sig_lines}`` or ``None`` when malformed."""
    lines = note_text.split("\n")
    if len(lines) < 4 or lines[3] != "":
        return None
    origin, size_str, root_b64 = lines[0], lines[1], lines[2]
    try:
        tree_size = int(size_str)
        root = base64.b64decode(root_b64, validate=True)
    except (ValueError, TypeError):
        return None
    if tree_size < 0 or len(root) != 32:
        return None
    body = origin + "\n" + size_str + "\n" + root_b64 + "\n"
    return {
        "origin": origin,
        "tree_size": tree_size,
        "root": root,
        "body": body,
        "sig_lines": [ln for ln in lines[4:] if ln],
    }


def _es384_verify(spki_der: bytes, der_sig: bytes, message: bytes) -> bool:
    """ECDSA-P384 / ES384 (SHA-384) verify of ``der_sig`` over ``message`` under
    the DER SPKI ``spki_der``. ``ec.ECDSA(SHA384)`` hashes ``message`` internally,
    so callers pass the RAW preimage (the CBOR ``promise_sig`` preimage, or the 32
    raw window-root bytes). Returns ``False`` on any structural or signature
    failure. This is the I1 key-sourcing discipline: an RSA key loaded here cannot
    verify a P-384 signature and yields ``False``."""
    try:
        public_key = serialization.load_der_public_key(spki_der)
    except (ValueError, TypeError):
        return False
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return False
    try:
        public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA384()))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _parse_rfc3339(value: object) -> datetime.datetime | None:
    """Parse an RFC-3339/ISO-8601 timestamp to an aware ``datetime`` (``Z`` ⇒
    UTC). Returns ``None`` for anything unparseable."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _verdict(state: str, tag: str, annotations: list[str] | None = None) -> dict:
    """One tri-state outcome: ``state ∈ {VALID, FAIL, WITHHELD}`` (or the
    non-enclave skip sentinel), the §7 ``verdict_tag``, and any non-verdict
    annotations."""
    return {"state": state, "tag": tag, "annotations": annotations or []}


def _enclave_attestation(ctx: dict, evidence: object) -> dict | None:
    """The DECODED NSM attestation facts for an opaque ``evidence`` base64 string.

    THE MODELED BOUNDARY (modules/attested-rail.md §8 honest-limits): the offline
    reference verifier does NOT re-run the AWS-Nitro COSE_Sign1 / cabundle /
    PCR-extraction crypto (it needs a live enclave + the AWS root CA), so the
    conformance corpus carries the facts that parser WOULD yield, keyed by the
    ``evidence`` string. Every OTHER leg (digest binding, params/token congruence,
    window Merkle fold, RFC-6962 inclusion, ES384 ``root_sig``/``promise_sig``,
    time math) runs on the REAL wire bytes."""
    table = ctx.get("attestations")
    if not isinstance(table, dict) or not isinstance(evidence, str):
        return None
    facts = table.get(evidence)
    return facts if isinstance(facts, dict) else None


def _enclave_promise_invalid(ctx: dict, egress: dict, wc: dict, pinned_pcr0: object) -> bool:
    """Evaluate the stapled promise in the PROOF-ABSENT branch (schema §6). Any
    attestation-validity failure OR a bad ``promise_sig`` collapses (caller maps to
    a single ``EnclaveWindowPromiseInvalid``). Returns ``True`` on any failure."""
    att = _enclave_attestation(ctx, wc.get("boot_attestation_b64"))
    if att is None or not att.get("parse_ok"):
        return True
    if not att.get("cose_sig_valid"):
        return True
    if att.get("root_fpr") != ctx.get("pinned_root_fpr"):
        return True
    if att.get("pcr0") != pinned_pcr0:
        return True
    spki_b64 = att.get("app_key_spki_b64")
    if not isinstance(spki_b64, str) or not att.get("hpke_present") or not att.get("kms_present"):
        return True
    try:
        spki = base64.b64decode(spki_b64, validate=True)
        sig = base64.b64decode(wc["promise_sig_b64"], validate=True)
    except (KeyError, ValueError, TypeError):
        return True
    preimage = promise_sig_preimage(
        wc["boot_id"],
        egress["event_id"],
        int(wc["window_id"]),
        wc["admitted_at"],
        egress["content_digest"],
        int(wc["max_merge_delay_secs"]),
    )
    return not _es384_verify(spki, sig, preimage)


def _enclave_check_attestation(ctx: dict, att: dict, evidence_type: str) -> dict | None:
    """Schema §6 Checks 1–4 over the decoded attestation facts + out-of-band pins.
    Returns a FAIL verdict on the first failing leg, else ``None``."""
    if not att.get("parse_ok"):
        return _verdict("FAIL", f"EnclaveAttestationMalformed:{att.get('chain_detail', 'parse')}")
    if att.get("cose_alg") != "ES384":
        return _verdict("FAIL", "EnclaveAttestationWrongAlgorithm")
    if att.get("root_fpr") != ctx.get("pinned_root_fpr"):
        return _verdict("FAIL", "EnclaveChainNotPinnedRoot")
    if not att.get("chain_valid"):
        return _verdict("FAIL", f"EnclaveChainInvalid:{att.get('chain_detail', 'chain')}")
    bad_att = att.get("cert_expired_at_attestation")
    if bad_att is not None:
        return _verdict("FAIL", f"EnclaveCertExpiredAtAttestation:{bad_att}")
    bad_adm = att.get("cert_expired_at_admitted")
    if bad_adm is not None:
        return _verdict("FAIL", f"EnclaveCertExpiredAtAdmittedAt:{bad_adm}")
    if not att.get("issuer_is_ca"):
        return _verdict("FAIL", "EnclaveIssuerNotCa:0")
    if not att.get("cose_sig_valid"):
        return _verdict("FAIL", "EnclaveAttestationSignatureInvalid")
    pinned = ctx.get("pinned_pcr0", {})
    if not isinstance(pinned, dict) or att.get("pcr0") != pinned.get(evidence_type):
        return _verdict("FAIL", "EnclavePcr0Mismatch")
    if not isinstance(att.get("app_key_spki_b64"), str):
        return _verdict("FAIL", "EnclaveAppKeyBindingMissing")
    if not att.get("hpke_present"):
        return _verdict("FAIL", "EnclaveHpkeBindingMissing")
    if not att.get("kms_present"):
        return _verdict("FAIL", "EnclaveKmsKeyBindingMissing")
    return None


def _enclave_check_window(egress: dict, proof: dict, att: dict) -> dict | None:
    """Schema §6 Check 5: the REAL window-binding crypto — D1 digest, params/token
    congruence (over the decoded ``event_bytes``), ES384 ``root_sig``, and the
    SHA-256 window-tree fold. Returns a FAIL verdict or ``None``."""
    try:
        event_bytes = base64.b64decode(proof["event_bytes_b64"], validate=True)
    except (KeyError, ValueError, TypeError):
        return _verdict("FAIL", "EnclaveContentDigestMismatch")
    if blake3(event_bytes).hexdigest() != egress.get("content_digest"):
        return _verdict("FAIL", "EnclaveContentDigestMismatch")
    try:
        body = det_cbor_decode(event_bytes)
    except EnclaveCborError:
        return _verdict("FAIL", "EnclaveContentDigestMismatch")
    if not isinstance(body, dict):
        return _verdict("FAIL", "EnclaveContentDigestMismatch")
    token = egress.get("authorization_token", {})
    if token.get("action_params_hash") != body.get("action_params_hash"):
        return _verdict("FAIL", "EnclaveActionParamsMismatch")
    if token.get("token_hash") != body.get("authorization_token"):
        return _verdict("FAIL", "EnclaveTokenBindingMismatch")
    spki_b64 = att.get("app_key_spki_b64")
    try:
        spki = base64.b64decode(spki_b64, validate=True) if isinstance(spki_b64, str) else b""
        sig = base64.b64decode(proof["root_sig_b64"], validate=True)
        window_root = bytes.fromhex(proof["window_root_hex"])
    except (KeyError, ValueError, TypeError):
        return _verdict("FAIL", "EnclaveRootSignatureInvalid")
    if not _es384_verify(spki, sig, window_root):
        return _verdict("FAIL", "EnclaveRootSignatureInvalid")
    if enclave_window_fold(event_bytes, proof.get("merkle_path", [])) != window_root:
        return _verdict("FAIL", "EnclaveInclusionProofInvalid")
    return None


def _enclave_check_witness(ctx: dict, egress: dict, wc: dict, proof: dict) -> dict:
    """Schema §6 Check 6 (witness quorum). REAL: RFC-6962 window-root inclusion
    (the index-driven Type-B fold), C2SP note parse, ``key_id_hex`` recompute, and
    the cosig active-window check. MODELED: the raw note / cosignature signature
    validity (``ctx['invalid_checkpoints']`` / ``ctx['invalid_cosigs']``) — Ed25519
    is proven elsewhere, ML-DSA-44 is Phase-1b. Returns a leg verdict whose state
    is VALID (annotation-only), WITHHELD, or FAIL."""
    policies = ctx.get("witness_policies", {})
    policy_version = proof.get("policy_version")
    if policy_version is None:
        policy = {"threshold": 1, "require_external_min": 0}
    elif isinstance(policies, dict) and policy_version in policies:
        policy = policies[policy_version]
    else:
        return _verdict("WITHHELD", "EnclaveWitnessPolicyUnknown")

    checkpoint = proof.get("witness_checkpoint_b64")
    cosigs = proof.get("witness_cosignatures", [])
    require_external = int(policy.get("require_external_min", 0))
    threshold = int(policy.get("threshold", 1))

    if checkpoint is not None:
        note = _checkpoint_from_b64(checkpoint)
        invalid_cps = ctx.get("invalid_checkpoints", set())
        if note is None or checkpoint in invalid_cps:
            return _verdict("FAIL", "EnclaveWitnessCheckpointInvalid")
        inclusion = _enclave_window_inclusion(wc, proof, note)
        if inclusion is not None:
            return inclusion

    verified_external = 0
    invalid_cosigs = ctx.get("invalid_cosigs", set())
    witnesses = policy.get("witnesses", {}) if isinstance(policy, dict) else {}
    for cosig in cosigs:
        if not _enclave_cosig_ok(cosig, witnesses, invalid_cosigs):
            return _verdict("FAIL", "EnclaveWitnessCosigInvalid")
        verified_external += 1

    if not cosigs and checkpoint is None:
        if require_external == 0:
            return _verdict("VALID", "EnclaveWitnessedSkipped", ["EnclaveWitnessedSkipped"])
        return _verdict("WITHHELD", "EnclaveWitnessQuorumNotMet")
    if verified_external < threshold or verified_external < require_external:
        return _verdict("WITHHELD", "EnclaveWitnessQuorumNotMet")
    return _verdict("VALID", "EnclaveWitnessedGreen", ["EnclaveWitnessedGreen"])


def _checkpoint_from_b64(checkpoint_b64: object) -> dict | None:
    if not isinstance(checkpoint_b64, str):
        return None
    try:
        text = base64.b64decode(checkpoint_b64, validate=True).decode("utf-8")
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
    return parse_checkpoint_note(text)


def _enclave_window_inclusion(wc: dict, proof: dict, note: dict) -> dict | None:
    """Schema §6 Check 5.2b — bind THIS window's sealed root to the witnessed
    checkpoint via the index-driven RFC-6962 Type-B fold. WITHHELD when the carrier
    is absent/partial (never false-green), FAIL when present-but-not-included."""
    inc = proof.get("window_root_inclusion_proof")
    leaf_index = proof.get("window_root_leaf_index")
    seal_time = proof.get("window_seal_time_ms")
    if inc is None or leaf_index is None or seal_time is None:
        return _verdict("WITHHELD", "EnclaveWindowRootInclusionMissing")
    try:
        window_root = bytes.fromhex(proof["window_root_hex"])
        siblings = [base64.b64decode(s, validate=True) for s in inc]
    except (KeyError, ValueError, TypeError):
        return _verdict("FAIL", "EnclaveWindowRootInclusionInvalid")
    leaf = l4_type_b_leaf(wc["boot_id"], int(wc["window_id"]), int(seal_time), window_root)
    if not rfc6962_verify_inclusion(
        leaf, int(leaf_index), int(note["tree_size"]), siblings, note["root"]
    ):
        return _verdict("FAIL", "EnclaveWindowRootInclusionInvalid")
    return None


def _enclave_cosig_ok(cosig: dict, witnesses: object, invalid_cosigs: object) -> bool:
    """One witness cosignature: REAL ``key_id_hex`` recompute + active-window
    check; MODELED raw-signature validity. ``algo ∈ {0x04, 0x06}`` is recovered by
    recomputing ``key_id_hex`` per the policy entry."""
    if not isinstance(witnesses, dict):
        return False
    entry = witnesses.get(cosig.get("witness_name"))
    if not isinstance(entry, dict):
        return False
    try:
        pubkey = base64.b64decode(entry["pubkey_b64"], validate=True)
    except (KeyError, ValueError, TypeError):
        return False
    algo = int(entry.get("algo", 0))
    if witness_key_id_hex(cosig.get("witness_name", ""), algo, pubkey) != cosig.get("key_id_hex"):
        return False
    ts = cosig.get("timestamp_unix")
    if not isinstance(ts, int):
        return False
    active_from = int(entry.get("active_from", 0))
    retired_at = entry.get("retired_at")
    if ts < active_from or (retired_at is not None and ts >= int(retired_at)):
        return False
    if isinstance(invalid_cosigs, (set, list)) and cosig.get("cosig_line") in invalid_cosigs:
        return False
    return True


def _enclave_check_registry(ctx: dict, egress: dict, wc: dict, proof: dict) -> dict:
    """Schema §6 Check 7 (verify-as-of-mint / release registry, ADVISORY-GATING).
    REAL: the index-driven RFC-6962 Type-C fold + anti-backdating time bounds.
    MODELED: the checkpoint log-key signature validity. Absent NEVER gates;
    present-but-invalid FAILS — frozen NOW so no later check can split
    VALID(old)→FAIL(new)."""
    entry_b64 = proof.get("registry_entry_bytes")
    if entry_b64 is None:
        return _verdict("VALID", "EnclaveRegistryUnresolved", ["EnclaveRegistryUnresolved"])
    inclusion = proof.get("inclusion_proof")
    leaf_index = proof.get("registry_leaf_index")
    checkpoint = proof.get("checkpoint")
    if inclusion is None or leaf_index is None or checkpoint is None:
        return _verdict("FAIL", "EnclaveRegistryProofInvalid")
    note = _checkpoint_from_b64(checkpoint)
    if note is None or checkpoint in ctx.get("invalid_checkpoints", set()):
        return _verdict("FAIL", "EnclaveRegistryProofInvalid")
    try:
        entry_bytes = base64.b64decode(entry_b64, validate=True)
        siblings = [base64.b64decode(s, validate=True) for s in inclusion]
    except (ValueError, TypeError):
        return _verdict("FAIL", "EnclaveRegistryProofInvalid")
    leaf = l4_type_c_leaf(entry_bytes)
    if not rfc6962_verify_inclusion(
        leaf, int(leaf_index), int(note["tree_size"]), siblings, note["root"]
    ):
        return _verdict("FAIL", "EnclaveRegistryProofInvalid")
    parsed = parse_registry_entry(entry_bytes)
    mint = _parse_rfc3339(wc.get("admitted_at"))
    if parsed is None or mint is None:
        return _verdict("FAIL", "EnclaveRegistryProofInvalid")
    mint_secs = int(mint.timestamp())
    valid_until = parsed["valid_until_secs"]
    if mint_secs < parsed["valid_from_secs"] or (valid_until != 0 and mint_secs > valid_until):
        return _verdict("FAIL", "EnclaveRegistryStale")
    return _verdict("VALID", "EnclaveRegistryResolved", ["EnclaveRegistryResolved"])


def verify_attested_rail(receipt: dict, ctx: dict) -> dict:
    """Verify the HESO-attested-rail/1 enclave-egress legs of an ``ActionReceipt``
    (modules/attested-rail.md §6). Returns ``{state, tag, annotations}`` where
    ``state ∈ {VALID, FAIL, WITHHELD}`` and ``tag`` is the §7 ``verdict_tag``.

    Runs ONLY when ``content.enclave_egress`` is present (PG-1: an absent core is
    a witness-mode / fallback receipt that ``verify_action_receipt`` governs —
    returns the ``NotEnclaveGrade`` sentinel). The order is the §6 short-circuit:
    PG-1..PG-7 → TL-0..TL-2 → PG-equiv → deferred-proof gate → per-proof [Check 0
    → Checks 1–4 → Check 5] → Check 6 → Check 7 → combined VALID.

    ``ctx`` carries the out-of-band trust state a stranger supplies alongside the
    receipt (none of it lives in the receipt): ``trusted_now`` (RFC-3339 clock),
    ``verifier_version``, ``supported_profiles``, ``supported_evidence_types``,
    ``pinned_pcr0`` (``{evidence_type: hex}``), ``pinned_root_fpr``,
    ``witness_policies``, ``revocation_list``, and the modeled ``attestations`` /
    ``invalid_checkpoints`` / ``invalid_cosigs`` facts (see
    :func:`_enclave_attestation`)."""
    content = receipt.get("content")
    if not isinstance(content, dict):
        return _verdict("FAIL", "EnclaveAttestationMalformed:no-content")
    egress = content.get("enclave_egress")
    if not isinstance(egress, dict):
        return _verdict("SKIP", "NotEnclaveGrade")

    annotations: list[str] = []
    required = bool(egress.get("required"))

    # ── PG (pre-gate) ───────────────────────────────────────────────────────
    supported_profiles = ctx.get("supported_profiles", {ENCLAVE_PROFILE_V1})
    if egress.get("profile") not in supported_profiles:
        return _verdict("WITHHELD", "EnclaveUnsupportedContract")
    verifier_version = int(ctx.get("verifier_version", ENCLAVE_VERIFIER_VERSION))
    if int(egress.get("min_verifier", 0)) > verifier_version:
        return _verdict("WITHHELD", "EnclaveVersionTooNew")
    ext = egress.get("ext")
    if isinstance(ext, dict):
        for key in ext.get("crit", []):
            if int(key) not in KNOWN_EXT_KEYS:
                return _verdict("WITHHELD", f"EnclaveUnknownCriticalExtension:{key}")
    supported_evidence = ctx.get("supported_evidence_types", {ENCLAVE_EVIDENCE_TYPE_V1})
    evidence_type = egress.get("evidence_type")
    if evidence_type not in supported_evidence:
        state = "FAIL" if required else "WITHHELD"
        return _verdict(state, "EnclaveAttestationUnsupportedProfile")
    wc = egress.get("window_commitment")
    if not isinstance(wc, dict):
        state = "FAIL" if required else "WITHHELD"
        return _verdict(state, "EnclaveProofAbsent")

    proofs = receipt.get("enclave_window_proofs") or []
    for proof in proofs:
        if wc.get("boot_attestation_b64") != proof.get("evidence"):
            return _verdict("FAIL", "EnclaveBootAttestationMismatch")

    # ── TL (authorization-token signed-core leg) ────────────────────────────
    token = egress.get("authorization_token", {})
    admitted = _parse_rfc3339(wc.get("admitted_at"))
    if admitted is None:
        return _verdict("FAIL", "EnclaveProofAbsent")
    if token.get("format") != ENCLAVE_TOKEN_FORMAT:
        return _verdict("FAIL", "EnclaveTokenMalformed")
    expires = _parse_rfc3339(token.get("expires_at"))
    if expires is None:
        return _verdict("FAIL", "EnclaveTokenMalformed")
    if expires < admitted:
        return _verdict("FAIL", "EnclaveTokenExpired")

    # ── PG-equiv: one boot must commit to one window root ───────────────────
    by_evidence: dict[str, str] = {}
    for proof in proofs:
        ev = proof.get("evidence")
        root = proof.get("window_root_hex")
        if isinstance(ev, str):
            if ev in by_evidence and by_evidence[ev] != root:
                return _verdict("FAIL", "EnclaveEquivocationDetected")
            by_evidence[ev] = root

    pinned_pcr0_map = ctx.get("pinned_pcr0", {})
    pinned_pcr0 = pinned_pcr0_map.get(evidence_type) if isinstance(pinned_pcr0_map, dict) else None

    # ── Deferred-proof gate (branch on PROOF-PRESENCE) ──────────────────────
    if not proofs:
        att = _enclave_attestation(ctx, wc.get("boot_attestation_b64"))
        if att is not None and att.get("parse_ok"):
            stamp = _parse_rfc3339(att.get("timestamp"))
            if stamp is not None and stamp > admitted:
                return _verdict("FAIL", "EnclaveTimestampAnomaly")
        if _enclave_promise_invalid(ctx, egress, wc, pinned_pcr0):
            return _verdict("FAIL", "EnclaveWindowPromiseInvalid")
        now = _parse_rfc3339(ctx.get("trusted_now"))
        deadline = admitted + datetime.timedelta(seconds=int(wc.get("max_merge_delay_secs", 0)))
        if now is None or now <= deadline:
            return _verdict("WITHHELD", "EnclaveWindowPending")
        return _verdict("FAIL", "EnclaveWindowPromiseBreached")

    # ── PROOF-PRESENT branch ────────────────────────────────────────────────
    for proof in proofs:
        att = _enclave_attestation(ctx, proof.get("evidence"))
        if att is not None and att.get("parse_ok"):
            stamp = _parse_rfc3339(att.get("timestamp"))
            if stamp is not None and stamp > admitted:
                return _verdict("FAIL", "EnclaveTimestampAnomaly")
        # Check 0 — congruence, before the attestation_profile dispatch.
        if evidence_type != proof.get("attestation_profile"):
            return _verdict("FAIL", "EnclaveAttestationProfileMismatch")
        if proof.get("profile") != egress.get("profile"):
            return _verdict("FAIL", "EnclaveContractProfileMismatch")
        if att is None:
            return _verdict("FAIL", "EnclaveAttestationMalformed:no-attestation")
        fail = _enclave_check_attestation(ctx, att, str(evidence_type))
        if fail is not None:
            return fail
        fail = _enclave_check_window(egress, proof, att)
        if fail is not None:
            return fail

    witness = _enclave_check_witness(ctx, egress, wc, proofs[0])
    if witness["state"] != "VALID":
        return witness
    annotations += witness["annotations"]

    registry = _enclave_check_registry(ctx, egress, wc, proofs[0])
    if registry["state"] == "FAIL":
        return registry
    annotations += registry["annotations"]

    revocation = ctx.get("revocation_list", set())
    if token.get("revocation_id") in revocation:
        annotations.append("EnclaveRevocationAdvisory")

    return _verdict("VALID", "EnclaveValid", annotations)


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

    # Dispatch by artifact shape. An ActionReceipt v2 is detected by its envelope
    # alg; a chain is a JSON array of them; a SealedPlat by {alg,content,signature}
    # with the plat alg; a §3.5 Receipt by a `trace_hash`; a bare plat by a
    # top-level `plat_hash`.
    if isinstance(obj, list):
        outcome = verify_chain(obj)
    elif isinstance(obj, dict) and obj.get("alg") == ACTION_ENVELOPE_ALG:
        outcome = verify_action_receipt(obj)
    elif isinstance(obj, dict) and {"alg", "content", "signature"} <= obj.keys():
        outcome = verify_sealed_plat(obj)
    elif isinstance(obj, dict) and isinstance(obj.get("trace_hash"), str):
        outcome = verify_receipt(obj)
    elif isinstance(obj, dict) and isinstance(obj.get("plat_hash"), str):
        outcome = "Valid" if obj["plat_hash"].lower() == plat_hash(obj) else "HashMismatch"
    else:
        print(
            "error: input is not a recognized HESO artifact "
            "(action receipt, chain, sealed plat, §3.5 receipt, or plat)",
            file=sys.stderr,
        )
        sys.exit(2)

    if outcome == "Valid":
        print(f"OK {outcome}")
        sys.exit(0)
    print(f"FAIL {outcome}", file=sys.stderr)
    _exit_1 = ("InvalidSignature", "SelfApproval", "ContentTamper", "LinkBroken")
    sys.exit(1 if outcome in _exit_1 else 2)
