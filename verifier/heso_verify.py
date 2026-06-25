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
import hashlib
import tomllib

import rfc8785
from blake3 import blake3
from cryptography.exceptions import InvalidSignature
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
        host = host.lower()
        if host in [h.lower() for h in pred.get("hosts", [])]:
            return True
        return any(host.endswith(sfx) for sfx in pred.get("host_suffixes", []))
    if kind == "path_glob":
        path = facts.get("path")
        if not path:
            return False
        return any(_glob_match(g, path) for g in pred.get("path_globs", []))
    if kind == "method_set":
        method = facts.get("method")
        return method is not None and method in pred.get("methods", [])
    if kind == "argv_token":
        tokens = {t.lower() for t in facts.get("argv_tokens", [])}
        return any(t.lower() in tokens for t in pred.get("tokens", []))
    if kind == "row_threshold":
        rows = facts.get("row_count_estimate")
        # The predicate matches only when a row count was OBSERVED and crosses the
        # bound. An ABSENT row count is "this action is not a counted data read" —
        # it does NOT match (otherwise bulk_data would swallow every action that
        # carries no count, pre-empting model/messaging/generic). The taxonomy's
        # "UNKNOWN fails SAFE" rule applies to an action already in a data-read
        # lane whose count is indeterminate; expressing that needs a paired
        # observed fact (e.g. a data-egress flag) and is a P2 classify refinement.
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


def load_taxonomy(toml_path: str) -> list:
    """Parse ``taxonomy.toml`` into the ordered list of classes (priority order =
    file order). Reads the gold-master verbatim; no Rust dependency."""
    with open(toml_path, "rb") as fh:
        data = tomllib.load(fh)
    return data.get("class", [])


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
            return {
                "class": cls["id"],
                "verb": verb,
                "primitive": VERB_TO_PRIMITIVE[verb],
                "effect": cls["effect"],
                "deny_unknown": cls["id"] == "unresolved",
            }
    # Unreachable for a well-formed taxonomy (the `always` residual is total).
    raise ValueError("taxonomy is not total: no class matched and no residual")


_KNOWN_HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}


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


def taxonomy_hash(toml_path: str) -> str:
    """``taxonomy_hash`` = BLAKE3 over the RFC-8785 (JCS) canonical projection of
    the parsed, normative classification data — NOT comments, whitespace, or key
    order. Mirrors taxonomy.md §4 and, byte-for-byte, the kernel
    ``heso_engine::Taxonomy::to_canonical_value`` (taxonomy.rs).

    The projection is ``{"version": 1, "classes": [{id, coarse_verb, effect,
    predicates: [<normalized predicate>, ...]}, ...]}`` — the SAME shape the kernel
    hashes, so this clean-room recompute reproduces the kernel golden
    (``9f3bbaaf…``). (The pre-2026 clean-room projection dumped a bare list with raw
    TOML predicate rows under a ``predicate`` key and diverged from the kernel; this
    is the corrected, kernel-faithful projection.)
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
    projection = {"version": 1, "classes": proj_classes}
    return blake3(rfc8785.dumps(projection)).hexdigest()


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
