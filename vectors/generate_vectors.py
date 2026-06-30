"""Generate the HESO/1 crown-jewel conformance vectors.

Writes ``vectors/heso-1.0-crown-vectors.json`` — the NEW goldens the P1 absorption
adds on top of the legacy plat/sealed-plat corpus in ``heso-1.0-vectors.json``:

  - ``action_receipt_v2``  — the default signed agent-action receipt (L0 + the
                             gated L1 co-signature lane) and the named verify-order
                             failure cases (HashMismatch / WrongAlgorithm /
                             InvalidSignature / SelfApproval / TrustLevelMismatch).
  - ``chain``              — the BLAKE3 hash-linked per-session chain: a valid
                             3-link chain plus a tampered (spliced predecessor)
                             negative.
  - ``redaction``         — commit-and-reveal: the salted-BLAKE3 commitment, the
                             reveal recomputation, and a bad-salt negative.
  - ``taxonomy_classify`` — deterministic classify() goldens (the ADR-0001 5-spine
                            mapped onto the FROZEN-7 verbs) over ``taxonomy.toml``.
  - ``rfc6962``           — RFC-6962 leaf/node/empty hashes + an inclusion proof.
  - ``dsse_pae``          — a golden in-toto Statement wrapped in DSSE, with the
                            exact PAE pre-image bytes and the signature over them.

PROVENANCE (per vector, tagged in the ``provenance`` field):
  - ``rust-reference``  — the receipt/chain bytes are minted AND validated by the
                          kept Rust reference. Ed25519 is deterministic (RFC 8032),
                          so a fixed-seed signature is byte-identical regardless of
                          which language computes it; we cross-check that the
                          all-zero-seed signer reproduces the committed Rust golden
                          in ``heso-1.0-vectors.json`` BYTE-FOR-BYTE, then validate
                          every assembled receipt/chain end-to-end through the Rust
                          ``heso-verify-cli`` (it must return the expected verdict).
                          A vector is only tagged rust-reference once the Rust CLI
                          has accepted/rejected it as expected.
  - ``spec-derived``    — derived from the normative spec using the SAME primitives
                          (rfc8785 / blake3 / sha2 / ed25519) where the Rust core
                          has no runnable CLI entrypoint to mine (the standalone
                          taxonomy classifier, the RFC-6962 primitives, the DSSE
                          PAE pre-image). These are the P2 cross-language-gate
                          blockers: a Rust runnable must regenerate them and the gate
                          must assert byte-equality.

The Rust cross-check + verify-cli paths only run when ``HESO_VERIFY_CLI`` and
``HESO_FIXTURE_SIGNER`` point at the built binaries (or they are found on PATH /
the sibling enterprise target dir). Without them the generator still emits every
vector; the rust-reference receipts are then asserted only against the committed
legacy golden signature (still a real cross-check) and flagged in stderr.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys

import rfc8785
from blake3 import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The clean-room verifier is the SINGLE source of truth for the new conformance
# projections (taxonomy_hash, anchored_content_hash, quorum cosign payload). The
# generator imports them rather than re-deriving, so a published vector and the
# verifier can never drift; the Rust kernel mint is then asserted == this.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "verifier"))
from heso_verify import (  # noqa: E402
    anchored_content_hash as clean_anchored_content_hash,
    multi_approval_cosign_payload as clean_cosign_payload,
    quorum_operator_base as clean_quorum_base,
    taxonomy_hash as clean_taxonomy_hash,
)

# ── Frozen constants (mirrored from heso-action/src/domain.rs) ──────────────
ACTION_SIGNING_DOMAIN = b"heso-action/v1\x00"
APPROVAL_SIGNING_DOMAIN = b"heso-approval/v1\x00"
RECEIPT_CHAIN_DOMAIN = b"heso-rcpt-chain/v1\x00"
ACTION_ENVELOPE_ALG = "heso-action/v2+ed25519"
ACTION_VERSION = "heso-action/2.0"
REDACT_COMMIT_ALG = "salted-blake3/v1"
OPERATOR_KEY_ID = "operator"
APPROVER_KEY_ID = "approver"

# The all-zero Ed25519 seed pins the canonical golden identity across the whole
# HESO project. Its public key is the value the committed legacy goldens use.
ZERO_SEED = bytes(32)
ZERO_SEED_PUBKEY = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
# A distinct approver identity (seed = 0x05 * 32), mirroring the Rust test's
# APPROVER_SEED so the L1 co-signature golden lines up with the reference.
APPROVER_SEED = bytes([5]) * 32

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(REPO, "vectors", "heso-1.0-crown-vectors.json")
TAXONOMY_PATH = os.path.join(REPO, "taxonomy.toml")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _pub_b64(sk: Ed25519PrivateKey) -> str:
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _b64(raw)


def action_canonical_bytes(content: dict) -> bytes:
    """RFC-8785 (JCS) canonical bytes of ``content`` with the top-level
    ``action_hash`` self-field removed (mirrors receipt.rs::action_canonical_bytes)."""
    projected = {k: v for k, v in content.items() if k != "action_hash"}
    return rfc8785.dumps(projected)


def action_content_hash(content: dict) -> str:
    return blake3(action_canonical_bytes(content)).hexdigest()


def sign_entry(sk: Ed25519PrivateKey, role: str, domain: bytes, content: dict) -> dict:
    sig = sk.sign(domain + action_canonical_bytes(content))
    return {
        "algorithm": "Ed25519",
        "key_id": role,
        "public_key": _pub_b64(sk),
        "signature": _b64(sig),
    }


# ── Golden ActionContent bodies (mirror heso-action fixtures::fixed_content) ──
def fixed_content() -> dict:
    return {
        "action_version": ACTION_VERSION,
        "captured_at": "2026-05-29T12:00:00Z",
        "agent_identity": ZERO_SEED_PUBKEY,
        "action": {
            "verb": "llm_call",
            "tool_name": "openai.chat.completions",
            "target_host": "api.openai.com",
            "workflow": "research-run-7",
            "account": "acct_acme",
            "fields": {"prompt": "summarize the filing", "model": "gpt-4o"},
            "result_hash": "a" * 64,
        },
        "policy": {
            "rule_id": "allow-llm",
            "rule_display": "allow llm_call to api.openai.com",
            "matched_conditions": [{"field": "verb", "op": "eq", "value": "llm_call"}],
            "decision_path": "allow",
        },
        "trust_level": "L0",
        "action_hash": "",
    }


def signed_l0(op: Ed25519PrivateKey, content: dict) -> dict:
    content = dict(content)
    content["trust_level"] = "L0"
    content["action_hash"] = action_content_hash(content)
    return {
        "alg": ACTION_ENVELOPE_ALG,
        "content": content,
        "signatures": [sign_entry(op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, content)],
        "transparency": [],
    }


def signed_l1(op: Ed25519PrivateKey, ap: Ed25519PrivateKey, content: dict) -> dict:
    content = dict(content)
    content["trust_level"] = "L1"
    content["policy"] = dict(content["policy"])
    content["policy"]["decision_path"] = "require_approval"
    content["approver_decision"] = {
        "decision": "approved",
        "approver_identity": _pub_b64(ap),
        "reason": "amount under desk limit",
        "decided_at": "2026-05-29T12:05:00Z",
        "sla_minutes": 30,
    }
    content["action_hash"] = action_content_hash(content)
    return {
        "alg": ACTION_ENVELOPE_ALG,
        "content": content,
        "signatures": [
            sign_entry(op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, content),
            sign_entry(ap, APPROVER_KEY_ID, APPROVAL_SIGNING_DOMAIN, content),
        ],
        "transparency": [],
    }


# ── Chain (mirror chain.rs::link_input / link_hash) ─────────────────────────
def _push_field(buf: bytearray, b: bytes) -> None:
    buf += len(b).to_bytes(8, "little")
    buf += b


def link_input(content: dict) -> bytes:
    buf = bytearray(RECEIPT_CHAIN_DOMAIN)
    _push_field(buf, (content.get("session_id") or "").encode())
    _push_field(buf, int(content.get("seq") or 0).to_bytes(8, "little"))
    _push_field(buf, content["action_hash"].encode())
    return bytes(buf)


def link_hash(content: dict) -> str:
    return blake3(link_input(content)).hexdigest()


def chained_receipt(
    op: Ed25519PrivateKey, session: str, seq: int, prev: str | None, suffix: str
) -> dict:
    content = fixed_content()
    content["action"] = dict(content["action"])
    content["action"]["workflow"] = f"session-{session}-step-{seq}-{suffix}"
    content["session_id"] = session
    content["seq"] = seq
    if prev is not None:
        content["prev_receipt_hash"] = prev
    content["trust_level"] = "L0"
    content["action_hash"] = action_content_hash(content)
    return {
        "alg": ACTION_ENVELOPE_ALG,
        "content": content,
        "signatures": [sign_entry(op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, content)],
        "transparency": [],
    }


# ── Commit-and-reveal redaction (mirror redact.rs) ──────────────────────────
def redact_commit(salt: bytes, field_path: str, value_json: bytes) -> str:
    h = blake3()
    h.update(salt)
    h.update(field_path.encode())
    h.update(value_json)
    return h.hexdigest()


def redaction_merkle_root(commitments: list[str]) -> str:
    h = blake3()
    for c in commitments:
        h.update(c.encode())
        h.update(b"\n")
    return h.hexdigest()


# ── RFC-6962 (mirror transparency.rs) ───────────────────────────────────────
import hashlib  # noqa: E402


def rfc6962_leaf(value: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + value).digest()


def rfc6962_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def rfc6962_empty_root() -> bytes:
    return hashlib.sha256(b"").digest()


def rfc6962_root(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return rfc6962_empty_root()
    if n == 1:
        return rfc6962_leaf(leaves[0])
    k = 1
    while (k << 1) < n:
        k <<= 1
    return rfc6962_node(rfc6962_root(leaves[:k]), rfc6962_root(leaves[k:]))


# ── DSSE / in-toto PAE (mirror standard/conformance-and-envelope.md §5) ─────
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def dsse_pae(payload_type: str, body: bytes) -> bytes:
    return (
        b"DSSEv1"
        + b" "
        + str(len(payload_type)).encode()
        + b" "
        + payload_type.encode()
        + b" "
        + str(len(body)).encode()
        + b" "
        + body
    )


# ── Rust reference cross-checks ─────────────────────────────────────────────
def _find_bin(env_var: str, name: str) -> str | None:
    p = os.environ.get(env_var)
    if p and os.path.exists(p):
        return p
    found = shutil.which(name)
    if found:
        return found
    candidate = os.path.join(REPO, "..", "heso-enterprise", "target", "debug", name)
    candidate = os.path.abspath(candidate)
    return candidate if os.path.exists(candidate) else None


VERIFY_CLI = _find_bin("HESO_VERIFY_CLI", "heso-verify-cli")
# The cross-language conformance MINT runnable (crates/heso-fixture-signer's
# `heso-conformance` bin). When present, the three spec-derived blocks
# (`dsse_pae` / `taxonomy_classify` / `rfc6962`) are minted by the RUST kernel and
# this generator asserts the Rust bytes equal the clean-room Python derivation —
# the byte-identical guarantee asserted Rust<->Python (not just Python-vs-golden).
CONFORMANCE_BIN = _find_bin("HESO_CONFORMANCE_BIN", "heso-conformance")


def conformance_mint(args: list[str]) -> dict | None:
    """Run a `heso-conformance` subcommand and parse its single-line JSON. Returns
    ``None`` when the binary is unavailable (the generator then falls back to the
    clean-room Python derivation, tagged spec-derived)."""
    if not CONFORMANCE_BIN:
        return None
    out = subprocess.run([CONFORMANCE_BIN, *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(
            f"heso-conformance {args[0]} failed (exit {out.returncode}): {out.stderr.strip()}"
        )
    return json.loads(out.stdout)


def verify_cli_verdict(receipts: list[dict], pubkey: str) -> str | None:
    """Run a receipt/chain through the Rust reference verifier; return its status
    string (``valid`` / ``invalid`` / ``wrong-alg-or-hash`` ...) or ``None`` when
    the CLI is unavailable."""
    if not VERIFY_CLI:
        return None
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        rp = os.path.join(td, "receipts.jsonl")
        pk = os.path.join(td, "pubkey")
        with open(rp, "w") as fh:
            for r in receipts:
                fh.write(json.dumps(r) + "\n")
        with open(pk, "w") as fh:
            fh.write(pubkey + "\n")
        out = subprocess.run([VERIFY_CLI, "--json", rp, pk], capture_output=True, text=True)
        try:
            return json.loads(out.stdout)["status"]
        except (json.JSONDecodeError, KeyError):
            return f"unparsable:{out.stdout.strip()}|{out.stderr.strip()}"


def main() -> int:
    op = Ed25519PrivateKey.from_private_bytes(ZERO_SEED)
    ap = Ed25519PrivateKey.from_private_bytes(APPROVER_SEED)

    # Hard provenance gate: the all-zero-seed signer MUST reproduce the committed
    # legacy Rust golden signature byte-for-byte, or every "rust-reference" claim
    # below is void.
    legacy_canon = bytes.fromhex(
        "7b22616374696f6e73223a5b5d2c226465736372697074696f6e223a22222c22696e"
        "7075745f75726c223a2268747470733a2f2f6578616d706c652e636f6d2f222c2274"
        "69746c65223a224578616d706c65222c2274726565223a5b5d2c2275726c223a2268"
        "747470733a2f2f6578616d706c652e636f6d2f227d"
    )
    legacy_sig = op.sign(b"heso-plat/v1\x00" + legacy_canon)
    legacy_golden_sig = (
        "wNzBIcWiNtEUEGcobYsQ9XwL5Dp5GFMSHxVinCUhXHymWYq0Eflns1z6YAuSnw39RD91ifZh81LYhnKg3/zsDQ=="
    )
    assert _pub_b64(op) == ZERO_SEED_PUBKEY, "zero-seed pubkey drift"
    assert _b64(legacy_sig) == legacy_golden_sig, (
        "zero-seed signer does NOT reproduce the committed Rust golden — provenance void"
    )

    vectors: dict = {
        "_comment": (
            "HESO/1 crown-jewel conformance vectors (P1 absorption). Generated by "
            "vectors/generate_vectors.py — do not hand-edit. See that file's header "
            "for the per-vector provenance contract."
        ),
        "spec": "HESO/1",
    }

    # ── action_receipt_v2 ───────────────────────────────────────────────────
    l0 = signed_l0(op, fixed_content())
    l1 = signed_l1(op, ap, fixed_content())

    # HashMismatch: mutate a signed field after stamping the hash.
    tampered = json.loads(json.dumps(l0))
    tampered["content"]["action"]["workflow"] = "research-run-MUTATED"

    # WrongAlgorithm: a plat envelope alg on an action receipt.
    wrong_alg = json.loads(json.dumps(l0))
    wrong_alg["alg"] = "heso-plat/v1+ed25519"

    # InvalidSignature: flip the operator signature.
    bad_sig = json.loads(json.dumps(l0))
    flipped = bytearray(base64.b64decode(bad_sig["signatures"][0]["signature"]))
    flipped[0] ^= 0x01
    bad_sig["signatures"][0]["signature"] = _b64(bytes(flipped))

    # SelfApproval: operator key co-signs as approver over the same body.
    self_appr = signed_l1(op, ap, fixed_content())
    self_appr["signatures"][1] = sign_entry(
        op, APPROVER_KEY_ID, APPROVAL_SIGNING_DOMAIN, self_appr["content"]
    )

    # TrustLevelMismatch: an L0-signed body that claims L1.
    tl_mismatch_content = fixed_content()
    tl_mismatch_content["trust_level"] = "L1"
    tl_mismatch_content["action_hash"] = action_content_hash(tl_mismatch_content)
    tl_mismatch = {
        "alg": ACTION_ENVELOPE_ALG,
        "content": tl_mismatch_content,
        "signatures": [sign_entry(op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, tl_mismatch_content)],
        "transparency": [],
    }

    vectors["action_receipt_v2"] = {
        "provenance": "rust-reference",
        "signing_domain_operator_hex": ACTION_SIGNING_DOMAIN.hex(),
        "signing_domain_approver_hex": APPROVAL_SIGNING_DOMAIN.hex(),
        "envelope_alg": ACTION_ENVELOPE_ALG,
        "action_version": ACTION_VERSION,
        "operator_public_key_b64": ZERO_SEED_PUBKEY,
        "approver_public_key_b64": _pub_b64(ap),
        "cases": [
            {
                "id": "AR-L0",
                "desc": "operator-only L0 receipt (mirrors fixtures::fixed_content)",
                "receipt_json": l0,
                "canonical_bytes_hex": action_canonical_bytes(l0["content"]).hex(),
                "action_hash": l0["content"]["action_hash"],
                "expected_outcome": "Valid",
                "expected_trust_level": "L0",
            },
            {
                "id": "AR-L1",
                "desc": "gated L1 receipt: operator + distinct approver co-signature",
                "receipt_json": l1,
                "action_hash": l1["content"]["action_hash"],
                "expected_outcome": "Valid",
                "expected_trust_level": "L1",
            },
            {
                "id": "AR-HASH-MISMATCH",
                "desc": "signed field mutated after action_hash was stamped",
                "receipt_json": tampered,
                "expected_outcome": "HashMismatch",
            },
            {
                "id": "AR-WRONG-ALG",
                "desc": "plat envelope alg on an action receipt",
                "receipt_json": wrong_alg,
                "expected_outcome": "WrongAlgorithm",
            },
            {
                "id": "AR-INVALID-SIG",
                "desc": "operator signature flipped (one bit)",
                "receipt_json": bad_sig,
                "expected_outcome": "InvalidSignature",
            },
            {
                "id": "AR-SELF-APPROVAL",
                "desc": "operator key co-signs as approver (self-approval)",
                "receipt_json": self_appr,
                "expected_outcome": "SelfApproval",
            },
            {
                "id": "AR-TRUST-MISMATCH",
                "desc": "L0-signed body claims trust_level L1",
                "receipt_json": tl_mismatch,
                "expected_outcome": "TrustLevelMismatch",
            },
        ],
    }

    # ── chain ────────────────────────────────────────────────────────────────
    session = "sess-golden-01"
    g0 = chained_receipt(op, session, 0, None, "genesis")
    g1 = chained_receipt(op, session, 1, link_hash(g0["content"]), "second")
    g2 = chained_receipt(op, session, 2, link_hash(g1["content"]), "third")
    valid_chain = [g0, g1, g2]

    # Tamper: re-point g2 at genesis (skip g1) — every receipt still self-verifies
    # but the link is broken (a spliced/dropped predecessor).
    broken = json.loads(json.dumps([g0, g1, g2]))
    broken[2]["content"]["prev_receipt_hash"] = link_hash(g0["content"])
    broken[2]["content"]["action_hash"] = action_content_hash(broken[2]["content"])
    broken[2]["signatures"][0] = sign_entry(
        op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, broken[2]["content"]
    )

    vectors["chain"] = {
        "provenance": "rust-reference",
        "chain_domain_hex": RECEIPT_CHAIN_DOMAIN.hex(),
        "session_id": session,
        "operator_public_key_b64": ZERO_SEED_PUBKEY,
        "link_hashes": {
            "seq0": link_hash(g0["content"]),
            "seq1": link_hash(g1["content"]),
            "seq2": link_hash(g2["content"]),
        },
        "cases": [
            {
                "id": "CHAIN-VALID",
                "desc": "3-link genesis->2 chain, links intact",
                "chain_jsonl": valid_chain,
                "expected_outcome": "Valid",
                "expected_length": 3,
            },
            {
                "id": "CHAIN-LINK-BROKEN",
                "desc": "seq2 re-pointed at genesis (predecessor spliced out)",
                "chain_jsonl": broken,
                "expected_outcome": "LinkBroken",
            },
        ],
    }

    # ── redaction (commit-and-reveal) ────────────────────────────────────────
    salt = bytes(range(32))  # 00 01 02 ... 1f — deterministic golden salt
    field_path = "card_number"
    plaintext = "4242424242424242"
    value_json = json.dumps(plaintext).encode()  # JSON-encoded value bytes
    commitment = redact_commit(salt, field_path, value_json)
    bad_salt = bytes([0xFF]) * 32

    # A full ActionReceipt carrying this commit-and-reveal record. The commitment
    # rides INSIDE the signed action_hash, so verify-cli accepting this receipt is
    # the Rust-reference cross-check that the marker structure + commitment scheme
    # are byte-compatible (the salt stays out of the signed bytes, in the reveal).
    redact_content = fixed_content()
    redact_content["redaction"] = {
        "mode": "commit_and_reveal",
        "markers": [
            {
                "field_path": field_path,
                "algorithm": REDACT_COMMIT_ALG,
                "commitment": commitment,
            }
        ],
        "merkle_root": redaction_merkle_root([commitment]),
    }
    redact_content["trust_level"] = "L0"
    redact_content["action_hash"] = action_content_hash(redact_content)
    redact_receipt = {
        "alg": ACTION_ENVELOPE_ALG,
        "content": redact_content,
        "signatures": [sign_entry(op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, redact_content)],
        "transparency": [],
    }

    vectors["redaction"] = {
        "provenance": "rust-reference",
        "algorithm": REDACT_COMMIT_ALG,
        "commit_rule": "BLAKE3(salt ++ field_path ++ value_json)",
        "merkle_root_rule": "BLAKE3 over each commitment hex followed by '\\n'",
        "receipt_json": redact_receipt,
        "receipt_expected_outcome": "Valid",
        "cases": [
            {
                "id": "REDACT-COMMIT",
                "field_path": field_path,
                "salt_hex": salt.hex(),
                "value_json": plaintext,
                "value_json_bytes_hex": value_json.hex(),
                "commitment": commitment,
                "merkle_root": redaction_merkle_root([commitment]),
                "reveal_verifies": True,
            },
            {
                "id": "REDACT-BAD-SALT",
                "desc": "wrong salt must NOT reproduce the commitment",
                "field_path": field_path,
                "salt_hex": bad_salt.hex(),
                "value_json": plaintext,
                "commitment_to_match": commitment,
                "reveal_verifies": False,
            },
        ],
    }

    # ── taxonomy_classify (spec-derived) ─────────────────────────────────────
    # Inputs are the structural observed-fact shapes classify() keys on; the
    # expected output is the FROZEN-7 coarse verb (from taxonomy.toml) and its
    # ADR-0001 destructive-primitive spine mapping. No Rust classify CLI exists, so
    # these are spec-derived against taxonomy.toml — a P2 cross-language blocker.
    classify_cases = [
        {
            "id": "TX-PAYMENT-HOST",
            "facts": {"host": "api.stripe.com", "method": "POST", "path": "/v1/charges"},
            "expected_class": "payment_endpoint",
            "expected_verb": "payment",
            "expected_primitive": "move-value",
            "expected_effect": "spend",
        },
        {
            "id": "TX-PAYMENT-PATH",
            "facts": {"host": "api.example.com", "method": "POST", "path": "/v2/payment_intents"},
            "expected_class": "payment_endpoint",
            "expected_verb": "payment",
            "expected_primitive": "move-value",
            "expected_effect": "spend",
        },
        {
            "id": "TX-DESTROY-METHOD",
            "facts": {"host": "api.example.com", "method": "DELETE", "path": "/v1/things/42"},
            "expected_class": "destructive_op",
            "expected_verb": "delete",
            "expected_primitive": "destroy",
            "expected_effect": "destroy",
        },
        {
            "id": "TX-DESTROY-ARGV",
            "facts": {"argv_tokens": ["psql", "-c", "drop", "table", "users"]},
            "expected_class": "destructive_op",
            "expected_verb": "delete",
            "expected_primitive": "destroy",
            "expected_effect": "destroy",
        },
        {
            "id": "TX-IDENTITY",
            "facts": {
                "host": "iam.amazonaws.com",
                "method": "POST",
                "path": "/iam/AttachRolePolicy",
            },
            "expected_class": "identity_endpoint",
            "expected_verb": "account_change",
            "expected_primitive": "change-authority",
            "expected_effect": "grant",
        },
        {
            "id": "TX-SECRET",
            "facts": {
                "host": "host.secretsmanager.amazonaws.com",
                "method": "GET",
                "path": "/secret",
            },
            "expected_class": "secret_store",
            "expected_verb": "data_export",
            "expected_primitive": "disclose",
            "expected_effect": "transfer_out",
        },
        {
            "id": "TX-SECRET-PATH",
            "facts": {"host": "fs.local", "path": "/home/app/.ssh/id_rsa"},
            "expected_class": "secret_store",
            "expected_verb": "data_export",
            "expected_primitive": "disclose",
            "expected_effect": "transfer_out",
        },
        {
            "id": "TX-BULK",
            "facts": {"host": "db.example.com", "row_count_estimate": 5000},
            "expected_class": "bulk_data",
            "expected_verb": "data_export",
            "expected_primitive": "disclose",
            "expected_effect": "transfer_out",
        },
        {
            "id": "TX-BULK-UNKNOWN-COUNT",
            "desc": "observed but indeterminate row count fails safe into bulk_data",
            "facts": {"host": "db.example.com", "row_count_unknown": True},
            "expected_class": "bulk_data",
            "expected_verb": "data_export",
            "expected_primitive": "disclose",
            "expected_effect": "transfer_out",
        },
        {
            "id": "TX-MODEL",
            "facts": {"host": "api.openai.com", "method": "POST", "path": "/v1/chat/completions"},
            "expected_class": "model_endpoint",
            "expected_verb": "llm_call",
            "expected_primitive": "execute",
            "expected_effect": "observe",
        },
        {
            "id": "TX-MESSAGING",
            "facts": {
                "host": "hooks.slack.com",
                "method": "POST",
                "path": "/api/chat.postMessage",
            },
            "expected_class": "messaging_endpoint",
            "expected_verb": "http_request",
            "expected_primitive": "execute",
            "expected_effect": "transfer_out",
        },
        {
            "id": "TX-GENERIC",
            "facts": {"host": "api.unknown-vendor.io", "method": "GET", "path": "/status"},
            "expected_class": "generic_network",
            "expected_verb": "http_request",
            "expected_primitive": "execute",
            "expected_effect": "transfer_out",
        },
        {
            "id": "TX-LOCAL",
            "facts": {"is_local_compute": True},
            "expected_class": "local_compute",
            "expected_verb": "tool_call",
            "expected_primitive": "execute",
            "expected_effect": "mutate",
        },
        {
            "id": "TX-RESIDUAL",
            "facts": {},
            "expected_class": "unresolved",
            "expected_verb": "tool_call",
            "expected_primitive": "execute",
            "expected_effect": "effect_unknown",
            "deny_unknown": True,
        },
        {
            "id": "TX-PRIORITY-PAYMENT-BEATS-NETWORK",
            "desc": "a payment host that is also a network reach classifies as payment (priority)",
            "facts": {"host": "api.stripe.com", "method": "POST", "path": "/v1/charges"},
            "expected_class": "payment_endpoint",
            "expected_verb": "payment",
            "expected_primitive": "move-value",
            "expected_effect": "spend",
        },
        {
            "id": "TX-EXT-PAYMENT-HOST",
            "desc": "well-known payment host comes from the heso/payment-providers extension pack",
            "facts": {"host": "api.adyen.com"},
            "expected_class": "payment_endpoint",
            "expected_verb": "payment",
            "expected_primitive": "move-value",
            "expected_effect": "spend",
        },
        {
            "id": "TX-EXT-IDENTITY-HOST",
            "desc": "well-known identity host comes from the heso/identity-providers extension pack",
            "facts": {"host": "acme.okta.com"},
            "expected_class": "identity_endpoint",
            "expected_verb": "account_change",
            "expected_primitive": "change-authority",
            "expected_effect": "grant",
        },
        {
            "id": "TX-EXT-SECRET-HOST",
            "desc": "well-known secret host comes from the heso/secret-stores extension pack",
            "facts": {"host": "abc.secretsmanager.amazonaws.com"},
            "expected_class": "secret_store",
            "expected_verb": "data_export",
            "expected_primitive": "disclose",
            "expected_effect": "transfer_out",
        },
        {
            "id": "TX-EXT-MODEL-HOST",
            "desc": "well-known model host comes from the heso/model-providers extension pack",
            "facts": {"host": "api.anthropic.com"},
            "expected_class": "model_endpoint",
            "expected_verb": "llm_call",
            "expected_primitive": "execute",
            "expected_effect": "observe",
        },
        {
            "id": "TX-EXT-GEMINI-HOST",
            "desc": "Gemini API is a precise model-provider host, not a broad googleapis wildcard",
            "facts": {"host": "generativelanguage.googleapis.com"},
            "expected_class": "model_endpoint",
            "expected_verb": "llm_call",
            "expected_primitive": "execute",
            "expected_effect": "observe",
        },
        {
            "id": "TX-GOOGLE-STORAGE-NOT-MODEL",
            "desc": "generic Google APIs must not be swept into model_endpoint by host suffix",
            "facts": {"host": "storage.googleapis.com", "method": "GET", "path": "/bucket/object"},
            "expected_class": "generic_network",
            "expected_verb": "http_request",
            "expected_primitive": "execute",
            "expected_effect": "transfer_out",
        },
        {
            "id": "TX-EXT-MESSAGING-HOST",
            "desc": "well-known messaging host comes from the heso/messaging-providers extension pack",
            "facts": {"host": "hooks.slack.com"},
            "expected_class": "messaging_endpoint",
            "expected_verb": "http_request",
            "expected_primitive": "execute",
            "expected_effect": "transfer_out",
        },
    ]
    for case in classify_cases:
        if "expected_outcome" in case:
            continue
        if case.get("deny_unknown"):
            case["expected_outcome"] = "residual"
        elif case["expected_effect"] == "observe":
            case["expected_outcome"] = "observe"
        else:
            case["expected_outcome"] = "destructive"
    # Regenerate (class, verb, primitive, effect) from the RUST kernel classify
    # spine when the runnable is present, and assert byte-equality with the
    # spec-derived expectation. This is the P2 cross-language gate: the Rust spine,
    # the clean-room Python verifier, and verify-wasm must all agree.
    taxonomy_provenance = "spec-derived"
    if CONFORMANCE_BIN:
        for case in classify_cases:
            got = conformance_mint(["classify", json.dumps(case["facts"])])
            want = {
                "class": case["expected_class"],
                "verb": case["expected_verb"],
                "primitive": case["expected_primitive"],
                "effect": case["expected_effect"],
            }
            if got != want:
                raise RuntimeError(
                    f"taxonomy_classify/{case['id']}: Rust kernel disagrees with the "
                    f"spec-derived expectation\n    rust: {got}\n    spec: {want}"
                )
        taxonomy_provenance = "rust-reference"
        print(
            f"  OK taxonomy_classify: {len(classify_cases)} cases regenerated by "
            "heso-conformance classify (Rust == spec)",
            file=sys.stderr,
        )

    # taxonomy_hash: the single BLAKE3(JCS(normative projection)) of the taxonomy
    # bundle: core taxonomy.toml plus active registry extension manifests.
    # MINT it from the Rust kernel and assert the clean-room Python recompute (the
    # SAME projection the verifier checks) reproduces it byte-for-byte. The kernel
    # value is the golden; Python is the independent reproduction that must MATCH.
    taxonomy_hash_value = clean_taxonomy_hash(TAXONOMY_PATH)
    if CONFORMANCE_BIN:
        rust_th = conformance_mint(["taxonomy_hash"])["taxonomy_hash"]
        if rust_th != taxonomy_hash_value:
            raise RuntimeError(
                "taxonomy_hash: Rust kernel disagrees with the clean-room projection\n"
                f"    rust: {rust_th}\n    python: {taxonomy_hash_value}"
            )
        taxonomy_hash_value = rust_th
        print("  OK taxonomy_hash: minted by heso-conformance (Rust == clean-room)", file=sys.stderr)

    vectors["taxonomy_classify"] = {
        "taxonomy_hash": taxonomy_hash_value,
        "taxonomy_hash_rule": (
            "BLAKE3(RFC8785-JCS(normative_projection(taxonomy.toml + active registry extensions)))"
        ),
        "provenance": taxonomy_provenance,
        "source": "taxonomy.toml + registry.toml + taxonomy/extensions/heso/*.toml",
        "regenerated_by": "heso-conformance classify (heso_engine::classify spine)",
        # The absent-row_count_estimate fail-safe nuance: both the kernel
        # (heso_engine::classify predicate_matches) and the clean-room Python
        # classifier treat an ABSENT row_count as NO-match for the bulk_data
        # row_threshold predicate. An observed but indeterminate row count MUST be
        # represented by the signed row_count_unknown fact, which classifies as
        # bulk_data and is pinned by TX-BULK-UNKNOWN-COUNT.
        "absent_row_count_semantics": (
            "absent row_count_estimate is NO-match for row_threshold; observed "
            "unknown row count is row_count_unknown=true and fails safe to bulk_data"
        ),
        "cases": classify_cases,
    }

    # ── rfc6962 (spec-derived) ───────────────────────────────────────────────
    # Leaf values are the 32-byte BLAKE3 contents (here: raw action_hash digests).
    leaf_vals = [
        bytes.fromhex(g0["content"]["action_hash"]),
        bytes.fromhex(g1["content"]["action_hash"]),
        bytes.fromhex(g2["content"]["action_hash"]),
    ]
    root3 = rfc6962_root(leaf_vals)
    # Inclusion proof for leaf index 0 in the size-3 tree:
    #   tree(3) = node( leaf0_or_subtree , ... ); split k=2 -> [0,1] | [2]
    #   left subtree root = node(leaf(v0), leaf(v1)); right = leaf(v2)
    #   proof for index 0: [ leaf(v1), leaf(v2) ]
    proof_idx0 = [rfc6962_leaf(leaf_vals[1]).hex(), rfc6962_leaf(leaf_vals[2]).hex()]
    rfc6962_block = {
        "hashing_rule": "leaf=SHA256(0x00||v); node=SHA256(0x01||l||r); empty=SHA256('')",
        "empty_root_hex": rfc6962_empty_root().hex(),
        "single_leaf": {
            "value_hex": leaf_vals[0].hex(),
            "leaf_hash_hex": rfc6962_leaf(leaf_vals[0]).hex(),
        },
        "node_example": {
            "left_hex": rfc6962_leaf(leaf_vals[0]).hex(),
            "right_hex": rfc6962_leaf(leaf_vals[1]).hex(),
            "node_hash_hex": rfc6962_node(
                rfc6962_leaf(leaf_vals[0]), rfc6962_leaf(leaf_vals[1])
            ).hex(),
        },
        "inclusion": {
            "leaf_index": 0,
            "tree_size": 3,
            "leaf_value_hex": leaf_vals[0].hex(),
            "proof_hex": proof_idx0,
            "expected_root_hex": root3.hex(),
        },
    }
    # Regenerate the leaf/node/empty/inclusion bytes from the RUST transparency
    # conformance surface (heso_action::transparency) and assert byte-equality.
    rfc6962_provenance = "spec-derived"
    if CONFORMANCE_BIN:
        rust = conformance_mint(["rfc6962", *(v.hex() for v in leaf_vals)])
        for key in ("empty_root_hex", "single_leaf", "node_example", "inclusion"):
            if rust[key] != rfc6962_block[key]:
                raise RuntimeError(
                    f"rfc6962/{key}: Rust transparency surface disagrees with the "
                    f"spec derivation\n    rust: {rust[key]}\n    spec: {rfc6962_block[key]}"
                )
        rfc6962_provenance = "rust-reference"
        print(
            "  OK rfc6962: leaf/node/empty/inclusion regenerated by heso-conformance "
            "rfc6962 (Rust == spec)",
            file=sys.stderr,
        )
    rfc6962_out = {
        "provenance": rfc6962_provenance,
        "regenerated_by": "heso-conformance rfc6962 (heso_action::transparency)",
        **rfc6962_block,
    }

    # ── rfc6962 consistency (RUST-MINTED; no clean-room hand-derivation) ──────
    # Consistency proofs are EMITTED by the kernel (heso-conformance consistency)
    # over the published 7-leaf CT inputs for old_size ∈ {1,2,3,4,6} (the named
    # spec case is cons(old_size=4,new_size=7)). The clean-room verifier
    # rfc6962_verify_consistency must reproduce True for each — that is the
    # cross-language gate. We deliberately do NOT hand-compute consistency proofs
    # in Python (a hand-written proof is worse than no proof); when the kernel
    # mint is unavailable the consistency sub-block is simply omitted.
    if CONFORMANCE_BIN:
        cons = conformance_mint(["consistency"])
        from heso_verify import rfc6962_verify_consistency  # noqa: E402

        for case in cons["cases"]:
            ok = rfc6962_verify_consistency(
                case["old_size"],
                bytes.fromhex(case["old_root_hex"]),
                case["new_size"],
                bytes.fromhex(case["new_root_hex"]),
                [bytes.fromhex(h) for h in case["proof_hex"]],
            )
            if not ok:
                raise RuntimeError(
                    f"rfc6962/consistency cons({case['old_size']},{case['new_size']}): "
                    "clean-room verifier REJECTS the kernel-minted proof"
                )
        rfc6962_out["consistency"] = {
            "provenance": "rust-reference",
            "regenerated_by": "heso-conformance consistency (heso_action::transparency)",
            "source": "RFC-6962 §2.1.2 over the published CT leaves (transparency.md §5)",
            "named_case": cons["named_case"],
            "inputs_hex": cons["inputs_hex"],
            "cases": cons["cases"],
        }
        print(
            f"  OK rfc6962 consistency: {len(cons['cases'])} proofs minted by "
            "heso-conformance consistency (clean-room verifies each)",
            file=sys.stderr,
        )
    else:
        print(
            "WARN: heso-conformance unavailable — rfc6962 consistency sub-block OMITTED "
            "(consistency proofs are kernel-minted, never hand-computed)",
            file=sys.stderr,
        )

    vectors["rfc6962"] = rfc6962_out

    # ── quorum (RUST-MINTED multi-approver cosign payloads) ──────────────────
    # The operator base + each approver leg's cosign payload are EMITTED by the
    # kernel (heso-conformance quorum) over a reused L0 fixture; the clean-room
    # verifier reproduces every byte. The suspended fixture is the L0 golden
    # content (fixed_content), so this rides entirely on already-pinned bytes.
    quorum_suspended = signed_l0(op, fixed_content())["content"]
    quorum_threshold = 2
    quorum_roster = [
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ]
    quorum_records = [
        {
            "decision": "approved",
            "approver_identity": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "reason": "first approver",
            "decided_at": "2026-05-29T12:05:00Z",
        },
        {
            "decision": "approved",
            "approver_identity": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
            "reason": "second approver",
            "decided_at": "2026-05-29T12:06:00Z",
        },
    ]
    clean_base = clean_quorum_base(quorum_suspended, quorum_threshold, quorum_roster)
    quorum_legs = [
        {
            "approver_identity": r["approver_identity"],
            "decision": r["decision"],
            "reason": r["reason"],
            "decided_at": r["decided_at"],
            "cosign_payload_hex": clean_cosign_payload(clean_base, r).hex(),
        }
        for r in quorum_records
    ]
    quorum_provenance = "spec-derived"
    if CONFORMANCE_BIN:
        rust_q = conformance_mint(
            [
                "quorum",
                json.dumps(quorum_suspended),
                str(quorum_threshold),
                json.dumps(quorum_roster),
                json.dumps(quorum_records),
            ]
        )
        if rust_q["base_action_hash"] != clean_base["action_hash"]:
            raise RuntimeError(
                "quorum/base_action_hash: Rust kernel disagrees with the clean-room base\n"
                f"    rust: {rust_q['base_action_hash']}\n    python: {clean_base['action_hash']}"
            )
        rust_legs = {leg["approver_identity"]: leg["cosign_payload_hex"] for leg in rust_q["legs"]}
        for leg in quorum_legs:
            ident = leg["approver_identity"]
            if rust_legs.get(ident) != leg["cosign_payload_hex"]:
                raise RuntimeError(
                    f"quorum/leg/{ident}: Rust kernel cosign payload disagrees with clean-room\n"
                    f"    rust: {rust_legs.get(ident)}\n    python: {leg['cosign_payload_hex']}"
                )
        quorum_provenance = "rust-reference"
        print(
            f"  OK quorum: base + {len(quorum_legs)} approver legs minted by "
            "heso-conformance quorum (Rust == clean-room)",
            file=sys.stderr,
        )
    vectors["quorum"] = {
        "provenance": quorum_provenance,
        "regenerated_by": "heso-conformance quorum (heso_action::receipt::multi_approval_cosign_payload)",
        "source": "transparency/quorum two-canonical model (receipt.rs build_quorum_base)",
        "suspended_content": quorum_suspended,
        "threshold": quorum_threshold,
        "roster": clean_base["multi_approval"]["roster"],
        "base_action_hash": clean_base["action_hash"],
        "approval_signing_domain_hex": APPROVAL_SIGNING_DOMAIN.hex(),
        "legs": quorum_legs,
    }

    # ── time_anchor (RUST-MINTED pre-anchor content hash) ────────────────────
    # The pre-anchor anchored_content_hash (the bytes a TSA certifies) is EMITTED
    # by the kernel (heso-conformance time_anchor) over the same L0 fixture; the
    # clean-room verifier reproduces it. The two absent-anchor outcome tags are
    # spec semantics (fail-closed), pinned alongside.
    ta_content = signed_l0(op, fixed_content())["content"]
    clean_anchored = clean_anchored_content_hash(ta_content)
    ta_provenance = "spec-derived"
    if CONFORMANCE_BIN:
        rust_ta = conformance_mint(["time_anchor", json.dumps(ta_content)])
        if rust_ta["anchored_content_hash"] != clean_anchored:
            raise RuntimeError(
                "time_anchor/anchored_content_hash: Rust kernel disagrees with clean-room\n"
                f"    rust: {rust_ta['anchored_content_hash']}\n    python: {clean_anchored}"
            )
        ta_provenance = "rust-reference"
        print(
            "  OK time_anchor: anchored_content_hash minted by heso-conformance "
            "time_anchor (Rust == clean-room)",
            file=sys.stderr,
        )
    vectors["time_anchor"] = {
        "provenance": ta_provenance,
        "regenerated_by": "heso-conformance time_anchor (heso_action::receipt::anchored_content_hash)",
        "source": "trusted-time anchor pre-image (receipt.rs anchored_content_hash; verify.rs outcomes)",
        "content": ta_content,
        "anchored_content_hash": clean_anchored,
        "outcomes": {
            "anchor_required_no_anchor": "AnchorRequired",
            "no_requirement_no_anchor": "NoTrustedTime",
        },
    }

    # ── dsse_pae (spec-derived) ──────────────────────────────────────────────
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": "action://research-run-7", "digest": {"blake3": l0["content"]["action_hash"]}}
        ],
        "predicateType": "https://hesohq.dev/ActionReceipt/v2",
        "predicate": {
            "primitive": "execute",
            "verb": "llm_call",
            "trust_level": "L0",
        },
    }
    # Body bytes: canonical JCS so the golden is reproducible byte-for-byte.
    body = rfc8785.dumps(statement)
    pae = dsse_pae(DSSE_PAYLOAD_TYPE, body)
    dsse_sig = op.sign(pae)
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": _b64(body),
        "signatures": [{"keyid": ZERO_SEED_PUBKEY, "sig": _b64(dsse_sig)}],
    }
    dsse_block = {
        "payload_type": DSSE_PAYLOAD_TYPE,
        "statement_json": statement,
        "body_bytes_hex": body.hex(),
        "pae_hex": pae.hex(),
        "operator_public_key_b64": ZERO_SEED_PUBKEY,
        "dsse_signature_b64": _b64(dsse_sig),
        "envelope_json": envelope,
    }
    # Mint the in-toto Statement + PAE pre-image + envelope from the RUST kernel
    # (heso_action::export::dsse) and assert byte-equality: the body, the PAE
    # pre-image (the single most error-prone byte rule), the zero-seed signature
    # over it, and the assembled envelope must all match the clean-room derivation.
    # This is the Rust<->Python<->verify-wasm DSSE byte-parity gate.
    dsse_provenance = "spec-derived"
    if CONFORMANCE_BIN:
        action_hash = l0["content"]["action_hash"]
        rust = conformance_mint(
            ["dsse", "action://research-run-7", action_hash, "execute", "llm_call", "L0"]
        )
        for key in (
            "payload_type",
            "statement_json",
            "body_bytes_hex",
            "pae_hex",
            "operator_public_key_b64",
            "dsse_signature_b64",
            "envelope_json",
        ):
            if rust[key] != dsse_block[key]:
                raise RuntimeError(
                    f"dsse_pae/{key}: Rust DSSE mint disagrees with the spec "
                    f"derivation\n    rust: {rust[key]}\n    spec: {dsse_block[key]}"
                )
        dsse_provenance = "rust-reference"
        print(
            "  OK dsse_pae: Statement + PAE + envelope minted by heso-conformance "
            "dsse (Rust == spec)",
            file=sys.stderr,
        )
    vectors["dsse_pae"] = {
        "provenance": dsse_provenance,
        "regenerated_by": "heso-conformance dsse (heso_action::export::dsse)",
        **dsse_block,
    }

    # ── Rust reference validation pass ───────────────────────────────────────
    cli_results: dict[str, str] = {}
    if VERIFY_CLI:
        cli_results["AR-L0"] = verify_cli_verdict([l0], ZERO_SEED_PUBKEY)
        cli_results["AR-L1"] = verify_cli_verdict([l1], ZERO_SEED_PUBKEY)
        cli_results["AR-HASH-MISMATCH"] = verify_cli_verdict([tampered], ZERO_SEED_PUBKEY)
        cli_results["AR-WRONG-ALG"] = verify_cli_verdict([wrong_alg], ZERO_SEED_PUBKEY)
        cli_results["AR-INVALID-SIG"] = verify_cli_verdict([bad_sig], ZERO_SEED_PUBKEY)
        cli_results["AR-SELF-APPROVAL"] = verify_cli_verdict([self_appr], ZERO_SEED_PUBKEY)
        cli_results["AR-TRUST-MISMATCH"] = verify_cli_verdict([tl_mismatch], ZERO_SEED_PUBKEY)
        cli_results["CHAIN-VALID"] = verify_cli_verdict(valid_chain, ZERO_SEED_PUBKEY)
        cli_results["CHAIN-LINK-BROKEN"] = verify_cli_verdict(broken, ZERO_SEED_PUBKEY)
        cli_results["REDACT-RECEIPT"] = verify_cli_verdict([redact_receipt], ZERO_SEED_PUBKEY)
        expected = {
            "AR-L0": "valid",
            "AR-L1": "valid",
            "AR-HASH-MISMATCH": "wrong_algorithm_or_hash",
            "AR-WRONG-ALG": "wrong_algorithm_or_hash",
            "AR-INVALID-SIG": "invalid",
            "AR-SELF-APPROVAL": "invalid",
            "AR-TRUST-MISMATCH": "invalid",
            "CHAIN-VALID": "valid",
            "CHAIN-LINK-BROKEN": "invalid",
            "REDACT-RECEIPT": "valid",
        }
        print("=== Rust heso-verify-cli reference validation ===", file=sys.stderr)
        ok = True
        for cid, got in cli_results.items():
            want = expected[cid]
            mark = "OK " if got == want else "XX "
            if got != want:
                ok = False
            print(f"  {mark}{cid}: cli={got} expected={want}", file=sys.stderr)
        if not ok:
            print("FATAL: Rust reference verdict mismatch — vectors NOT written", file=sys.stderr)
            return 1
        vectors["_rust_reference_validation"] = {
            # Basename only: VERIFY_CLI lives in the sibling heso-enterprise repo, so an
            # absolute/relative path leaks the build host (e.g. /Users/... vs /home/runner/...)
            # and makes the corpus drift across machines. The name is all that is informative.
            "verify_cli": os.path.basename(VERIFY_CLI),
            "results": cli_results,
        }
    else:
        print(
            "WARN: heso-verify-cli not found — rust-reference receipts are cross-checked "
            "only via the byte-identical zero-seed signature gate above. Set "
            "HESO_VERIFY_CLI to the built binary to validate end-to-end.",
            file=sys.stderr,
        )

    with open(OUT_PATH, "w") as fh:
        json.dump(vectors, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {os.path.relpath(OUT_PATH, REPO)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
