"""Generate the commitment WIRE-PAYLOAD conformance vectors (P3, ADR-0003).

Writes ``vectors/heso-1.0-wire-vectors.json`` — the goldens the commitment-store
pivot (receipt-mirror -> commitment-store) adds for the SDK Transport boundary:

  - ``commitment_wire``  — the FULL `ActionReceipt` -> `commitment + indexes`
                           transform. Given a known receipt + taxonomy version,
                           the EXACT commitment payload the SDK Transport must
                           emit on the wire (POST /v1/commitments). Raw content
                           (action.fields, prompts, tool args, response bodies)
                           is STRUCTURALLY ABSENT from the payload.
  - ``primitive_index``  — the queryable metadata shape the commitment is indexed
                           by server-side: the destructive primitive (5-spine),
                           coarse verb, taxonomy_hash, resource_class, decision,
                           trust_level, chain head. The crown-jewel query axis.
  - ``redact_before_sign`` — the redact-before-sign boundary: a receipt carrying
                           a sensitive field via commit-and-reveal, projected to
                           the wire commitment. Proves the raw value is NOT on the
                           wire (only its salted-BLAKE3 commitment + merkle root),
                           AND that the wire commitment carries no `action.fields`.

PROVENANCE (per vector, tagged in the ``provenance`` field):
  - ``rust-reference``  — the underlying receipt's `action_hash` (the BLAKE3
                          fingerprint the commitment IS) and chain head bytes are
                          minted AND validated by the kept Rust reference: the
                          zero-seed signer reproduces the committed legacy Rust
                          golden BYTE-FOR-BYTE (hard provenance gate), and every
                          source receipt is run end-to-end through the Rust
                          ``heso-verify-cli`` (it must return the expected verdict)
                          before the commitment is projected from it.
  - ``spec-derived``    — the FULL-receipt -> commitment+indexes PROJECTION itself
                          (which receipt fields cross the wire and which are
                          dropped) is a NEW spec surface: ``heso-conformance`` has
                          no ``commitment`` mint subcommand yet. The projection is
                          derived from commitment-store.md §3.1/§4 + ADR-0003 using
                          the SAME primitives (rfc8785/blake3) the kernel uses, and
                          is a P3 cross-language-gate blocker: a Rust runnable must
                          regenerate the projection and the gate must assert
                          byte-equality (mirrors how dsse_pae/rfc6962/taxonomy were
                          P2 blockers before their Rust runnable landed).

The chain head, action_hash, taxonomy_hash, and the redaction commitment are all
computed with the EXACT kernel primitives (mirrored from generate_vectors.py):
  - action_hash   = BLAKE3(JCS(content \\ action_hash))         [receipt.rs]
  - chain_head    = BLAKE3(domain || len-prefixed session/seq/action_hash) [chain.rs]
  - commitment    = BLAKE3(salt ++ field_path ++ value_json)    [redact.rs]
  - signer_fpr    = BLAKE3(raw ed25519 public key bytes)        [commitment-store §3.1]
  - taxonomy_hash = BLAKE3(JCS(taxonomy bundle projection))     [taxonomy.md]

The Rust verify-cli path runs when ``HESO_VERIFY_CLI`` (or the sibling enterprise
target dir) points at the built binary; without it the source receipts are still
cross-checked against the committed legacy golden signature gate and flagged.
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

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(REPO, "vectors", "heso-1.0-wire-vectors.json")
TAXONOMY_PATH = os.path.join(REPO, "taxonomy.toml")

sys.path.insert(0, os.path.join(REPO, "verifier"))
from heso_verify import taxonomy_hash as clean_taxonomy_hash  # noqa: E402

# ── Frozen constants (mirrored from heso-action/src/domain.rs) ──────────────
ACTION_SIGNING_DOMAIN = b"heso-action/v1\x00"
RECEIPT_CHAIN_DOMAIN = b"heso-rcpt-chain/v1\x00"
ACTION_ENVELOPE_ALG = "heso-action/v2+ed25519"
ACTION_VERSION = "heso-action/2.0"
REDACT_COMMIT_ALG = "salted-blake3/v1"
OPERATOR_KEY_ID = "operator"

# The all-zero Ed25519 seed pins the canonical golden identity across the whole
# HESO project (same seed as generate_vectors.py).
ZERO_SEED = bytes(32)
ZERO_SEED_PUBKEY = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="

# The wire payload version (the versioned outbox protocol from ADR-0003 §4).
COMMITMENT_WIRE_VERSION = "heso-commitment/v1"
COMMITMENT_ENVELOPE_KIND = "dsse"  # in-toto Statement + DSSE (ADR-0009)

# The all-zero-seed operator's commitment fingerprint = blake3(raw pubkey), 64-hex.
# NOT the heso:-prefixed Grade-0 signer_fingerprint. Pinned in heso-action
# ``commitment::tests::ZERO_SEED_COMMITMENT_FPR``.
ZERO_SEED_COMMITMENT_FPR = "51f1365add907c3dcaead8fae90cfe55902638248377b4dd1db501b11554ac46"

# The standalone L0 receipt golden the commitment seam MUST NOT MOVE (CORE-WIRE
# §0.1, VERIFY-GAP #3). action_hash + operator sig of the zero-seed fixed_content.
STANDALONE_L0_GOLDEN_ACTION_HASH = (
    "988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d"
)
STANDALONE_L0_GOLDEN_OPERATOR_SIG = (
    "ujGbJO2VR2PpaguiG3NegMWAyQLWJlgAVxuKnwaeV8KsMbtT4K/f8lGhLrNI3NSxbIXQnwZGCS1b4BtXnRMQAQ=="
)

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _pub_b64(sk: Ed25519PrivateKey) -> str:
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _b64(raw)


def _pub_raw(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


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


# ── Chain head (mirror chain.rs::link_input / link_hash) ────────────────────
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


# ── Redaction commit (mirror redact.rs) ─────────────────────────────────────
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


def signer_fpr(sk: Ed25519PrivateKey) -> str:
    """blake3(signer pubkey) — the commitment-store signer fingerprint (§3.1)."""
    return blake3(_pub_raw(sk)).hexdigest()


def taxonomy_hash() -> str:
    return clean_taxonomy_hash(TAXONOMY_PATH)


# ── The FULL receipt -> commitment + indexes PROJECTION (ADR-0003 §4) ───────
# The crux of P3: which receipt fields cross the customer/cloud boundary, and
# which (the raw content) NEVER do. The wire payload is exactly the columns of the
# `commitment` table in commitment-store.md §3.1 — nothing more.
WIRE_KEYS = (
    "wire_version",
    "action_hash",  # the BLAKE3 fingerprint == the commitment
    "chain_prev",
    "chain_head",
    "session_id",
    "seq",
    "primitive",
    "coarse_verb",
    "taxonomy_hash",
    "resource_class",
    "trust_level",
    "decision",
    "occurred_at",
    "signer_fpr",
    "signature",
    "envelope_kind",
)
# Fields that MUST NOT appear anywhere in the wire payload (raw content stays in
# the customer VPC). Asserted structurally below.
FORBIDDEN_WIRE_SUBSTRINGS = (
    "prompt",
    "summarize the filing",  # the raw prompt value
    "gpt-4o",  # the raw model value
    "4242424242424242",  # the raw redacted card number
    "fields",
    "action_version",
    "approver_decision",
)


def project_to_wire(
    receipt: dict,
    *,
    sk: Ed25519PrivateKey,
    primitive: str,
    coarse_verb: str,
    resource_class: str,
    decision: str,
) -> dict:
    """FULL ActionReceipt -> commitment+indexes. The ONLY transform the Transport
    runs. It reads the signed envelope and the kernel-derived chain head; it COPIES
    NO raw `content.action.fields`. The signature carried on the wire is the
    operator's detached Ed25519 signature already minted inside the receipt."""
    content = receipt["content"]
    chain_head = link_hash(content)
    wire = {
        "wire_version": COMMITMENT_WIRE_VERSION,
        "action_hash": content["action_hash"],
        "chain_prev": content.get("prev_receipt_hash"),
        "chain_head": chain_head,
        "session_id": content.get("session_id"),
        "seq": content.get("seq"),
        "primitive": primitive,
        "coarse_verb": coarse_verb,
        "taxonomy_hash": taxonomy_hash(),
        "resource_class": resource_class,
        "trust_level": content["trust_level"],
        "decision": decision,
        "occurred_at": content["captured_at"],
        "signer_fpr": signer_fpr(sk),
        "signature": receipt["signatures"][0]["signature"],
        "envelope_kind": COMMITMENT_ENVELOPE_KIND,
    }
    assert set(wire.keys()) == set(WIRE_KEYS), "wire payload key drift vs §3.1 schema"
    return wire


def assert_no_raw_content(wire: dict, label: str) -> None:
    """The structural redact-before-sign guarantee: serialize the wire payload and
    prove no raw-content substring survives the projection."""
    blob = json.dumps(wire, ensure_ascii=False)
    for needle in FORBIDDEN_WIRE_SUBSTRINGS:
        assert needle not in blob, f"{label}: raw content '{needle}' leaked onto the wire"


# ── Golden ActionContent body (mirror heso-action fixtures::fixed_content) ──
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


# ── Rust reference cross-check ──────────────────────────────────────────────
def _find_bin(env_var: str, name: str) -> str | None:
    p = os.environ.get(env_var)
    if p and os.path.exists(p):
        return p
    found = shutil.which(name)
    if found:
        return found
    candidate = os.path.abspath(
        os.path.join(REPO, "..", "heso-enterprise", "target", "debug", name)
    )
    return candidate if os.path.exists(candidate) else None


VERIFY_CLI = _find_bin("HESO_VERIFY_CLI", "heso-verify-cli")
# The kernel MINT runnable — emits the commitment-envelope + chained-receipt
# goldens straight from the Rust producer seam (NEVER hand-computed). These are
# success-path artifacts (NOT conformance-safe), so they must come from the kernel
# (CORE-WIRE design §0.1, VERIFY-GAPS #2/#3).
CONFORMANCE_BIN = _find_bin("HESO_CONFORMANCE_BIN", "heso-conformance")


def _conformance(*args: str) -> dict:
    """Invoke the kernel ``heso-conformance`` mint runnable and parse its one JSON
    line. FATAL-aborts (the generator refuses to write) if the binary is missing or
    errors — the commitment/chained goldens are KERNEL-EMITTED, never hand-derived,
    so there is no Python fallback."""
    if not CONFORMANCE_BIN:
        sys.exit(
            "FATAL: heso-conformance binary not found — the commitment_envelope and "
            "chained_receipt goldens are KERNEL-EMITTED (CORE-WIRE §0.1). Build it "
            "(cargo build -p heso-fixture-signer --bin heso-conformance) and/or set "
            "HESO_CONFORMANCE_BIN."
        )
    out = subprocess.run([CONFORMANCE_BIN, *args], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"FATAL: heso-conformance {args[0]} failed:\n{out.stderr.strip()}")
    return json.loads(out.stdout)


def fixed_content_with_ert() -> dict:
    """The ERT-PRESENT golden body — mirrors heso-action
    ``fixtures::fixed_content_with_ert`` (a JPMorgan wire payment, classified by
    host, carrying a signed ERT + the fine domain/action labels). Byte-identical to
    the body the kernel golden test pins, so the kernel-minted envelope reproduces
    ``ERT_PRESENT_*``."""
    content = fixed_content()
    content["action"] = {
        "verb": "payment",
        "domain": "payment",
        "action": "authorize_payment",
        "tool_name": "jpmorgan.payments.wire.initiate",
        "target_host": "api.payments.jpmorgan.com",
        "workflow": "research-run-7",
        "account": "acct_acme",
        "fields": {"prompt": "summarize the filing", "model": "gpt-4o"},
        "result_hash": "a" * 64,
        "ert": {
            "observed_facts": {"host": "api.payments.jpmorgan.com", "method": "POST"},
            "resource_class": "payment_endpoint",
            "effect": "spend",
            "egress": "crosses_trust_boundary",
            "observability": "wire",
            "taxonomy_hash": taxonomy_hash(),
        },
    }
    return content


def verify_cli_verdict(receipts: list[dict], pubkey: str) -> str | None:
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

    # Hard provenance gate: the all-zero-seed signer MUST reproduce the committed
    # legacy Rust golden signature byte-for-byte, or every "rust-reference" claim
    # below is void (identical gate to generate_vectors.py).
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
            "HESO/1 commitment WIRE-PAYLOAD conformance vectors (P3, ADR-0003). "
            "Generated by vectors/generate_wire_vectors.py — do not hand-edit. "
            "Pins the FULL receipt -> commitment+indexes Transport transform: the "
            "EXACT payload that crosses the customer/cloud boundary on POST "
            "/v1/commitments, and the structural guarantee that raw content "
            "(prompts, tool args, response bodies, action.fields) NEVER does. The "
            "underlying receipt fingerprints are rust-reference (validated by "
            "heso-verify-cli); the FULL-receipt->commitment PROJECTION is a NEW "
            "spec surface (no Rust `commitment` mint subcommand yet) and is "
            "spec-derived — a P3 cross-language-gate blocker. NOTE on the recorder "
            "vs gate boundary (ADR-0004/0015): the RECORDER never blocks; this wire "
            "payload is emitted by the injected Transport (sdk-recorder-and-gate.md "
            "§5). The GATE is the only blocking surface and fails closed by default "
            "(deny/approval/any thrown error -> synthetic 403); fail-closed is a "
            "BEHAVIORAL property of the gate, not a wire-payload shape, so it is "
            "asserted in the SDK gate tests, not minted as a byte-golden here."
        ),
        "spec": "HESO/1",
        "wire_version": COMMITMENT_WIRE_VERSION,
    }

    # Source receipts (rust-reference: minted + validated by the kept kernel) ──
    # A receipt in a chain so chain_prev / chain_head are exercised on the
    # wire (mirrors the chain primitive in generate_vectors.py).
    g0_content = fixed_content()
    g0_content["action"] = dict(g0_content["action"])
    g0_content["action"]["workflow"] = "session-sess-wire-01-step-0-genesis"
    g0_content["session_id"] = "sess-wire-01"
    g0_content["seq"] = 0
    g0_content["trust_level"] = "L0"
    g0_content["action_hash"] = action_content_hash(g0_content)
    g0 = {
        "alg": ACTION_ENVELOPE_ALG,
        "content": g0_content,
        "signatures": [sign_entry(op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, g0_content)],
        "transparency": [],
    }

    g1_content = fixed_content()
    g1_content["action"] = dict(g1_content["action"])
    g1_content["action"]["workflow"] = "session-sess-wire-01-step-1-second"
    g1_content["session_id"] = "sess-wire-01"
    g1_content["seq"] = 1
    g1_content["prev_receipt_hash"] = link_hash(g0_content)
    g1_content["trust_level"] = "L0"
    g1_content["action_hash"] = action_content_hash(g1_content)
    g1 = {
        "alg": ACTION_ENVELOPE_ALG,
        "content": g1_content,
        "signatures": [sign_entry(op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, g1_content)],
        "transparency": [],
    }

    # ── commitment_wire ──────────────────────────────────────────────────────
    # Case 1: a genesis llm_call commitment (execute / model_endpoint / allow).
    wire_genesis = project_to_wire(
        g0,
        sk=op,
        primitive="execute",
        coarse_verb="llm_call",
        resource_class="model_endpoint",
        decision="allow",
    )
    assert_no_raw_content(wire_genesis, "CW-GENESIS")

    # Case 2: the chained successor — chain_prev is set, chain_head advances.
    wire_chained = project_to_wire(
        g1,
        sk=op,
        primitive="execute",
        coarse_verb="llm_call",
        resource_class="model_endpoint",
        decision="allow",
    )
    assert_no_raw_content(wire_chained, "CW-CHAINED")
    assert wire_chained["chain_prev"] == wire_genesis["chain_head"], "chain link must thread"

    # Case 3: a BLOCKED move-value commitment (the destructive-primitive index,
    # decision=block path). The receipt is still signed (the gate witnesses the
    # attempt) but decision=block.
    block_content = fixed_content()
    block_content["action"] = {
        "verb": "payment",
        "tool_name": "stripe.charges.create",
        "target_host": "api.stripe.com",
        "workflow": "payout-run-9",
        "account": "acct_acme",
        "fields": {"amount": 500000, "currency": "usd", "destination": "acct_payee"},
        "result_hash": "b" * 64,
    }
    block_content["policy"] = {
        "rule_id": "deny-large-payout",
        "rule_display": "deny payment over desk limit",
        "matched_conditions": [{"field": "verb", "op": "eq", "value": "payment"}],
        "decision_path": "block",
    }
    block_content["session_id"] = "sess-wire-02"
    block_content["seq"] = 0
    block_content["trust_level"] = "L0"
    block_content["action_hash"] = action_content_hash(block_content)
    block_receipt = {
        "alg": ACTION_ENVELOPE_ALG,
        "content": block_content,
        "signatures": [sign_entry(op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, block_content)],
        "transparency": [],
    }
    wire_block = project_to_wire(
        block_receipt,
        sk=op,
        primitive="move-value",
        coarse_verb="payment",
        resource_class="payment_endpoint",
        decision="block",
    )
    # the payment-specific raw fields must also be absent from the wire
    for needle in ("acct_payee", "500000", "amount", "currency"):
        assert needle not in json.dumps(wire_block), f"CW-BLOCK: raw '{needle}' leaked"
    assert_no_raw_content(wire_block, "CW-BLOCK")

    vectors["commitment_wire"] = {
        "provenance": "spec-derived",
        "regenerated_by": "DEFERRED — no `heso-conformance commitment` subcommand yet (P3 blocker)",
        "source": "commitment-store.md §3.1/§4 + ADR-0003 + ADR-0004 (recorder Transport)",
        "wire_endpoint": "POST /v1/commitments",
        "wire_version": COMMITMENT_WIRE_VERSION,
        "envelope_kind": COMMITMENT_ENVELOPE_KIND,
        "taxonomy_hash": taxonomy_hash(),
        "operator_public_key_b64": ZERO_SEED_PUBKEY,
        "signer_fpr": signer_fpr(op),
        "chain_domain_hex": RECEIPT_CHAIN_DOMAIN.hex(),
        "wire_keys": list(WIRE_KEYS),
        "projection_rule": (
            "Transport reads the signed ActionReceipt and the kernel chain head; it "
            "copies ONLY the §3.1 commitment columns. content.action.fields, "
            "content.action.account/tool_name/target_host, action_version, policy "
            "internals, and approver_decision NEVER cross the wire."
        ),
        "forbidden_on_wire": list(FORBIDDEN_WIRE_SUBSTRINGS),
        "cases": [
            {
                "id": "CW-GENESIS",
                "desc": "FULL llm_call receipt -> genesis commitment (execute / allow)",
                "source_receipt_json": g0,
                "source_action_hash": g0_content["action_hash"],
                "wire_payload": wire_genesis,
                "raw_content_on_wire": False,
                "source_receipt_expected_outcome": "Valid",
            },
            {
                "id": "CW-CHAINED",
                "desc": "chained successor: chain_prev == predecessor chain_head",
                "source_receipt_json": g1,
                "source_action_hash": g1_content["action_hash"],
                "wire_payload": wire_chained,
                "raw_content_on_wire": False,
                "source_receipt_expected_outcome": "Valid",
            },
            {
                "id": "CW-BLOCK",
                "desc": "blocked move-value: decision=block, witnessed but not forwarded",
                "source_receipt_json": block_receipt,
                "source_action_hash": block_content["action_hash"],
                "wire_payload": wire_block,
                "raw_content_on_wire": False,
                "source_receipt_expected_outcome": "Valid",
            },
        ],
    }

    # ── primitive_index ──────────────────────────────────────────────────────
    # The queryable metadata shape, per primitive. These are the index columns the
    # commitment store filters by ("show me every move-value last week"). One row
    # per destructive-primitive spine value, projected from a representative
    # receipt, asserting the (primitive, coarse_verb, resource_class) tuple the
    # server indexes on — keyed to the taxonomy_classify goldens in
    # heso-1.0-crown-vectors.json.
    index_cases = [
        {
            "id": "IDX-MOVE-VALUE",
            "primitive": "move-value",
            "coarse_verb": "payment",
            "resource_class": "payment_endpoint",
            "decision": "block",
            "desc": "spend axis — Stripe charge, blocked over desk limit",
        },
        {
            "id": "IDX-DESTROY",
            "primitive": "destroy",
            "coarse_verb": "delete",
            "resource_class": "destructive_op",
            "decision": "allow",
            "desc": "destroy axis — resource deletion",
        },
        {
            "id": "IDX-CHANGE-AUTHORITY",
            "primitive": "change-authority",
            "coarse_verb": "account_change",
            "resource_class": "identity_endpoint",
            "decision": "suspended",
            "desc": "grant axis — IAM attach, suspended pending approval",
        },
        {
            "id": "IDX-DISCLOSE",
            "primitive": "disclose",
            "coarse_verb": "data_export",
            "resource_class": "secret_store",
            "decision": "allow",
            "desc": "transfer-out axis — secret read",
        },
        {
            "id": "IDX-EXECUTE",
            "primitive": "execute",
            "coarse_verb": "llm_call",
            "resource_class": "model_endpoint",
            "decision": "allow",
            "desc": "execute axis — llm call",
        },
    ]
    vectors["primitive_index"] = {
        "provenance": "spec-derived",
        "source": "commitment-store.md §3.1 (primitive_enum) + taxonomy_classify goldens",
        "primitive_enum": ["move-value", "destroy", "change-authority", "disclose", "execute"],
        "decision_enum": ["allow", "block", "suspended"],
        "index_columns": [
            "organisation_id",
            "primitive",
            "coarse_verb",
            "taxonomy_hash",
            "resource_class",
            "trust_level",
            "decision",
            "occurred_at",
            "chain_head",
            "signer_fpr",
        ],
        "taxonomy_hash": taxonomy_hash(),
        "note": (
            "primitive_enum here uses the hyphenated spine spelling (move-value, "
            "change-authority) matching taxonomy_classify in heso-1.0-crown-vectors.json "
            "and ADR-0001; the Postgres `primitive_enum` in commitment-store.md §3.1 "
            "uses the underscore form (move_value, change_authority) — same five values, "
            "the SQL identifier just can't contain a hyphen. The wire carries the "
            "hyphenated spine token; the DB enum is its 1:1 underscore mapping."
        ),
        "cases": index_cases,
    }

    # ── redact_before_sign ───────────────────────────────────────────────────
    # The boundary: a sensitive field is committed (salted-BLAKE3) BEFORE signing,
    # so the raw value rides nowhere — not in the signed receipt body, and (by
    # projection) not on the wire. The wire commitment carries the merkle_root of
    # the redaction markers, never the value.
    salt = bytes(range(32))  # 00 01 ... 1f — deterministic golden salt
    field_path = "card_number"
    plaintext = "4242424242424242"
    value_json = json.dumps(plaintext).encode()
    redaction_commitment = redact_commit(salt, field_path, value_json)
    bad_salt = bytes([0xFF]) * 32
    merkle_root = redaction_merkle_root([redaction_commitment])

    redact_content = fixed_content()
    redact_content["redaction"] = {
        "mode": "commit_and_reveal",
        "markers": [
            {
                "field_path": field_path,
                "algorithm": REDACT_COMMIT_ALG,
                "commitment": redaction_commitment,
            }
        ],
        "merkle_root": merkle_root,
    }
    redact_content["session_id"] = "sess-wire-03"
    redact_content["seq"] = 0
    redact_content["trust_level"] = "L0"
    redact_content["action_hash"] = action_content_hash(redact_content)
    redact_receipt = {
        "alg": ACTION_ENVELOPE_ALG,
        "content": redact_content,
        "signatures": [sign_entry(op, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, redact_content)],
        "transparency": [],
    }

    # The wire commitment for the redacted receipt: carries the redaction merkle
    # root (so a relying party can later verify a reveal) but NOT the value.
    wire_redacted = project_to_wire(
        redact_receipt,
        sk=op,
        primitive="execute",
        coarse_verb="llm_call",
        resource_class="model_endpoint",
        decision="allow",
    )
    # add the redaction merkle root onto the wire commitment (the one redaction
    # field that DOES cross — it's a hash, never the value).
    wire_redacted_with_merkle = dict(wire_redacted)
    wire_redacted_with_merkle["redaction_merkle_root"] = merkle_root
    assert_no_raw_content(wire_redacted_with_merkle, "REDACT-WIRE")
    assert plaintext not in json.dumps(wire_redacted_with_merkle), "raw card number leaked to wire"
    # the salt is the reveal secret — it must NEVER be on the wire
    assert salt.hex() not in json.dumps(wire_redacted_with_merkle), "reveal salt leaked to wire"

    vectors["redact_before_sign"] = {
        "provenance": "rust-reference",
        "algorithm": REDACT_COMMIT_ALG,
        "commit_rule": "BLAKE3(salt ++ field_path ++ value_json)",
        "merkle_root_rule": "BLAKE3 over each commitment hex followed by '\\n'",
        "source": "redact.rs (commit-and-reveal) + sdk-recorder-and-gate.md §3.1 step 3",
        "boundary": (
            "redact-before-sign: the commitment is computed and stamped into the "
            "signed action_hash BEFORE the Ed25519 signature; the raw value and the "
            "reveal salt live ONLY in the customer-held sidecar. Neither the signed "
            "receipt body nor the wire commitment carries the value or the salt — "
            "only the salted-BLAKE3 commitment and the markers' merkle_root."
        ),
        "source_receipt_json": redact_receipt,
        "source_receipt_expected_outcome": "Valid",
        "wire_payload": wire_redacted_with_merkle,
        "raw_value_on_wire": False,
        "reveal_salt_on_wire": False,
        "cases": [
            {
                "id": "REDACT-WIRE-COMMIT",
                "desc": "correct salt reproduces the commitment (reveal verifies)",
                "field_path": field_path,
                "salt_hex": salt.hex(),
                "value_json": plaintext,
                "value_json_bytes_hex": value_json.hex(),
                "commitment": redaction_commitment,
                "merkle_root": merkle_root,
                "reveal_verifies": True,
            },
            {
                "id": "REDACT-WIRE-BAD-SALT",
                "desc": "wrong salt must NOT reproduce the on-wire commitment",
                "field_path": field_path,
                "salt_hex": bad_salt.hex(),
                "value_json": plaintext,
                "commitment_to_match": redaction_commitment,
                "reveal_verifies": False,
            },
        ],
    }

    # ── commitment_envelope (KERNEL-EMITTED — CORE-WIRE §0.1, VERIFY-GAP #2) ──
    # The signed commitment envelope is a NEW success-path artifact (NOT
    # conformance-safe): the kernel mints the canonical bytes + the detached
    # operator signature under COMMITMENT_SIGNING_DOMAIN. We EMIT it from the Rust
    # producer seam (never hand-compute) and FATAL-abort if a clean-room re-derive
    # of the fingerprint/domain disagrees. Four cases: ERT-absent (all optionals
    # absent) and ERT-present (optionals present), plus chain-fields-absent and
    # chain-fields-present so both the present-optionals and the all-absent JCS
    # paths are pinned.
    genesis_head = "0" * 64

    # (1) ERT-ABSENT + chain-absent — every optional OMITTED.
    ce_absent = _conformance("commitment", json.dumps(fixed_content()), "allow", genesis_head)
    # (2) ERT-PRESENT — taxonomy_hash + resource_class present.
    ce_ert = _conformance("commitment", json.dumps(fixed_content_with_ert()), "allow", genesis_head)

    # (3) chain-fields-PRESENT — a commitment over a chained successor body, so the
    # envelope carries chain_prev / session_id / seq. We need a real successor body;
    # mint the chained pair first (also the chained_receipt golden, below), then
    # project the successor content into a commitment.
    chained = _conformance(
        "chained", json.dumps(fixed_content()), "sess-wire-chain-01"
    )
    succ_content = chained["successor"]["receipt_json"]["content"]
    ce_chained = _conformance(
        "commitment",
        json.dumps(succ_content),
        "allow",
        chained["genesis"]["link_hash"],
    )

    # FATAL drift gate: the kernel-minted fingerprint MUST equal blake3(pubkey) (the
    # derive.py digest), NOT the heso:-prefixed signer_fingerprint; and the standalone
    # L0 golden MUST be UNMOVED by the seam.
    for label, ce in (("ERT-ABSENT", ce_absent), ("ERT-PRESENT", ce_ert), ("CHAINED", ce_chained)):
        if ce["verify_verdict"] != "Valid":
            sys.exit(f"FATAL: commitment {label} did not self-verify Valid: {ce['verify_verdict']}")
        if ce["signer_fpr"] != ZERO_SEED_COMMITMENT_FPR:
            sys.exit(
                f"FATAL: commitment {label} signer_fpr {ce['signer_fpr']} != blake3(pubkey) "
                f"{ZERO_SEED_COMMITMENT_FPR} (must be the derive.py digest, not signer_fingerprint)"
            )
    # The ERT-absent commitment projects the standalone L0 receipt — its action_hash
    # + operator sig are the 988baa2e… golden the seam MUST NOT move.
    if ce_absent["receipt_action_hash"] != STANDALONE_L0_GOLDEN_ACTION_HASH:
        sys.exit(
            "FATAL: commitment seam MOVED the standalone L0 action_hash golden "
            f"({ce_absent['receipt_action_hash']} != {STANDALONE_L0_GOLDEN_ACTION_HASH})"
        )
    if ce_absent["receipt_operator_signature_b64"] != STANDALONE_L0_GOLDEN_OPERATOR_SIG:
        sys.exit("FATAL: commitment seam MOVED the standalone L0 operator-sig golden")

    vectors["commitment_envelope"] = {
        "provenance": "rust-reference",
        "regenerated_by": "heso-conformance commitment <content_json> <decision> <chain_head>",
        "source": "heso-action::commitment + sign::assemble_action_receipt_with_commitment (CORE-WIRE §0)",
        "crypto_safety": (
            "NOT conformance-safe: a NEW signed/canonical artifact. Kernel-EMITTED, "
            "never hand-computed. Does NOT move the standalone receipt goldens "
            "(f599f21b… / 988baa2e…) — pinned UNMOVED below + in run_vectors.py."
        ),
        "signing_domain": "heso-commitment/v1\\0",
        "signing_domain_hex": ce_absent["commitment_signing_domain_hex"],
        "founder_ratify": (
            "COMMITMENT_SIGNING_DOMAIN = b'heso-commitment/v1\\0' is the design-PROPOSED "
            "value (CORE-WIRE open decision §3). It becomes a frozen wire contract once "
            "this vector ships — founder must ratify before publish."
        ),
        "fingerprint_rule": (
            "signer_fpr = blake3(raw ed25519 pubkey), 64 lowercase-hex, NO prefix — the "
            "derive.py digest the cloud joins approver_keys on, NOT signer_fingerprint."
        ),
        "signer_fpr": ZERO_SEED_COMMITMENT_FPR,
        "operator_public_key_b64": ZERO_SEED_PUBKEY,
        "signed_field_set": [
            "action_hash",
            "chain_prev",
            "chain_head",
            "session_id",
            "seq",
            "primitive",
            "coarse_verb",
            "taxonomy_hash",
            "resource_class",
            "trust_level",
            "decision",
            "occurred_at",
        ],
        "optionality_note": (
            "chain_prev/session_id/seq/taxonomy_hash/resource_class are "
            "skip_serializing_if = Option::is_none — ABSENT = OMITTED from the signed "
            "JCS bytes, never null/sentinel. The field SET is the JCS contract."
        ),
        "standalone_golden_unmoved": {
            "action_hash": STANDALONE_L0_GOLDEN_ACTION_HASH,
            "operator_signature_b64": STANDALONE_L0_GOLDEN_OPERATOR_SIG,
            "note": "the ERT-absent commitment projects this receipt; the seam must not move it",
        },
        "cases": [
            {
                "id": "CE-ERT-ABSENT",
                "desc": "ERT-absent llm_call (execute / allow) — every optional OMITTED",
                "ert_present": False,
                "chain_present": False,
                "envelope_json": ce_absent["envelope_json"],
                "envelope_canonical_bytes_hex": ce_absent["envelope_canonical_bytes_hex"],
                "signature_b64": ce_absent["signature_b64"],
                "signer_pubkey_b64": ce_absent["signer_pubkey_b64"],
                "signer_fpr": ce_absent["signer_fpr"],
                "expected_verdict": "Valid",
            },
            {
                "id": "CE-ERT-PRESENT",
                "desc": "ERT-present payment (move-value / allow) — taxonomy_hash + resource_class present",
                "ert_present": True,
                "chain_present": False,
                "envelope_json": ce_ert["envelope_json"],
                "envelope_canonical_bytes_hex": ce_ert["envelope_canonical_bytes_hex"],
                "signature_b64": ce_ert["signature_b64"],
                "signer_pubkey_b64": ce_ert["signer_pubkey_b64"],
                "signer_fpr": ce_ert["signer_fpr"],
                "expected_verdict": "Valid",
            },
            {
                "id": "CE-CHAIN-PRESENT",
                "desc": "chained successor (seq 1) — chain_prev + session_id + seq present",
                "ert_present": False,
                "chain_present": True,
                "envelope_json": ce_chained["envelope_json"],
                "envelope_canonical_bytes_hex": ce_chained["envelope_canonical_bytes_hex"],
                "signature_b64": ce_chained["signature_b64"],
                "signer_pubkey_b64": ce_chained["signer_pubkey_b64"],
                "signer_fpr": ce_chained["signer_fpr"],
                "expected_verdict": "Valid",
            },
        ],
    }

    # ── chained_receipt (KERNEL-EMITTED — CORE-WIRE A.4, VERIFY-GAP #3) ───────
    # A receipt that CARRIES real seq/session_id/prev_receipt_hash. The instant the
    # chain fields are present, action_canonical_bytes includes them → a NEW
    # action_hash + operator signature (success-path byte change, NOT covered by the
    # standalone goldens). Kernel-emitted via bind_into_chain + assemble. The
    # standalone goldens remain field-absent and UNMOVED (asserted in run_vectors.py).
    vectors["chained_receipt"] = {
        "provenance": "rust-reference",
        "regenerated_by": "heso-conformance chained <content_json> <session_id>",
        "source": "heso-action::chain::bind_into_chain + sign::assemble_action_receipt (CORE-WIRE A.4)",
        "crypto_safety": (
            "NOT conformance-safe: carrying seq/session_id/prev_receipt_hash changes the "
            "signed canonical string → a new action_hash + operator sig. Kernel-EMITTED. "
            "The standalone goldens (f599f21b… / 988baa2e…) stay field-ABSENT + UNMOVED."
        ),
        "session_id": chained["session_id"],
        "operator_public_key_b64": chained["operator_public_key_b64"],
        "chain_link_rule": (
            "prev_receipt_hash = BLAKE3(RECEIPT_CHAIN_DOMAIN ++ LP(session_id) ++ LP(seq_le) "
            "++ LP(action_hash)); the successor's chain_prev MUST equal the genesis link_hash."
        ),
        "standalone_goldens_unmoved": {
            "l0_action_hash": STANDALONE_L0_GOLDEN_ACTION_HASH,
            "l1_action_hash": "f599f21bd3c8c183476743c156a7f4cb79288b97afd5cbd6eb674562bc3b51d0",
            "note": (
                "these standalone (chain-field-absent) goldens are NOT moved by emitting "
                "chained receipts — re-pinned in run_vectors.py as a regression gate"
            ),
        },
        "cases": [
            {
                "id": "CHAIN-GENESIS",
                "desc": "genesis: seq 0, no prev_receipt_hash, session_id stamped",
                "seq": chained["genesis"]["seq"],
                "action_hash": chained["genesis"]["action_hash"],
                "operator_signature_b64": chained["genesis"]["operator_signature_b64"],
                "link_hash": chained["genesis"]["link_hash"],
                "receipt_json": chained["genesis"]["receipt_json"],
                "expected_outcome": "Valid",
            },
            {
                "id": "CHAIN-SUCCESSOR",
                "desc": "successor: seq 1, prev_receipt_hash == genesis link_hash, threads the chain",
                "seq": chained["successor"]["seq"],
                "session_id": chained["successor"]["session_id"],
                "prev_receipt_hash": chained["successor"]["prev_receipt_hash"],
                "action_hash": chained["successor"]["action_hash"],
                "operator_signature_b64": chained["successor"]["operator_signature_b64"],
                "receipt_json": chained["successor"]["receipt_json"],
                "expected_outcome": "Valid",
            },
        ],
        "chain_jsonl": [
            chained["genesis"]["receipt_json"],
            chained["successor"]["receipt_json"],
        ],
        "chain_expected_outcome": "Valid",
    }

    # ── Rust reference validation pass (the SOURCE receipts) ──────────────────
    cli_results: dict[str, str] = {}
    if VERIFY_CLI:
        cli_results["CW-GENESIS"] = verify_cli_verdict([g0], ZERO_SEED_PUBKEY)
        cli_results["CW-CHAINED"] = verify_cli_verdict([g0, g1], ZERO_SEED_PUBKEY)
        cli_results["CW-BLOCK"] = verify_cli_verdict([block_receipt], ZERO_SEED_PUBKEY)
        cli_results["REDACT-RECEIPT"] = verify_cli_verdict([redact_receipt], ZERO_SEED_PUBKEY)
        expected = {
            "CW-GENESIS": "valid",
            "CW-CHAINED": "valid",
            "CW-BLOCK": "valid",
            "REDACT-RECEIPT": "valid",
        }
        print("=== Rust verify-cli reference validation (source receipts) ===", file=sys.stderr)
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
            "scope": (
                "Validates the SOURCE receipts whose fingerprints the commitments "
                "project. The FULL-receipt->commitment projection itself is "
                "spec-derived (no Rust commitment mint yet)."
            ),
            "results": cli_results,
        }
    else:
        print(
            "WARN: heso-verify-cli not found — source receipts cross-checked only via "
            "the zero-seed signature gate. Set HESO_VERIFY_CLI to validate end-to-end.",
            file=sys.stderr,
        )

    with open(OUT_PATH, "w") as fh:
        json.dump(vectors, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {os.path.relpath(OUT_PATH, REPO)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
