"""Cross-language interop gate (§1.7).

For every plat vector, assert that THIS implementation's RFC 8785 (JCS)
canonical bytes — rendered as lowercase hex — equal the recorded
`canonical_bytes_hex`. The recorded value is produced by the reference (Rust)
implementation, so agreement proves byte-identical canonicalization across
languages. The §1.7 ASCII-field-name rule is what makes this agreement
guaranteed rather than incidental.

Exit 0 if all match; exit 1 (printing a diff per failure) otherwise.

The recorded `canonical_bytes_hex` values are filled by Job A at merge; until
then they are "<GENERATED_AT_MERGE>" and are reported as PENDING (exit 1).
"""

from __future__ import annotations

import base64
import json
import os
import sys

import heso_verify as hv
from heso_verify import canonical_bytes

_VEC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vectors")
VECTORS_PATH = os.path.join(_VEC_DIR, "heso-1.0-vectors.json")
CROWN_PATH = os.path.join(_VEC_DIR, "heso-1.0-crown-vectors.json")
ROUND_TRIP_PATH = os.path.join(_VEC_DIR, "round-trip-goldens.json")
ATTESTED_RAIL_PATH = os.path.join(_VEC_DIR, "heso-1.0-attested-rail-vectors.json")

_B64 = base64.standard_b64encode


def recompute_round_trip() -> dict[str, str]:
    """Recompute the schema-§9 round-trip values (RT-1..10) from THIS clean-room
    implementation. Each must equal the Rust kernel's golden byte-for-byte — that
    equality is the attested-rail neutrality proof (modules/attested-rail.md §7)."""
    token = {
        "format": "biscuit-v3",
        "issuer_key_hash": "1" * 64,
        "issuer_managed": False,
        "token_hash": "9" * 64,
        "action_params_hash": "7" * 64,
        "expires_at": "2099-01-01T00:00:00Z",
        "revocation_id": bytes(range(64)).hex(),
        "attenuated": False,
    }
    event_body = {
        "tier": 3,
        "version": 1,
        "event_id": "01900000-0000-7000-8000-000000000001",
        "request_hash": "b" * 64,
        "response_hash": "c" * 64,
        "action_params_hash": "7" * 64,
        "authorization_token": "9" * 64,
        "fetch_content_digest": "e" * 64,
        "server_cert_chain_hash": "d" * 64,
    }
    rt8 = hv.event_bytes_cbor(event_body)
    rt3 = hv.action_params_cbor({"amount": 100, "currency": "USD", "recipient": "acct_123"})
    egress = {
        "event_id": "01900000-0000-7000-8000-000000000001",
        "content_digest": "a" * 64,
        "request_hash": "b" * 64,
        "response_hash": "c" * 64,
        "server_cert_chain_hash": "d" * 64,
        "authorization_token": token,
        "window_commitment": {
            "boot_id": "01900000-0000-7000-8000-000000000002",
            "window_id": 1,
            "admitted_at": "2026-06-27T00:00:00Z",
            "max_merge_delay_secs": 90,
            "promise_sig_b64": _B64(bytes(range(104))).decode(),
            "boot_attestation_b64": _B64(bytes(range(256))).decode(),
        },
        "required": True,
        "profile": "heso-attested-rail/1",
        "min_verifier": 0,
        "evidence_type": "aws-nitro-v1",
    }
    proofs = [
        {
            "attestation_profile": "aws-nitro-v1",
            "evidence": _B64(bytes(range(256))).decode(),
            "window_root_hex": "e" * 64,
            "root_sig_b64": _B64(bytes(range(104))).decode(),
            "merkle_path": [
                {"sibling_hex": "f" * 64, "i_am_right": False},
                {"sibling_hex": "1" * 64, "i_am_right": True},
            ],
            "event_bytes_b64": _B64(rt8).decode(),
            "profile": "heso-attested-rail/1",
            "min_verifier": 0,
        }
    ]
    return {
        "RT1_JCS": canonical_bytes(egress).hex(),
        "RT2_CBOR": hv.promise_sig_preimage(
            "01900000-0000-7000-8000-000000000002",
            "01900000-0000-7000-8000-000000000001",
            1,
            "2026-06-27T00:00:00Z",
            "a" * 64,
            90,
        ).hex(),
        "RT3_CBOR": rt3.hex(),
        "RT3_BLAKE3": hv.blake3(rt3).hexdigest(),
        "RT4_JCS": canonical_bytes(proofs).hex(),
        "RT5_B64": _B64(bytes(range(256))).decode(),
        "RT6A": hv.witness_key_id_hex("test-witness.heso.ca", 0x04, bytes(32)),
        "RT6B": hv.witness_key_id_hex("pq-witness.heso.ca", 0x06, bytes(1312)),
        "RT7": hv.hpke_info(bytes(48)).hex(),
        "RT8_CBOR": rt8.hex(),
        "RT8_BLAKE3": hv.blake3(rt8).hexdigest(),
        "RT9_JCS": canonical_bytes(token).hex(),
        "RT10_CBOR": hv.boot_bindings_cbor(bytes(32), bytes(range(120))).hex(),
    }


def check_round_trip_goldens() -> tuple[int, list[str]]:
    """Assert every RT-1..10 value equals the committed Rust golden (byte-identity).
    Returns (passed, failures)."""
    if not os.path.exists(ROUND_TRIP_PATH):
        return 0, [f"round-trip goldens missing: {ROUND_TRIP_PATH}"]
    with open(ROUND_TRIP_PATH, encoding="utf-8") as fh:
        goldens = json.load(fh).get("goldens", {})
    actual = recompute_round_trip()
    passed = 0
    failures: list[str] = []
    for key in sorted(goldens):
        if actual.get(key) != goldens[key]:
            failures.append(
                f"round-trip/{key}: NOT byte-identical to the Rust golden\n"
                f"    golden: {goldens[key]}\n    actual: {actual.get(key)}"
            )
        else:
            passed += 1
    return passed, failures


def _attested_rail_runtime_ctx(ctx: dict) -> dict:
    """Rebuild the runtime ctx from the JSON-friendly vector form (lists ⇒ sets,
    witness_policies string keys ⇒ int)."""
    runtime = dict(ctx)
    for field in (
        "supported_profiles",
        "supported_evidence_types",
        "revocation_list",
        "invalid_checkpoints",
        "invalid_cosigs",
    ):
        runtime[field] = set(ctx.get(field, []))
    runtime["witness_policies"] = {int(k): v for k, v in ctx.get("witness_policies", {}).items()}
    return runtime


def check_attested_rail_vectors() -> tuple[int, list[str]]:
    """Run every attested-rail conformance vector through ``verify_attested_rail``
    and assert the tri-state verdict (+ annotations on the VALID cases) match the
    expected. Returns (passed, failures)."""
    if not os.path.exists(ATTESTED_RAIL_PATH):
        return 0, [f"attested-rail vectors missing: {ATTESTED_RAIL_PATH}"]
    with open(ATTESTED_RAIL_PATH, encoding="utf-8") as fh:
        corpus = json.load(fh)
    passed = 0
    failures: list[str] = []
    for vec in corpus.get("vectors", []):
        got = hv.verify_attested_rail(vec["receipt"], _attested_rail_runtime_ctx(vec["ctx"]))
        exp = vec["expected"]
        if got["state"] != exp["state"] or got["tag"] != exp["tag"]:
            failures.append(
                f"attested-rail/{vec['id']}: expected {exp['state']}/{exp['tag']} "
                f"but got {got['state']}/{got['tag']}"
            )
        elif "annotations" in exp and sorted(got["annotations"]) != sorted(exp["annotations"]):
            failures.append(
                f"attested-rail/{vec['id']}: annotations expected "
                f"{sorted(exp['annotations'])} but got {sorted(got['annotations'])}"
            )
        else:
            passed += 1
    return passed, failures


def _is_placeholder(value) -> bool:
    return isinstance(value, str) and value.startswith("<GENERATED_AT_MERGE")


def main() -> int:
    with open(VECTORS_PATH, encoding="utf-8") as fh:
        vectors = json.load(fh)

    failures: list[str] = []
    pending: list[str] = []
    passed = 0

    for vec in vectors.get("plat_vectors", []):
        vid = vec.get("id", "?")
        expected = vec.get("canonical_bytes_hex")
        actual = canonical_bytes(vec["input_json"]).hex()
        if _is_placeholder(expected):
            pending.append(f"{vid}: canonical_bytes_hex awaiting Job A (got {actual})")
            continue
        if actual != expected:
            failures.append(
                f"{vid}: canonical_bytes_hex mismatch\n"
                f"    expected: {expected}\n"
                f"    actual:   {actual}"
            )
        else:
            passed += 1

    # ── Crown-jewel byte-identical cross-checks ──────────────────────────────
    # Beyond the plat JCS bytes, the absorbed modules each have a byte-exact rule
    # the spec calls "the byte-identical guarantee". Re-derive each from this
    # clean-room implementation and assert it equals the committed golden bytes:
    #   - action-receipt canonical bytes (JCS over content, action_hash stripped)
    #   - the BLAKE3 chain link hashes
    #   - the DSSE PAE pre-image bytes (the single most error-prone byte rule)
    passed_crown = 0
    if os.path.exists(CROWN_PATH):
        with open(CROWN_PATH, encoding="utf-8") as fh:
            crown = json.load(fh)

        ar = crown.get("action_receipt_v2", {})
        for case in ar.get("cases", []):
            recorded = case.get("canonical_bytes_hex")
            if recorded is None:
                continue
            actual = hv.action_canonical_bytes(case["receipt_json"]["content"]).hex()
            if actual != recorded:
                failures.append(
                    f"action_receipt_v2/{case['id']}: canonical_bytes_hex mismatch\n"
                    f"    expected: {recorded}\n    actual:   {actual}"
                )
            else:
                passed_crown += 1

        chain = crown.get("chain", {})
        links = chain.get("link_hashes", {})
        chain_cases = chain.get("cases", [])
        valid_chain = next(
            (c["chain_jsonl"] for c in chain_cases if c["id"] == "CHAIN-VALID"), None
        )
        if valid_chain:
            for seq, receipt in enumerate(valid_chain):
                key = f"seq{seq}"
                if key not in links:
                    continue
                actual = hv.link_hash(receipt["content"])
                if actual != links[key]:
                    failures.append(
                        f"chain/link/{key}: link_hash mismatch\n"
                        f"    expected: {links[key]}\n    actual:   {actual}"
                    )
                else:
                    passed_crown += 1

        dsse = crown.get("dsse_pae")
        if dsse:
            body = bytes.fromhex(dsse["body_bytes_hex"])
            actual = hv.dsse_pae(dsse["payload_type"], body).hex()
            if actual != dsse["pae_hex"]:
                failures.append(
                    "dsse_pae/pae_hex mismatch\n"
                    f"    expected: {dsse['pae_hex']}\n    actual:   {actual}"
                )
            else:
                passed_crown += 1
    else:
        pending.append("crown vectors file missing — run vectors/generate_vectors.py")

    passed += passed_crown

    # ── HESO-attested-rail/1 — byte-identity neutrality proof + tri-state vectors ──
    rt_passed, rt_failures = check_round_trip_goldens()
    passed += rt_passed
    failures.extend(rt_failures)

    ar_passed, ar_failures = check_attested_rail_vectors()
    passed += ar_passed
    failures.extend(ar_failures)

    for line in pending:
        print(f"PENDING  {line}")
    for line in failures:
        print(f"FAIL     {line}")

    print(f"\n{passed} passed, {len(failures)} failed, {len(pending)} pending merge")

    if failures or pending:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
