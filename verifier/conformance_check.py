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

import json
import os
import sys

import heso_verify as hv
from heso_verify import canonical_bytes

_VEC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vectors")
VECTORS_PATH = os.path.join(_VEC_DIR, "heso-1.0-vectors.json")
CROWN_PATH = os.path.join(_VEC_DIR, "heso-1.0-crown-vectors.json")


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
