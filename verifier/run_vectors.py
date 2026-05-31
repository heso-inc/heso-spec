"""Run the HESO/1.0 conformance vectors against this reference verifier.

For every plat vector: assert plat_hash(input_json) == recorded plat_hash.
For every sealed-envelope / receipt vector: assert
verify_sealed_plat(sealed_envelope_json) == expected_outcome.

Exit 0 if all vectors pass; exit 1 (printing a diff per failure) otherwise.

NOTE: all cryptographic / canonical constants in the vectors file are filled at
merge by the reference implementation (Job A). Until then they hold the literal
placeholder "<GENERATED_AT_MERGE>" and the matching vectors will report as
PENDING and the run will exit non-zero — that is expected pre-merge.
"""

from __future__ import annotations

import json
import os
import sys

from heso_verify import plat_hash, verify_sealed_plat

PLACEHOLDER = "<GENERATED_AT_MERGE>"

VECTORS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "vectors",
    "heso-1.0-vectors.json",
)


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
        expected = vec.get("plat_hash")
        actual = plat_hash(vec["input_json"])
        if _is_placeholder(expected):
            pending.append(f"{vid}: plat_hash awaiting Job A (got {actual})")
            continue
        if actual != expected:
            failures.append(
                f"{vid}: plat_hash mismatch\n"
                f"    expected: {expected}\n"
                f"    actual:   {actual}"
            )
        else:
            passed += 1

    envelope_specs = []
    if "sealed_envelope_vector" in vectors:
        envelope_specs.append(("sealed_envelope_vector", vectors["sealed_envelope_vector"]))
    # A Receipt (§3.5) is a distinct artifact type with its own signing
    # convention; this Grade-0 reference verifier only verifies SealedPlats, so
    # receipt_vector stays in the vectors file as data but is not run here.

    for name, vec in envelope_specs:
        expected = vec.get("expected_outcome")
        envelope = vec.get("sealed_envelope_json") or vec.get("receipt_json")
        # If the signed artifact still carries placeholder crypto, the outcome
        # cannot be meaningfully evaluated yet.
        if _contains_placeholder(envelope):
            pending.append(f"{name}: outcome awaiting Job A constants")
            continue
        actual = verify_sealed_plat(envelope)
        if actual != expected:
            failures.append(
                f"{name}: outcome mismatch\n"
                f"    expected: {expected}\n"
                f"    actual:   {actual}"
            )
        else:
            passed += 1

    for line in pending:
        print(f"PENDING  {line}")
    for line in failures:
        print(f"FAIL     {line}")

    print(f"\n{passed} passed, {len(failures)} failed, {len(pending)} pending merge")

    if failures or pending:
        return 1
    return 0


def _contains_placeholder(obj) -> bool:
    if isinstance(obj, str):
        return _is_placeholder(obj)
    if isinstance(obj, dict):
        return any(_contains_placeholder(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_placeholder(v) for v in obj)
    return False


if __name__ == "__main__":
    sys.exit(main())
