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

from heso_verify import canonical_bytes

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
