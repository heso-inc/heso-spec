"""Pytest for the HESO-attested-rail/1 reference verifier + conformance corpus.

Three things are asserted:

  1. ROUND-TRIP byte-identity (RT-1..10): every canonical JCS / deterministic-CBOR
     / hash value recomputed by ``heso_verify`` equals the committed Rust kernel
     golden byte-for-byte. This is the neutrality proof.
  2. CONFORMANCE tri-state: every §8 vector (A/B/C/D/E/I1) verifies to the expected
     ``state`` + ``verdict_tag`` (and annotations on the VALID cases).
  3. I1 IMPL-DISCIPLINE: a real RSA-2048 key CANNOT verify the P-384 ``root_sig``,
     so a verifier that (wrongly) sources the app-key from ``attestation.public_key``
     would FAIL where the correct ``app_key_spki``-sourcing verifier returns VALID.

Run: ``pytest vectors/test_attested_rail.py`` (needs ``pytest`` in the venv).
"""

from __future__ import annotations

import json
import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "verifier"))

import conformance_check as cc  # noqa: E402
import heso_verify as hv  # noqa: E402

_VEC_DIR = os.path.join(_ROOT, "vectors")


def _load(name: str) -> dict:
    with open(os.path.join(_VEC_DIR, name), encoding="utf-8") as fh:
        return json.load(fh)


_GOLDENS = _load("round-trip-goldens.json")["goldens"]
_ACTUAL_RT = cc.recompute_round_trip()
_VECTORS = _load("heso-1.0-attested-rail-vectors.json")["vectors"]


@pytest.mark.parametrize("key", sorted(_GOLDENS))
def test_round_trip_byte_identity(key: str) -> None:
    assert _ACTUAL_RT[key] == _GOLDENS[key], f"{key} is not byte-identical to the Rust golden"


@pytest.mark.parametrize("vec", _VECTORS, ids=lambda v: v["id"])
def test_attested_rail_vector(vec: dict) -> None:
    got = hv.verify_attested_rail(vec["receipt"], cc._attested_rail_runtime_ctx(vec["ctx"]))
    exp = vec["expected"]
    assert (got["state"], got["tag"]) == (exp["state"], exp["tag"])
    if "annotations" in exp:
        assert sorted(got["annotations"]) == sorted(exp["annotations"])


def test_i1_app_key_sourcing_discipline() -> None:
    """I1: the P-384 ``root_sig`` verifies under the real ``app_key_spki`` and is
    REJECTED under an RSA-2048 key — so the key-source choice is load-bearing."""
    app_key = ec.generate_private_key(ec.SECP384R1())
    app_spki = app_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    window_root = bytes(range(32))
    sig = app_key.sign(window_root, ec.ECDSA(hashes.SHA384()))

    rsa_spki = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )

    assert hv._es384_verify(app_spki, sig, window_root) is True
    assert hv._es384_verify(rsa_spki, sig, window_root) is False


def test_conformance_check_aggregate() -> None:
    """The same corpus through the repo's conformance gate must report zero
    failures (the byte-identity block + the tri-state block)."""
    rt_passed, rt_failures = cc.check_round_trip_goldens()
    ar_passed, ar_failures = cc.check_attested_rail_vectors()
    assert rt_failures == []
    assert ar_failures == []
    assert rt_passed == len(_GOLDENS)
    assert ar_passed == len(_VECTORS)
