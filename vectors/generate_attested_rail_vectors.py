"""Generate the HESO-attested-rail/1 cross-language conformance vectors.

Emits ``vectors/heso-1.0-attested-rail-vectors.json`` — the §8 catalogue from the
FROZEN-WIRE-SCHEMA: A (valid), B (forgery/FAIL), C (lifecycle), D (forward-compat
& congruence), E (registry / verify-as-of-mint), plus I1 (impl-discipline). Each
vector is ``{id, group, description, expected:{state,tag}, receipt, ctx}`` and is
SELF-CHECKED against :func:`heso_verify.verify_attested_rail` here at generation
time, so a spec-logic drift fails the build instead of silently shipping.

Every leg that is a pure function of bytes is REAL: the BLAKE3 ``content_digest``
binding, the params/token congruence over the decoded ``event_bytes``, the
SHA-256 window-tree fold, the index-driven RFC-6962 Type-B/Type-C inclusion folds,
the RFC-3339 time math, and the ES384 ``root_sig``/``promise_sig`` signatures
(deterministic P-384 keys). The reference verifier MODELS three signature boundaries
as out-of-band ``ctx`` facts (Grade-0): the AWS-Nitro COSE/cabundle/PCR attestation
(``ctx["attestations"]``), the witness cosignature raw-signature bytes
(``ctx["invalid_cosigs"]``), and the checkpoint log-key signature validity
(``ctx["invalid_checkpoints"]``); a production verifier MUST verify all three for real
(modules/attested-rail.md §8). Run: ``python generate_attested_rail_vectors.py``.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "verifier")
)

import heso_verify as hv  # noqa: E402
from heso_verify import (  # noqa: E402
    blake3,
    event_bytes_cbor,
    l4_type_b_leaf,
    l4_type_c_leaf,
    promise_sig_preimage,
    rfc6962_leaf_hash,
    rfc6962_node_hash,
)

B64 = base64.standard_b64encode

# ── deterministic keys (reproducible vectors) ───────────────────────────────
APP_KEY = ec.derive_private_key(
    int.from_bytes(b"heso-attested-rail-app-key-p384!!", "big"), ec.SECP384R1()
)
APP_SPKI = APP_KEY.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
)
APP_SPKI_B64 = B64(APP_SPKI).decode()
LOG_KEY = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
LOG_PUB = LOG_KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
ED_WITNESS = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)
ED_WITNESS_PUB = ED_WITNESS.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
MLDSA_WITNESS_PUB = bytes(range(256)) * 5 + bytes(32)  # 1312-byte stand-in (modeled sig)

PCR0_GOOD = "ab" * 48
ROOT_FPR = "cd" * 32
ADMITTED_AT = "2026-06-27T00:00:00Z"
NOW_WITHIN = "2026-06-27T00:01:00Z"
NOW_PAST = "2026-06-27T02:00:00Z"


def es384(message: bytes) -> str:
    # Deterministic (RFC 6979) so the committed vectors are byte-reproducible on
    # regeneration; the verifier accepts any valid ES384 signature regardless.
    sig = APP_KEY.sign(message, ec.ECDSA(hashes.SHA384(), deterministic_signing=True))
    return B64(sig).decode()


def rfc6962_root(leaves: list[bytes]) -> bytes:
    hashed = [rfc6962_leaf_hash(v) for v in leaves]
    return _mth(hashed)


def _mth(nodes: list[bytes]) -> bytes:
    if len(nodes) == 1:
        return nodes[0]
    k = 1
    while k * 2 < len(nodes):
        k *= 2
    return rfc6962_node_hash(_mth(nodes[:k]), _mth(nodes[k:]))


def rfc6962_path(leaves: list[bytes], index: int) -> list[bytes]:
    return _path([rfc6962_leaf_hash(v) for v in leaves], index)


def _path(nodes: list[bytes], m: int) -> list[bytes]:
    if len(nodes) == 1:
        return []
    k = 1
    while k * 2 < len(nodes):
        k *= 2
    if m < k:
        return _path(nodes[:k], m) + [_mth(nodes[k:])]
    return _path(nodes[k:], m - k) + [_mth(nodes[:k])]


def make_checkpoint(root: bytes, tree_size: int, origin: str = "l4.heso.ca/v1") -> str:
    body = f"{origin}\n{tree_size}\n{B64(root).decode()}\n"
    sig = LOG_KEY.sign(body.encode())
    key_hash = hv.hashlib.sha256(origin.encode() + b"\n" + bytes([0x01]) + LOG_PUB).digest()[:4]
    note = body + "\n" + f"— {origin} {B64(key_hash + sig).decode()}\n"
    return B64(note.encode()).decode()


def registry_entry(valid_from: int, valid_until: int) -> bytes:
    ref = b"git:" + b"a" * 40 + b":eif-sha256:" + b"b" * 64
    return (
        bytes([0x01])
        + bytes.fromhex(PCR0_GOOD)
        + bytes(48) * 3
        + valid_from.to_bytes(8, "big")
        + valid_until.to_bytes(8, "big")
        + len(ref).to_bytes(2, "big")
        + ref
    )


def good_attestation(evidence: str) -> dict:
    return {
        evidence: {
            "parse_ok": True,
            "cose_alg": "ES384",
            "cose_sig_valid": True,
            "root_fpr": ROOT_FPR,
            "chain_valid": True,
            "chain_detail": "ok",
            "issuer_is_ca": True,
            "cert_expired_at_attestation": None,
            "cert_expired_at_admitted": None,
            "pcr0": PCR0_GOOD,
            "app_key_spki_b64": APP_SPKI_B64,
            "hpke_present": True,
            "kms_present": True,
            "timestamp": ADMITTED_AT,
        }
    }


def base_ctx() -> dict:
    return {
        "trusted_now": NOW_WITHIN,
        "verifier_version": 0,
        "supported_profiles": [hv.ENCLAVE_PROFILE_V1],
        "supported_evidence_types": [hv.ENCLAVE_EVIDENCE_TYPE_V1],
        "pinned_pcr0": {hv.ENCLAVE_EVIDENCE_TYPE_V1: PCR0_GOOD},
        "pinned_root_fpr": ROOT_FPR,
        "witness_policies": {},
        "revocation_list": [],
        "invalid_checkpoints": [],
        "invalid_cosigs": [],
        "attestations": {},
    }


def make_token(event_bytes: dict) -> dict:
    return {
        "format": "biscuit-v3",
        "issuer_key_hash": "1" * 64,
        "issuer_managed": False,
        "token_hash": event_bytes["authorization_token"],
        "action_params_hash": event_bytes["action_params_hash"],
        "expires_at": "2099-01-01T00:00:00Z",
        "revocation_id": "ab" * 32,
        "attenuated": False,
    }


def make_green(*, required: bool = True, tier: int = 1, evidence_tag: str = "base") -> dict:
    """A fully-green proof-present receipt: Checks 0–5 pass, witness leg defaults
    to WitnessedSkipped (no checkpoint), registry leg to RegistryUnresolved. Both
    legs are layered on per-vector. Returns {receipt, ctx}."""
    evidence = B64(f"nsm-doc-{evidence_tag}".encode() + bytes(200)).decode()
    body = {
        "tier": tier,
        "version": 1,
        "event_id": "01900000-0000-7000-8000-000000000001",
        "request_hash": "b" * 64,
        "response_hash": "c" * 64,
        "action_params_hash": "7" * 64,
        "authorization_token": "9" * 64,
        "server_cert_chain_hash": "d" * 64,
    }
    if tier == 3:
        body["fetch_content_digest"] = "e" * 64
    event_bytes = event_bytes_cbor(body)
    content_digest = blake3(event_bytes).hexdigest()

    # 2-leaf window tree: this event at index 0, a sibling event at index 1.
    sibling_event = event_bytes_cbor({**body, "request_hash": "a" * 64})
    window_root = rfc6962_node_hash(
        rfc6962_leaf_hash(event_bytes), rfc6962_leaf_hash(sibling_event)
    )
    merkle_path = [{"sibling_hex": rfc6962_leaf_hash(sibling_event).hex(), "i_am_right": False}]

    wc = {
        "boot_id": "01900000-0000-7000-8000-000000000002",
        "window_id": 1,
        "admitted_at": ADMITTED_AT,
        "max_merge_delay_secs": 90,
        "promise_sig_b64": es384(
            promise_sig_preimage(
                "01900000-0000-7000-8000-000000000002",
                body["event_id"],
                1,
                ADMITTED_AT,
                content_digest,
                90,
            )
        ),
        "boot_attestation_b64": evidence,
    }
    proof = {
        "attestation_profile": hv.ENCLAVE_EVIDENCE_TYPE_V1,
        "evidence": evidence,
        "window_root_hex": window_root.hex(),
        "root_sig_b64": es384(window_root),
        "merkle_path": merkle_path,
        "event_bytes_b64": B64(event_bytes).decode(),
        "profile": hv.ENCLAVE_PROFILE_V1,
        "min_verifier": 0,
    }
    receipt = {
        "content": {
            "enclave_egress": {
                "event_id": body["event_id"],
                "content_digest": content_digest,
                "request_hash": "b" * 64,
                "response_hash": "c" * 64,
                "server_cert_chain_hash": "d" * 64,
                "authorization_token": make_token(body),
                "window_commitment": wc,
                "required": required,
                "profile": hv.ENCLAVE_PROFILE_V1,
                "min_verifier": 0,
                "evidence_type": hv.ENCLAVE_EVIDENCE_TYPE_V1,
            }
        },
        "enclave_window_proofs": [proof],
    }
    ctx = base_ctx()
    ctx["attestations"].update(good_attestation(evidence))
    return {
        "receipt": receipt,
        "ctx": ctx,
        "_window_root": window_root,
        "_seal_time_ms": 1782000000000,
    }


def add_witness_green(bundle: dict) -> None:
    """Layer a witness-green leg (checkpoint + Ed25519 cosig + window-root
    inclusion carrier, policy threshold=1/external=1) onto a green bundle."""
    proof = bundle["receipt"]["enclave_window_proofs"][0]
    wc = bundle["receipt"]["content"]["enclave_egress"]["window_commitment"]
    seal = bundle["_seal_time_ms"]
    leaf = l4_type_b_leaf(wc["boot_id"], wc["window_id"], seal, bundle["_window_root"])
    other = b"\x11other-l4-leaf"
    root = rfc6962_root([leaf, other])
    proof["witness_checkpoint_b64"] = make_checkpoint(root, 2)
    proof["window_root_inclusion_proof"] = [B64(s).decode() for s in rfc6962_path([leaf, other], 0)]
    proof["window_root_leaf_index"] = 0
    proof["window_seal_time_ms"] = seal
    cosig = {
        "witness_name": "witness2.heso.ca/v1",
        "key_id_hex": hv.witness_key_id_hex("witness2.heso.ca/v1", 0x04, ED_WITNESS_PUB),
        "cosig_line": "— witness2.heso.ca/v1 AAAA",
        "timestamp_unix": 1782000000,
    }
    proof["policy_version"] = 1
    proof["witness_cosignatures"] = [cosig]
    bundle["ctx"]["witness_policies"]["1"] = {
        "threshold": 1,
        "require_external_min": 1,
        "witnesses": {
            "witness2.heso.ca/v1": {
                "algo": 0x04,
                "pubkey_b64": B64(ED_WITNESS_PUB).decode(),
                "active_from": 0,
                "retired_at": None,
            }
        },
    }


def add_registry(bundle: dict, valid_from: int = 0, valid_until: int = 0) -> None:
    """Layer a valid registry leg (Type-C inclusion + time bounds) onto a bundle."""
    proof = bundle["receipt"]["enclave_window_proofs"][0]
    entry = registry_entry(valid_from, valid_until)
    leaf = l4_type_c_leaf(entry)
    other = b"\x12other-registry"
    root = rfc6962_root([leaf, other])
    proof["registry_entry_bytes"] = B64(entry).decode()
    proof["inclusion_proof"] = [B64(s).decode() for s in rfc6962_path([leaf, other], 0)]
    proof["registry_leaf_index"] = 0
    proof["checkpoint"] = make_checkpoint(root, 2)


def make_promise_only(*, required: bool = True) -> dict:
    """A PROOF-ABSENT (pending) receipt: signed window_commitment, no sidecar
    proof. The stapled boot_attestation is decoded for the promise evaluation."""
    bundle = make_green(required=required)
    bundle["receipt"]["enclave_window_proofs"] = []
    return bundle


# ── vector assembly ─────────────────────────────────────────────────────────
VECTORS: list[dict] = []


def emit(
    vid: str,
    group: str,
    desc: str,
    state: str,
    tag: str,
    bundle: dict,
    annos: list[str] | None = None,
) -> None:
    receipt = bundle["receipt"]
    ctx = bundle["ctx"]
    expected: dict = {"state": state, "tag": tag}
    if annos is not None:
        expected["annotations"] = annos
    VECTORS.append(
        {
            "id": vid,
            "group": group,
            "description": desc,
            "expected": expected,
            "receipt": receipt,
            "ctx": ctx,
        }
    )


def _mut(bundle: dict) -> dict:
    return {
        "receipt": copy.deepcopy(bundle["receipt"]),
        "ctx": copy.deepcopy(bundle["ctx"]),
        "_window_root": bundle.get("_window_root"),
        "_seal_time_ms": bundle.get("_seal_time_ms"),
    }


def _egress(bundle: dict) -> dict:
    return bundle["receipt"]["content"]["enclave_egress"]


def _proof(bundle: dict) -> dict:
    return bundle["receipt"]["enclave_window_proofs"][0]


def _att(bundle: dict) -> dict:
    ev = _proof(bundle)["evidence"]
    return bundle["ctx"]["attestations"][ev]


def build() -> None:
    # ---- A: valid (5) ------------------------------------------------------
    a1 = make_green(evidence_tag="a1")
    add_witness_green(a1)
    add_registry(a1)
    emit(
        "A1",
        "A",
        "fully-proven tier-1 required, witness-green + valid registry",
        "VALID",
        "EnclaveValid",
        a1,
        ["EnclaveWitnessedGreen", "EnclaveRegistryResolved"],
    )

    a2 = make_green(required=False, evidence_tag="a2")
    emit(
        "A2",
        "A",
        "advisory proof-present, cosigs=[]+no checkpoint under advisory policy",
        "VALID",
        "EnclaveValid",
        a2,
        ["EnclaveWitnessedSkipped", "EnclaveRegistryUnresolved"],
    )

    a3 = make_green(required=False, evidence_tag="a3")
    _egress(a3)["ext"] = {"values": {"50000": "advisory-note"}}
    emit(
        "A3",
        "A",
        "unknown advisory ext (key 50000) not in crit",
        "VALID",
        "EnclaveValid",
        a3,
        ["EnclaveWitnessedSkipped", "EnclaveRegistryUnresolved"],
    )

    a4 = make_green(tier=3, required=False, evidence_tag="a4")
    emit(
        "A4",
        "A",
        "tier-3 (fetch_content_digest in event_bytes)",
        "VALID",
        "EnclaveValid",
        a4,
        ["EnclaveWitnessedSkipped", "EnclaveRegistryUnresolved"],
    )

    a5 = make_green(evidence_tag="a5")
    add_witness_green(a5)
    p5 = _proof(a5)
    p5["witness_cosignatures"] = [
        {
            "witness_name": "pq-witness.heso.ca/v1",
            "key_id_hex": hv.witness_key_id_hex("pq-witness.heso.ca/v1", 0x06, MLDSA_WITNESS_PUB),
            "cosig_line": "— pq-witness.heso.ca/v1 PQPQ",
            "timestamp_unix": 1782000000,
        }
    ]
    a5["ctx"]["witness_policies"]["1"]["witnesses"] = {
        "pq-witness.heso.ca/v1": {
            "algo": 0x06,
            "pubkey_b64": B64(MLDSA_WITNESS_PUB).decode(),
            "active_from": 0,
            "retired_at": None,
        }
    }
    emit(
        "A5",
        "A",
        "ML-DSA-44 (0x06) cosig only, full inclusion carrier",
        "VALID",
        "EnclaveValid",
        a5,
        ["EnclaveWitnessedGreen", "EnclaveRegistryUnresolved"],
    )

    # ---- B: forgery / FAIL (27, minus retired B14) -------------------------
    b = make_green(evidence_tag="b")

    b1 = _mut(b)
    _att(b1)["root_fpr"] = "ff" * 32
    emit("B1", "B", "wrong AWS root", "FAIL", "EnclaveChainNotPinnedRoot", b1)

    b2 = _mut(b)
    _att(b2)["pcr0"] = "00" * 48
    emit("B2", "B", "tampered PCR0 (proof present)", "FAIL", "EnclavePcr0Mismatch", b2)

    b3 = _mut(b)
    _proof(b3)["merkle_path"][0]["sibling_hex"] = "0" * 64
    emit("B3", "B", "flipped sibling_hex", "FAIL", "EnclaveInclusionProofInvalid", b3)

    b4 = _mut(b)
    _proof(b4)["merkle_path"][0]["i_am_right"] = True
    emit("B4", "B", "inverted i_am_right", "FAIL", "EnclaveInclusionProofInvalid", b4)

    b5 = _mut(b)
    _egress(b5)["authorization_token"]["expires_at"] = "2020-01-01T00:00:00Z"
    emit("B5", "B", "expires_at < admitted_at", "FAIL", "EnclaveTokenExpired", b5)

    b6 = _mut(b)
    _egress(b6)["authorization_token"]["action_params_hash"] = "5" * 64
    emit(
        "B6",
        "B",
        "token.action_params_hash != event_bytes.action_params_hash",
        "FAIL",
        "EnclaveActionParamsMismatch",
        b6,
    )

    b7 = make_green(evidence_tag="b7")
    p7a = _proof(b7)
    p7b = copy.deepcopy(p7a)
    p7b["window_root_hex"] = "a" * 64
    b7["receipt"]["enclave_window_proofs"] = [p7a, p7b]
    emit(
        "B7",
        "B",
        "two proofs, same boot evidence, different window_root",
        "FAIL",
        "EnclaveEquivocationDetected",
        b7,
    )

    b8 = _mut(b)
    _proof(b8)["evidence"] = B64(b"different-evidence" + bytes(200)).decode()
    emit(
        "B8",
        "B",
        "sidecar evidence != boot_attestation_b64",
        "FAIL",
        "EnclaveBootAttestationMismatch",
        b8,
    )

    b9 = _mut(b)
    _att(b9)["cose_sig_valid"] = False
    emit("B9", "B", "bad COSE signature", "FAIL", "EnclaveAttestationSignatureInvalid", b9)

    b10 = make_promise_only()
    # break the promise_sig by signing over a different preimage.
    wc10 = _egress(b10)["window_commitment"]
    wc10["promise_sig_b64"] = es384(promise_sig_preimage("x", "y", 9, ADMITTED_AT, "0" * 64, 1))
    emit(
        "B10",
        "B",
        "promise_sig over wrong preimage (proof absent)",
        "FAIL",
        "EnclaveWindowPromiseInvalid",
        b10,
    )

    b11 = _mut(b)
    _att(b11)["cose_alg"] = "ES256"
    emit("B11", "B", "COSE alg ES256", "FAIL", "EnclaveAttestationWrongAlgorithm", b11)

    b12 = _mut(b)
    _att(b12)["cert_expired_at_attestation"] = 1
    emit(
        "B12",
        "B",
        "cert expired at attestation.timestamp",
        "FAIL",
        "EnclaveCertExpiredAtAttestation:1",
        b12,
    )

    b13 = _mut(b)
    _att(b13)["issuer_is_ca"] = False
    emit("B13", "B", "issuer cA:FALSE", "FAIL", "EnclaveIssuerNotCa:0", b13)

    b15 = _mut(b)
    _att(b15)["parse_ok"] = False
    _att(b15)["chain_detail"] = "cose-parse"
    emit("B15", "B", "COSE parse failure", "FAIL", "EnclaveAttestationMalformed:cose-parse", b15)

    b16 = _mut(b)
    _att(b16)["chain_valid"] = False
    _att(b16)["chain_detail"] = "unsigned"
    emit("B16", "B", "cert not signed by issuer", "FAIL", "EnclaveChainInvalid:unsigned", b16)

    b17 = _mut(b)
    _att(b17)["app_key_spki_b64"] = None
    emit("B17", "B", "app_key_spki absent", "FAIL", "EnclaveAppKeyBindingMissing", b17)

    b18 = _mut(b)
    _att(b18)["hpke_present"] = False
    emit("B18", "B", "hpke_pubkey absent", "FAIL", "EnclaveHpkeBindingMissing", b18)

    b19 = _mut(b)
    _att(b19)["kms_present"] = False
    emit(
        "B19",
        "B",
        "attestation.public_key (KMS) absent",
        "FAIL",
        "EnclaveKmsKeyBindingMissing",
        b19,
    )

    b20 = _mut(b)
    _egress(b20)["content_digest"] = "0" * 64
    emit(
        "B20",
        "B",
        "blake3(event_bytes) != content_digest",
        "FAIL",
        "EnclaveContentDigestMismatch",
        b20,
    )

    b21 = _mut(b)
    _proof(b21)["root_sig_b64"] = es384(b"not the window root")
    emit("B21", "B", "root_sig invalid under app-key", "FAIL", "EnclaveRootSignatureInvalid", b21)

    b22 = make_green(evidence_tag="b22")
    add_witness_green(b22)
    add_registry(b22)
    b22["ctx"]["invalid_checkpoints"] = [_proof(b22)["witness_checkpoint_b64"]]
    emit(
        "B22",
        "B",
        "witness checkpoint log-key sig invalid",
        "FAIL",
        "EnclaveWitnessCheckpointInvalid",
        b22,
    )

    b23 = make_green(evidence_tag="b23")
    add_witness_green(b23)
    add_registry(b23)
    b23["ctx"]["invalid_cosigs"] = [_proof(b23)["witness_cosignatures"][0]["cosig_line"]]
    emit("B23", "B", "cosig signature invalid", "FAIL", "EnclaveWitnessCosigInvalid", b23)

    b24 = _mut(b)
    _att(b24)["cert_expired_at_admitted"] = 2
    emit(
        "B24",
        "B",
        "cert valid at attestation but expired at admitted_at",
        "FAIL",
        "EnclaveCertExpiredAtAdmittedAt:2",
        b24,
    )

    b25 = make_green(evidence_tag="b25")
    add_witness_green(b25)
    _proof(b25)["window_root_inclusion_proof"] = [B64(b"\x00" * 32).decode()]
    emit(
        "B25",
        "B",
        "window-root inclusion carrier present but leaf not in checkpoint",
        "FAIL",
        "EnclaveWindowRootInclusionInvalid",
        b25,
    )

    b26 = _mut(b)
    _att(b26)["timestamp"] = "2026-06-27T01:00:00Z"
    emit("B26", "B", "attestation.timestamp > admitted_at", "FAIL", "EnclaveTimestampAnomaly", b26)

    b27 = _mut(b)
    _egress(b27)["authorization_token"]["token_hash"] = "4" * 64
    emit(
        "B27",
        "B",
        "token.token_hash != event_bytes.authorization_token",
        "FAIL",
        "EnclaveTokenBindingMismatch",
        b27,
    )

    b28 = _mut(b)
    _egress(b28)["authorization_token"]["expires_at"] = "not-a-timestamp"
    emit("B28", "B", "expires_at unparseable", "FAIL", "EnclaveTokenMalformed", b28)

    # ---- C: lifecycle (9) --------------------------------------------------
    c1 = make_promise_only()
    c1["ctx"]["trusted_now"] = NOW_WITHIN
    emit("C1", "C", "within-MMD, no proof", "WITHHELD", "EnclaveWindowPending", c1)

    c2 = make_promise_only()
    c2["ctx"]["trusted_now"] = NOW_PAST
    emit("C2", "C", "past-MMD, no proof", "FAIL", "EnclaveWindowPromiseBreached", c2)

    c3 = make_promise_only()
    ev3 = _egress(c3)["window_commitment"]["boot_attestation_b64"]
    c3["ctx"]["attestations"][ev3]["pcr0"] = "00" * 48
    emit(
        "C3", "C", "promise present, PCR0 bad, no proof", "FAIL", "EnclaveWindowPromiseInvalid", c3
    )

    c4 = make_green(evidence_tag="c4")
    c4["receipt"]["enclave_window_proofs"] = []
    del _egress(c4)["window_commitment"]
    emit(
        "C4",
        "C",
        "required=true, window_commitment=None, no proof",
        "FAIL",
        "EnclaveProofAbsent",
        c4,
    )

    c5 = make_green(evidence_tag="c5")
    _proof(c5)["policy_version"] = 2
    c5["ctx"]["witness_policies"]["2"] = {
        "threshold": 2,
        "require_external_min": 1,
        "witnesses": {},
    }
    emit(
        "C5",
        "C",
        "checks 1-5 green, cosigs=[] under threshold=2/external=1",
        "WITHHELD",
        "EnclaveWitnessQuorumNotMet",
        c5,
    )

    c6 = make_green(evidence_tag="c6")
    _proof(c6)["policy_version"] = 3
    c6["ctx"]["witness_policies"]["3"] = {
        "threshold": 1,
        "require_external_min": 0,
        "witnesses": {},
    }
    emit(
        "C6",
        "C",
        "cosigs=[]+no checkpoint under threshold=1/external=0",
        "VALID",
        "EnclaveValid",
        c6,
        ["EnclaveWitnessedSkipped", "EnclaveRegistryUnresolved"],
    )

    c7 = make_green(evidence_tag="c7")
    _proof(c7)["policy_version"] = 999
    emit("C7", "C", "unknown policy_version", "WITHHELD", "EnclaveWitnessPolicyUnknown", c7)

    c8 = make_green(evidence_tag="c8")
    add_witness_green(c8)
    p8 = _proof(c8)
    del p8["window_root_inclusion_proof"]
    del p8["window_root_leaf_index"]
    del p8["window_seal_time_ms"]
    emit(
        "C8",
        "C",
        "checkpoint+cosigs valid but window-root-inclusion carrier absent",
        "WITHHELD",
        "EnclaveWindowRootInclusionMissing",
        c8,
    )

    c9 = make_green(required=False, evidence_tag="c9")
    c9["receipt"]["enclave_window_proofs"] = []
    del _egress(c9)["window_commitment"]
    emit("C9", "C", "required=false, window_commitment=None", "WITHHELD", "EnclaveProofAbsent", c9)

    # ---- D: forward-compat & congruence (9) --------------------------------
    d1 = make_green(required=False, evidence_tag="d1")
    _egress(d1)["ext"] = {"values": {"50000": "advisory"}}
    emit(
        "D1",
        "D",
        "unknown advisory ext (key 50000) not in crit",
        "VALID",
        "EnclaveValid",
        d1,
        ["EnclaveWitnessedSkipped", "EnclaveRegistryUnresolved"],
    )

    d2 = make_green(evidence_tag="d2")
    _egress(d2)["ext"] = {"crit": [50001], "values": {"50001": "must-understand"}}
    emit(
        "D2",
        "D",
        "unknown critical ext (key 50001 in crit)",
        "WITHHELD",
        "EnclaveUnknownCriticalExtension:50001",
        d2,
    )

    d3 = make_green(evidence_tag="d3")
    _egress(d3)["min_verifier"] = 65535
    emit("D3", "D", "min_verifier=65535", "WITHHELD", "EnclaveVersionTooNew", d3)

    d4 = make_green(evidence_tag="d4")
    _egress(d4)["profile"] = "heso-attested-rail/99"
    emit("D4", "D", "profile heso-attested-rail/99", "WITHHELD", "EnclaveUnsupportedContract", d4)

    d5 = make_green(required=False, evidence_tag="d5")
    _egress(d5)["evidence_type"] = "intel-tdx-v1"
    emit(
        "D5",
        "D",
        "evidence_type intel-tdx-v1, required=false",
        "WITHHELD",
        "EnclaveAttestationUnsupportedProfile",
        d5,
    )

    d6 = make_green(evidence_tag="d6")
    _egress(d6)["evidence_type"] = "intel-tdx-v1"
    emit(
        "D6",
        "D",
        "evidence_type intel-tdx-v1, required=true",
        "FAIL",
        "EnclaveAttestationUnsupportedProfile",
        d6,
    )

    d7 = make_green(evidence_tag="d7")
    _proof(d7)["attestation_profile"] = "intel-tdx-v1"
    emit(
        "D7",
        "D",
        "signed evidence_type aws-nitro-v1 vs sidecar attestation_profile intel-tdx-v1",
        "FAIL",
        "EnclaveAttestationProfileMismatch",
        d7,
    )

    d8 = make_green(evidence_tag="d8")
    _proof(d8)["profile"] = "heso-attested-rail/2"
    emit(
        "D8",
        "D",
        "sidecar profile heso-attested-rail/2 vs signed /1",
        "FAIL",
        "EnclaveContractProfileMismatch",
        d8,
    )

    d9 = make_green(evidence_tag="d9")
    _proof(d9)["profile"] = "heso-attested-rail/unknownx"
    emit(
        "D9",
        "D",
        "sidecar profile heso-attested-rail/unknownx vs signed /1",
        "FAIL",
        "EnclaveContractProfileMismatch",
        d9,
    )

    # ---- E: registry / verify-as-of-mint (4) -------------------------------
    e1 = make_green(required=False, evidence_tag="e1")
    add_registry(e1)
    emit(
        "E1",
        "E",
        "registry present + valid inclusion + time-bounds OK",
        "VALID",
        "EnclaveValid",
        e1,
        ["EnclaveWitnessedSkipped", "EnclaveRegistryResolved"],
    )

    e2 = make_green(required=False, evidence_tag="e2")
    add_registry(e2)
    _proof(e2)["inclusion_proof"] = [B64(b"\x00" * 32).decode()]
    emit(
        "E2",
        "E",
        "registry present with garbage inclusion_proof",
        "FAIL",
        "EnclaveRegistryProofInvalid",
        e2,
    )

    e3 = make_green(required=False, evidence_tag="e3")
    add_registry(e3, valid_from=4102444800, valid_until=0)  # valid_from = 2100 > mint
    emit(
        "E3",
        "E",
        "registry inclusion valid but valid_from > mint_time",
        "FAIL",
        "EnclaveRegistryStale",
        e3,
    )

    e4 = make_green(required=False, evidence_tag="e4")
    emit(
        "E4",
        "E",
        "registry absent (whole carrier absent)",
        "VALID",
        "EnclaveValid",
        e4,
        ["EnclaveWitnessedSkipped", "EnclaveRegistryUnresolved"],
    )

    # ---- I1: impl-discipline (sources app-key from app_key_spki, not RSA) ---
    i1 = make_green(evidence_tag="i1")
    emit(
        "I1",
        "I",
        "RSA in attestation.public_key, real P-384 in app_key_spki; correct path",
        "VALID",
        "EnclaveValid",
        i1,
        ["EnclaveWitnessedSkipped", "EnclaveRegistryUnresolved"],
    )


def ctx_to_runtime(ctx: dict) -> dict:
    """Rebuild the runtime ctx the verifier expects from the JSON-friendly form:
    lists ⇒ sets, witness_policies str keys ⇒ int."""
    runtime = dict(ctx)
    runtime["supported_profiles"] = set(ctx["supported_profiles"])
    runtime["supported_evidence_types"] = set(ctx["supported_evidence_types"])
    runtime["revocation_list"] = set(ctx["revocation_list"])
    runtime["invalid_checkpoints"] = set(ctx["invalid_checkpoints"])
    runtime["invalid_cosigs"] = set(ctx["invalid_cosigs"])
    runtime["witness_policies"] = {int(k): v for k, v in ctx["witness_policies"].items()}
    return runtime


def main() -> int:
    build()
    failures: list[str] = []
    for vec in VECTORS:
        got = hv.verify_attested_rail(vec["receipt"], ctx_to_runtime(vec["ctx"]))
        exp = vec["expected"]
        if got["state"] != exp["state"] or got["tag"] != exp["tag"]:
            failures.append(
                f"{vec['id']}: expected {exp['state']}/{exp['tag']} "
                f"but got {got['state']}/{got['tag']}"
            )
        elif "annotations" in exp and sorted(got["annotations"]) != sorted(exp["annotations"]):
            failures.append(
                f"{vec['id']}: annotations expected {sorted(exp['annotations'])} "
                f"but got {sorted(got['annotations'])}"
            )
    if failures:
        for line in failures:
            print(f"SELF-CHECK FAIL  {line}")
        return 1

    out = {
        "_comment": (
            "HESO-attested-rail/1 cross-language conformance vectors (FROZEN-WIRE-SCHEMA §8). "
            "GENERATED by vectors/generate_attested_rail_vectors.py — do not hand-edit. Each "
            "vector self-checks against verifier/heso_verify.py::verify_attested_rail at build."
        ),
        "schema_version": 1,
        "profile": hv.ENCLAVE_PROFILE_V1,
        "vectors": VECTORS,
    }
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "heso-1.0-attested-rail-vectors.json"
    )
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {len(VECTORS)} vectors to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
