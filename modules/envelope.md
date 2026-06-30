# HESO/1 — Envelope Module (in-toto Statement + DSSE)

**Status: Normative.** Key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY are to be interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

The envelope module specifies how a HESO [Action Receipt](./action-receipt.md) is wrapped as an **in-toto Statement** carrying a HESO/1 `predicateType`, and how that Statement is signed inside a **DSSE (Dead Simple Signing Envelope) v1.0.2** envelope.

HESO does **not** invent a signing envelope. It adopts in-toto + DSSE so standard
tooling can verify that a Statement body was signed with the expected key. HESO
trust still requires HESO-specific receipt verification: canonical receipt hash,
signature roles, chain/quorum/time rules when present, and taxonomy
re-derivation for ERT receipts.

This module is conformance-claimable independently of `time-anchor`, `quorum`, and `transparency`. The single load-bearing, most error-prone rule in the entire standard — the **PAE byte formula** ([§4](#4-the-pae-byte-formula-normative)) — is specified here exactly and is pinned by the `dsse-pae` conformance vector. Every conformant signer and every clean-room verifier MUST implement it byte-for-byte.

---

## 1. The verification contract

For a relying party, verifying a DSSE-wrapped HESO receipt has two layers:

1. **Verify the DSSE envelope** — recompute the PAE ([§4](#4-the-pae-byte-formula-normative)) over the raw Statement body and check the signature(s) against the signer's public key(s) ([§5](#5-verification)). Standard DSSE tooling can do this.
2. **Verify the HESO predicate** — run the [action-receipt](./action-receipt.md) verifier over the Statement predicate and, when the receipt carries ERT, re-derive classification against the pinned taxonomy bundle hash. If the deployment requires transparency, verify the inclusion proof per [transparency.md](./transparency.md).

DSSE establishes authenticity of the Statement bytes. It does not prove the HESO
receipt is internally valid, correctly classified, or log-included.

---

## 2. The in-toto Statement

An Action Receipt is carried as the **predicate** of an [in-toto v1 Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "<action subject>", "digest": { "blake3": "<action_hash hex>" } }
  ],
  "predicateType": "https://hesohq.dev/ActionReceipt/v2",
  "predicate": { /* the HESO/1 receipt body — structure governed by the taxonomy */ }
}
```

Normative rules:

- `_type` MUST be the literal `https://in-toto.io/Statement/v1`.
- `subject` MUST be a non-empty array. Each entry MUST carry a `digest` map containing the key `blake3` whose value is the receipt's `action_hash` as 64-character lowercase hex (the same content hash that is the [transparency](./transparency.md) leaf value). The `name` is an implementation-chosen label for the action subject.
- `predicateType` MUST be a stable HESO-owned URI. For the default v2 receipt it is `https://hesohq.dev/ActionReceipt/v2`. The legacy v1 receipt ([action-receipt-v1.md](./action-receipt-v1.md)) uses `https://hesohq.dev/ActionReceipt/v1`.
- `predicate` MUST be the HESO/1 receipt body. **Its schema IS the destructive-primitive taxonomy** — the predicate carries the structural classification (`move-value` / `destroy` / `change-authority` / `disclose` / `execute`) defined in [taxonomy.md](./taxonomy.md). The taxonomy is the open, normative schema of the predicate; this module does not restate it.
- The predicate MUST pin the taxonomy bundle hash it was classified under.
  Verification of the predicate's classification is always against that pinned
  bundle, never the latest. The DSSE signature in this module is independent of
  the taxonomy version; it covers whatever body bytes are present.

The `predicateType` URI and its predicate schema are a **hard compatibility boundary**: once an external verifier ships against `https://hesohq.dev/ActionReceipt/v2`, that v2 predicate schema MUST NOT change incompatibly. A change is a new `predicateType` (e.g. `/v3`), with old and new coexisting.

---

## 3. The DSSE envelope

The Statement is the **body**; DSSE is the **signing envelope** around it ([DSSE v1.0.2 spec](https://github.com/secure-systems-lab/dsse/blob/v1.0.0/envelope.md)):

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64(Statement)>",
  "signatures": [
    { "keyid": "<signer key id>", "sig": "<base64(signature)>" }
  ]
}
```

Normative rules:

- `payloadType` MUST be the fixed string `application/vnd.in-toto+json` for an in-toto Statement.
- `payload` MUST be the **standard base64** (RFC 4648 §4, with padding) encoding of the **raw serialized Statement body** ([§2](#2-the-in-toto-statement)). Base64 is **transport-only**; the signature does **not** cover the base64 text (see [§4](#4-the-pae-byte-formula-normative)).
- `signatures` MUST be a non-empty array. Each entry MUST carry `sig` = standard base64 of the raw signature bytes, and SHOULD carry `keyid` identifying the signing key. A verifier MUST NOT trust `keyid` as a key source on its own; it is a hint for key selection only.
- The serialized Statement body — the exact bytes that base64-decode out of `payload` — is the canonical object the signature is computed over (via PAE). A verifier MUST sign/verify over those decoded bytes, NOT over a re-serialization of the parsed JSON. There is exactly **one** authoritative body byte-string per envelope: the one in `payload`.

> **No algorithm agility.** DSSE has no in-band algorithm/`crit`/`b64` negotiation to abuse. The signature suite (Ed25519 with `verify_strict`, matching the receipt signer) is fixed by the surrounding HESO/1 profile, not negotiated in the envelope.

---

## 4. The PAE byte formula (NORMATIVE)

DSSE signs the **Pre-Authentication Encoding (PAE)** of the body — **not** the raw JSON alone, and **not** the base64 transport form. This is the single most error-prone byte rule in HESO/1. It MUST be implemented identically by the kernel signer, the clean-room Python verifier, and the WASM verify surface, or signatures created by one will not verify in another and the byte-identical-verifier trust claim collapses.

### 4.1 The formula

```
PAE(type, body) =
      "DSSEv1"          the 6 ASCII bytes  0x44 0x53 0x53 0x45 0x76 0x31
    ++ SP               one space, 0x20
    ++ LEN(type)        byte-length of `type`, ASCII decimal, NO leading zeros
    ++ SP               one space, 0x20
    ++ type             the payloadType UTF-8 bytes: application/vnd.in-toto+json
    ++ SP               one space, 0x20
    ++ LEN(body)        byte-length of the RAW body, ASCII decimal, NO leading zeros
    ++ SP               one space, 0x20
    ++ body             the RAW, pre-base64 serialized Statement bytes
```

Each term, stated as bytes:

1. The 6 ASCII bytes of the string `DSSEv1` (`0x44 0x53 0x53 0x45 0x76 0x31`).
2. A single `SP` byte (`0x20`).
3. `LEN(type)` — the byte-length of `type` rendered as ASCII decimal with **NO leading zeros** (e.g. `28`, not `028`).
4. A single `SP` byte (`0x20`).
5. `type` — the `payloadType` bytes, UTF-8: `application/vnd.in-toto+json` (28 bytes).
6. A single `SP` byte (`0x20`).
7. `LEN(body)` — the byte-length of the **RAW** body rendered as ASCII decimal with **NO leading zeros**.
8. A single `SP` byte (`0x20`).
9. `body` — the **RAW serialized Statement bytes**, exactly as they appear before base64 encoding into `payload`.

Definitions:

- `SP` is a single `0x20` byte. No other whitespace is permitted between fields, and there is no trailing byte after `body`.
- `LEN(x)` is the byte-length (not character count) of `x` as ASCII decimal digits, with **no leading zeros**. `LEN` of an empty string is the single byte `0`.
- `type` is the UTF-8 bytes of `payloadType`.
- `body` is the **raw serialized Statement** — the bytes *before* base64 encoding, byte-for-byte identical to what base64-decoding `payload` yields. No re-canonicalization, no re-indentation, no added or stripped newline.

### 4.2 The signature

```
SERIALIZED_BODY = the raw bytes that base64-decode out of envelope.payload
signature       = Sign( PAE( UTF8("application/vnd.in-toto+json"), SERIALIZED_BODY ) )
```

The signature is computed over `PAE(payloadType, raw_body)`. The envelope then base64-encodes `raw_body` into `payload` and base64-encodes `signature` into `sig` **purely for JSON transport**.

A signer MUST NOT sign over the base64 text, MUST NOT sign over the raw JSON without the PAE framing, and MUST NOT sign over a re-serialized form of the parsed Statement. Any of these breaks interop and the `dsse-pae` vector catches it.

### 4.3 Worked byte intuition

For `payloadType = application/vnd.in-toto+json` (28 bytes) and a body of `B` bytes, the PAE pre-image begins with the literal ASCII:

```
DSSEv1 28 application/vnd.in-toto+json <LEN(B)> <body...>
```

— where each gap above is a single `0x20`, `<LEN(B)>` is `B` in ASCII decimal with no leading zeros, and `<body...>` is the raw body bytes. The `dsse-pae` conformance vector ([§6](#6-conformance)) pins the exact pre-image bytes and the signature for a known Statement.

### 4.4 Why every implementation MUST be byte-identical

The kernel signer (`heso-action/export/dsse`), the clean-room Python verifier, and the WASM verify surface MUST all produce the identical PAE pre-image byte-for-byte. PAE is small but unforgiving — a **leading zero in `LEN`**, **signing over base64**, or a **stray newline in `body`** all silently break interop while looking correct in isolation. The guarantees that hold this together:

1. **One reference implementation.** PAE lives in the Rust kernel; SDKs should
   bind to that implementation or match the conformance vector exactly.
2. **A clean-room cross-check.** The Python verifier implements PAE *independently* and MUST agree — proving the formula is implementable from this spec, not just copyable from one codebase.
3. **A golden vector.** `dsse-pae` pins the exact PAE pre-image bytes + signature for a known Statement, so any third party and CI confirm their implementation matches the published bytes before claiming conformance.

---

## 5. Verification

To verify a DSSE-wrapped HESO receipt, a verifier MUST, in order:

1. **Decode the body.** Base64-decode `envelope.payload` to the raw body bytes. Use these decoded bytes for everything that follows; do **not** re-serialize the parsed JSON.
2. **Recompute PAE.** Compute `PAE(envelope.payloadType, raw_body)` per [§4](#4-the-pae-byte-formula-normative). `payloadType` MUST be `application/vnd.in-toto+json`.
3. **Verify signature(s).** For each accepted signer key, base64-decode the corresponding `sig` and verify it over the recomputed PAE using the fixed suite (Ed25519 `verify_strict`). Accept according to the surrounding profile's signer policy (single-signer, or k-of-n where the `quorum` module applies). A verifier MUST reject if no accepted signature verifies.
4. **Parse the Statement.** Confirm `_type` is `https://in-toto.io/Statement/v1` and `predicateType` is an accepted HESO/1 URI.
5. **(Receipt-level checks.)** Hand the predicate to the [action-receipt](./action-receipt.md) verify order (canonicalization → fingerprint → signature → chain link → redaction reveal) and, where required, the [transparency](./transparency.md) inclusion proof. DSSE establishes *authenticity of the body*; receipt-level verification establishes *correctness of the receipt*.

A verifier MUST treat any of the following as a verification failure: a malformed envelope, a missing/empty `signatures`, an unexpected `payloadType`, a PAE that no accepted signature covers, or a `_type`/`predicateType` outside the accepted set.

---

## 6. Conformance

This module is conformant when (a) this normative spec defines it, (b) the
`dsse-pae` golden vector covers it, and (c) at least one clean-room
implementation independent of the Rust kernel passes that vector. The
`dsse-pae` vector contains a golden Statement, its exact PAE pre-image bytes, the
raw signature, and the assembled DSSE envelope; it is regenerated from the
reference implementation in CI and the build fails on any drift.

---

## 7. Relationship to legacy exports

The kernel additionally emits legacy COSE/CBOR exports. Those are an **export
format**, not the canonical signing envelope. The DSSE envelope defined here is
the canonical on-the-wire wrapper; both forms are kept byte-stable and
vector-backed during the transition.

---

## 8. Pointers

- [action-receipt.md](./action-receipt.md) — the receipt that becomes the Statement predicate; its verify order runs after DSSE verification.
- [taxonomy.md](./taxonomy.md) — the predicate schema. Canonical home of the destructive-primitive classification; never restated here.
- [transparency.md](./transparency.md) — the inclusion proof that pairs with DSSE to complete the two-check verification contract.
- [`../vectors/`](../vectors/) — the conformance vectors, including `dsse-pae`.
