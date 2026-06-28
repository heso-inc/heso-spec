# Attested Rail (HESO/1 — attested-rail module)

**Status: Normative.** **Contract id: `heso-attested-rail/1` (Phase-0, FREEZE-ONCE).**

The **attested-enclave rail**: a way to prove that one agent action was egressed
from inside an *attested* confidential-compute enclave (AWS Nitro in Phase-0),
that its release was *promised* into an append-only window log, and that the
pinned enclave image was *registry-valid at mint time*. It adds two reserved
fields to the v2 [ActionReceipt](./action-receipt.md) — a **signed core**
(`content.enclave_egress`) and an **unsigned sidecar**
(`ActionReceipt.enclave_window_proofs`) — and a tri-state verifier (§6) that
returns **VALID / FAIL / WITHHELD** with a single `verdict_tag` (§7).

A 2026 receipt MUST verify against THIS document in 2036. Adding or renaming any
field after the cut is the `deny_unknown_fields`-breaking, golden-moving change
the freeze exists to prevent. Conformance is claimable per module: an
implementation MAY claim `action-receipt` without claiming `attested-rail`.

**Absent by default.** Both fields are `#[serde(default, skip_serializing_if =
"Option::is_none")]`. A pre-feature receipt omits them and canonicalizes
**byte-identically** to the [`action-receipt.md` §7](./action-receipt.md) golden
(`988baa2e…` metrics-free, `f599f21b…` standalone, every zero-seed golden
UNCHANGED) — there is NO `action_version` / `alg` bump. The presence of
`content.enclave_egress` is the **ONE** canonical discriminator that puts a
receipt on this rail.

> **Two canonical disciplines, never mixed in one artifact (§3).** **JCS (RFC
> 8785)** for everything that lives in the JSON receipt tree (signed
> `enclave_egress.*` and the unsigned `enclave_window_proofs.*`), via the single
> `heso_verify::canonical_bytes`. **Deterministic CBOR (RFC 8949 §4.2.1)** for the
> four signature/registry *preimages* that never appear verbatim in the JSON:
> `promise_sig`, `event_bytes`, `action_params_hash` params, and the in-`user_data`
> `EnclaveBootBindings`. Every CBOR preimage is **float-free**, so there is no
> cross-language float-canonicalization surface.

The reference verifier is `verifier/heso_verify.py::verify_attested_rail`; the
byte-exact preimage encoders are the same file's `det_cbor`, `promise_sig_preimage`,
`event_bytes_cbor`, `action_params_cbor`, `boot_bindings_cbor`, `hpke_info`,
`witness_key_id_hex`. The cross-language goldens are `vectors/round-trip-goldens.json`
(RT-1..10) and the tri-state corpus is `vectors/heso-1.0-attested-rail-vectors.json`.

---

## 1. Signed core — `content.enclave_egress`

`Option<EnclaveEgress>` on `ActionContent`, covered by the operator Ed25519
signature (domain `ACTION_SIGNING_DOMAIN = b"heso-action/v1\0"`) because it rides
inside `action_canonical_bytes(content)`. The whole core — including the nested
`promise_sig_b64` — is therefore strip-proof and swap-proof.

### 1.1 `EnclaveEgress` (`deny_unknown_fields`)

| Field | Type | Meaning |
|---|---|---|
| `event_id` | `string` | **THE JOIN KEY**: the consume-once egress event id (UUIDv4). Equals `event_bytes.event_id` and the Biscuit nonce. NOT a digest. |
| `content_digest` | `string` | **THE D1 ANCHOR**: 64-hex BLAKE3 of the canonical `event_bytes` (= `blake3(base64_decode(sidecar.event_bytes_b64))`). |
| `request_hash` / `response_hash` / `server_cert_chain_hash` | `string` | 64-hex BLAKE3. `server_cert_chain_hash` is the enclave-verified TLS chain (honest limit: not a replayable transcript). |
| `authorization_token` | `AuthorizationTokenRecord` | The H3 token leg, offline-verified (§6 TL + Check 5). |
| `window_commitment` | `Option<EnclaveWindowCommitment>` | The H6 silicon SCT promise. `Option` so a no-promise receipt is *representable* (PG-6 catches `None`); present on every well-formed enclave-grade receipt and byte-identical to a non-`Option` field when present. |
| `required` | `bool` | `true` ⇒ enclave-grade REQUIRED (fail-closed if absent/breached); `false` ⇒ ADVISORY. A witness-FALLBACK receipt sets `enclave_egress = None` entirely. |
| `profile` | `string` | The immortal contract id; Phase-0 `"heso-attested-rail/1"`. Unknown ⇒ **WITHHELD ALWAYS** (PG-2). |
| `min_verifier` | `u16` | Monotonic must-understand floor; Phase-0 `0`. `> supported` ⇒ WITHHELD (PG-3). |
| `evidence_type` | `string` | Vendor tag; Phase-0 `"aws-nitro-v1"`. Unknown ⇒ FAIL-on-required / WITHHELD-otherwise (PG-5). |
| `ext` | `Option<Extensions>` | The ONE criticality-governed carrier (§3.1). `None` in Phase-0 ⇒ zero bytes. |

### 1.2 `AuthorizationTokenRecord` (H3, `deny_unknown_fields`)

| Field | Type | Meaning |
|---|---|---|
| `format` | `string` | FROZEN `"biscuit-v3"` under this profile. Any other value ⇒ FAIL `EnclaveTokenMalformed` (TL-0). A genuinely newer token arrives under a bumped `profile`, already WITHHELD at PG-2. |
| `issuer_key_hash` | `string` | 64-hex **BLAKE3** of the Ed25519 root pubkey (NOT SHA-256). |
| `issuer_managed` | `bool` | `true` ⇒ HESO can forge (disclosed); `false` ⇒ BYOC. |
| `token_hash` | `string` | 64-hex BLAKE3 of the sealed Biscuit bytes. MUST equal `event_bytes.authorization_token` (Check 5 ⇒ else FAIL `EnclaveTokenBindingMismatch`). |
| `action_params_hash` | `string` | 64-hex BLAKE3 of the canonical-params CBOR (RT-3). MUST equal `event_bytes.action_params_hash` (Check 5 ⇒ else FAIL `EnclaveActionParamsMismatch`). |
| `expires_at` | `string` | RFC-3339/ISO-8601 ONLY. Verified vs `admitted_at`; `< admitted_at` ⇒ FAIL `EnclaveTokenExpired` (TL-2). |
| `revocation_id` | `string` | Lowercase hex of the Biscuit block-0 signature. Out-of-band/online revocation lookup ONLY ⇒ advisory `EnclaveRevocationAdvisory`, NEVER a core verdict. |
| `attenuated` | `bool` | Whether the token was caveat-narrowed before sealing. |

> **Offline-verified, not in-enclave-only.** Token expiry and the
> `token_hash` / `action_params_hash` congruence against the D1-anchored
> `event_bytes` are checked by the frozen verifier. Only **revocation** is left to
> an out-of-band lookup (a network-dependent list cannot be a deterministic offline
> tri-state).

### 1.3 `EnclaveWindowCommitment` (H6, `deny_unknown_fields`) + the `promise_sig` preimage

| Field | Type | Meaning |
|---|---|---|
| `boot_id` | `string` | Per-boot enclave-instance id (UUID, RFC 4122). |
| `window_id` | `u64` | Per-boot MONOTONIC window counter. `(boot_id, window_id)` names a window. |
| `admitted_at` | `string` | RFC-3339 UTC `Z` — the per-action #45 trusted-time. The **as-of / BREACHED clock + token-expiry anchor**. Lives ONLY here ⇒ a receipt with `window_commitment = None` has NO trusted-time anchor and is caught at PG-6 BEFORE any `admitted_at`-dependent check. |
| `max_merge_delay_secs` | `u32` | SECONDS (the unit is in the name). `BREACHED = trusted_now > parse_rfc3339(admitted_at) + Duration::seconds(max_merge_delay_secs)`. |
| `promise_sig_b64` | `string` | base64-STD DER ECDSA-P384 (ES384/SHA-384) by the per-boot app-key over the preimage below. |
| `boot_attestation_b64` | `string` | base64-STD COSE_Sign1 NSM doc. MUST equal every sidecar `EnclaveWindowProof.evidence` (PG-7). |

The **`promise_sig` preimage** is a deterministic-CBOR map of **6** entries (RT-2);
`event_id`/`content_digest` are pulled from the enclosing `EnclaveEgress`, not
duplicated. Emit order (all keys < 24 B ⇒ §4.2.1 = length-first here):

| # | key | value | source |
|---|---|---|---|
| 1 | `boot_id` | tstr (UUID) | window_commitment |
| 2 | `event_id` | tstr (UUID) | EnclaveEgress |
| 3 | `window_id` | uint (u64) | window_commitment |
| 4 | `admitted_at` | tstr (RFC-3339) | window_commitment |
| 5 | `content_digest` | tstr (64-hex) | EnclaveEgress |
| 6 | `max_merge_delay_secs` | uint (seconds) | window_commitment |

Sign = `ECDSA-P384(SHA-384(cbor_preimage))`, DER, base64. The signing key is
recovered ONLY from `boot_attestation_b64.user_data.EnclaveBootBindings.app_key_spki`
(§3.3) — never a free-floating field.

### 1.4 `GateDecision::EnclaveGrade` (golden-safe variant add)

The live `GateDecision` enum gains one `"enclave_grade"` variant. **Backend ingest
invariant (HTTP 422):** `PolicyOutcome.decision_path == EnclaveGrade ⇒
enclave_egress.is_some()`. This is ADVISORY to the verifier — the canonical
discriminator is `enclave_egress` PRESENCE, not the gate decision.

---

## 2. Unsigned sidecar — `ActionReceipt.enclave_window_proofs`

`Option<Vec<EnclaveWindowProof>>`, sibling of `transparency`, OUTSIDE `content`.
Attaching/sealing never touches a signed byte. **FLAT layout** (`deny_unknown_fields`);
default-build (NOT behind a `nitro` feature) so verifier surfaces decode it even
when enclave crypto is off.

### 2.1 `EnclaveWindowProof` (flat; optional legs absent-default)

| Field | Type | Meaning |
|---|---|---|
| `attestation_profile` | `string` | Open vendor profile (NO enum). Congruence vs signed `evidence_type` runs FIRST (Check 0). |
| `evidence` | `string` | base64-STD COSE_Sign1 NSM doc. MUST equal `window_commitment.boot_attestation_b64` (PG-7, pure string compare). |
| `window_root_hex` | `string` | 64-hex SHA-256 window root. |
| `root_sig_b64` | `string` | base64-STD DER ECDSA-P384 over the **32 raw** window-root bytes, by `app_key_spki`. |
| `merkle_path` | `Vec<MerkleStep>` | `leaf_hash(event_bytes) → window_root` (duplicate-last-on-odd). |
| `event_bytes_b64` | `string` | base64-STD of the canonical `event_bytes` (RT-8). `blake3(decode(.)) == content_digest` (D1). |
| `registry_entry_bytes` | `Option<string>` | base64-STD L4 Type-C entry (sans the `0x12` discriminator). |
| `inclusion_proof` | `Option<Vec<string>>` | base64-STD RFC-6962 sibling hashes of the registry leaf into `checkpoint`. |
| `registry_leaf_index` | `Option<u64>` | RFC-6962 leaf position of the Type-C registry leaf. **REQUIRED** to fold `leaf_hash_C` to `checkpoint.root` — the split-point path depends on `(registry_leaf_index, tree_size)`, so without it the fold is unimplementable and the leg would false-green a garbage `inclusion_proof`. Present-while-`None` ⇒ FAIL (Check 7). |
| `checkpoint` | `Option<string>` | C2SP signed-note text (L4 log key) the registry inclusion proves into; its body carries `tree_size` + `root`. |
| `policy_version` | `Option<u32>` | Compiled-in witness-policy version this proof resolves against. |
| `witness_checkpoint_b64` | `Option<string>` | base64-STD cosigned checkpoint. |
| `witness_cosignatures` | `Vec<WitnessCosig>` | ABSENT (not `[]`) when empty. |
| `ots_proof_b64` | `Option<string>` | Fire-and-forget OpenTimestamps; NEVER on the Check-6 critical path. |
| `window_root_inclusion_proof` | `Option<Vec<string>>` | RFC-6962 inclusion of THIS `window_root_hex` (the L4 Type-B leaf) into `witness_checkpoint_b64`. |
| `window_root_leaf_index` | `Option<u64>` | Leaf index of the Type-B leaf. |
| `window_seal_time_ms` | `Option<u64>` | #45 trusted-time (UNIX MILLIS) of the window seal — the Type-B leaf's `seal_time_ms`. REQUIRED to reconstruct `leaf_hash_B`; integrity comes from inclusion into the cosigned checkpoint, never a signature on the field. |
| `action_leaf_inclusion_proof` / `action_leaf_index` | `Option<…>` | Type-A carriers, RESERVED in Phase-0 (the verifier does NOT read them). |
| `profile` | `string` | Mirrors `enclave_egress.profile`. ANY deviation ⇒ FAIL `EnclaveContractProfileMismatch` (Check 0; sidecar has NO WITHHELD path). |
| `min_verifier` | `u16` | Mirrors `enclave_egress.min_verifier`. |
| `ext` | `Option<Extensions>` | ADVISORY-ONLY: the verifier ignores unknown keys + any `crit`, NEVER withholds. |

`tier` and `fetch_content_digest` are **inside** `event_bytes` (D1-bound), NOT
top-level sidecar fields.

The window-root-inclusion carrier (`window_root_inclusion_proof` +
`window_root_leaf_index` + `window_seal_time_ms`) and the registry carrier
(`registry_entry_bytes` + `inclusion_proof` + `registry_leaf_index` +
`checkpoint`) are each **all-or-nothing**: a partial carrier is non-provable.

### 2.2 `MerkleStep` (`deny_unknown_fields`)

| Field | Type | Meaning |
|---|---|---|
| `sibling_hex` | `string` | 64-hex (32 bytes). |
| `i_am_right` | `bool` | `true` ⇒ accumulator is the RIGHT child (sibling on the LEFT). NOT `right`. |

**Fold:** `acc = leaf_hash(event_bytes)`; per step `acc = i_am_right ?
node_hash(sibling, acc) : node_hash(acc, sibling)`; accept iff `acc ==
hex_decode(window_root_hex)`. The window tree is **duplicate-last-on-odd**; the L4
log is RFC-6962 **split-point** — distinct, never conflated.

---

## 3. Shared types & canonical encodings

### 3.1 `Extensions` — the ONE tolerant carrier (signed core + sidecar share it)

The **only** non-`deny_unknown_fields` type inside the JSON receipt tree.

| Field | Type | Meaning |
|---|---|---|
| `crit` | `Vec<u32>` | Must-understand keys. Signed-core only; ignored in the sidecar. |
| `values` | `BTreeMap<u32, JsonValue>` | Extension values. `u32` keys serialize as JSON string keys; JCS re-sorts by decimal-string. |

`None`/empty in Phase-0 ⇒ ZERO canonical bytes. In the SIGNED core, an unknown key
in `crit` ⇒ WITHHELD (PG-4). In the sidecar, `ext`/`crit` are advisory-only. The
key space is **entirely unsigned u32** — there is no negative key.

### 3.2 `WitnessCosig` (`deny_unknown_fields`)

| Field | Type | Meaning |
|---|---|---|
| `witness_name` | `string` | C2SP signed-note key name. |
| `key_id_hex` | `string` | 8-hex = `SHA-256(name ‖ 0x0A ‖ algo ‖ pubkey)[:4]`; `algo ∈ {0x04 ts-Ed25519, 0x06 ts-ML-DSA-44}`. |
| `cosig_line` | `string` | The literal C2SP tlog-cosignature signed-note line. |
| `timestamp_unix` | `u64` | Seconds; MUST equal the time in `cosig_line` and fall in the witness active window. |

The algo byte is the ONLY place the algorithm is encoded — recovered by recomputing
`key_id_hex` per the policy entry. There is NO separate `algo_byte` field.

### 3.3 `EnclaveBootBindings` — NSM `user_data` payload (CBOR)

Deterministic-CBOR map of 2 entries (RT-10), bound by the attestation signature.
**Emit order §4.2.1: `hpke_pubkey` (head `6B`) BEFORE `app_key_spki` (head `6C`)** —
the pinned Rust declaration order produces the same bytes. THREE boot keypairs:
RSA-2048 (KMS, in `attestation.public_key`) + X25519 HPKE (`hpke_pubkey`) + P-384
app-key (`app_key_spki`). The app-key is recovered from HERE, **never** from
`attestation.public_key`. Forward-growth is gated by PCR0 (any added field ⇒ new
enclave image ⇒ PCR0 mismatch ⇒ Check 4 FAIL).

### 3.4 HPKE info string (RT-7)

`info = b"HESO-enclave-v1\x00" ‖ pcr0` = **16 + 48 (full SHA-384 PCR0) = 64 bytes**.
A 32-byte PCR0 is REJECTED.

### 3.5 `event_bytes` inner CBOR (RT-8) — the D1-anchored body

`blake3(event_bytes_raw) == content_digest`. Carries `version` (=1, reserved-now at
zero cost), `tier` (1|2|3), the four hash fields, and `authorization_token` (=
`token_hash`) + `action_params_hash` so the token identity AND its committed params
are bound into the D1 digest and become offline-checkable for congruence (Check 5,
covering B6/B27). §4.2.1 emit order: `tier`, `version`, `event_id`, `request_hash`,
`response_hash`, `action_params_hash`, `authorization_token`,
`[fetch_content_digest (tier-3 only)]`, `server_cert_chain_hash`. Map header `A8`
(tier 1/2) or `A9` (tier 3).

### 3.6 `action_params_hash` params CBOR (RT-3)

`action_params_hash = blake3_hex(det_cbor(params_map))`, RFC 8949 §4.2.1, text keys
§4.2.1-ordered, recursive; value types text/bytes/uint/nint/bool/null; **floats
FORBIDDEN**. The raw params are NOT placed on the wire (privacy + size). The offline
verifier proves **congruence**: the operator-signed `action_params_hash` MUST equal
the `action_params_hash` bound into the D1-anchored `event_bytes` (Check 5).

### 3.7 Out-of-band pins (never receipt fields)

`ReferenceValues` (the SHA-384 PCR0/1/2/8 reference values, 48 bytes each) and
`PinnedNitroRoot` (the pinned AWS root DER + its SHA-256 fingerprint) are
distributed out-of-band (policy/CoRIM), never receipt fields. The verifier compares
by raw-byte equality after hex-decode. These are the trust anchors a stranger
supplies alongside the receipt.

---

## 4. L4 log wire — three leaf types

A single RFC-6962 / C2SP tlog-tiles append-only log. `leaf_hash(v) = SHA-256(0x00 ‖
v)`, `node_hash(l,r) = SHA-256(0x01 ‖ l ‖ r)`. The first byte of `leaf_bytes`
discriminates (distinct from RFC-6962 separators `0x00`/`0x01`):

| disc | type | bytes |
|---|---|---|
| `0x10` | Action / window-commitment (SCT analog) | `0x10 ‖ event_id[16] ‖ content_digest[32] ‖ boot_id[16] ‖ window_id[u64 BE] ‖ admitted_at_ms[u64 BE] ‖ max_merge_delay_secs[u32 BE]` (85, RESERVED in Phase-0). |
| `0x11` | Window-root (STH/seal analog) | `0x11 ‖ boot_id[16] ‖ window_id[u64 BE] ‖ seal_time_ms[u64 BE] ‖ window_root[32]` (65). |
| `0x12` | Enclave-release registry entry | `0x12 ‖ entry_schema_version[u8=0x01] ‖ pcr0[48] ‖ pcr1[48] ‖ pcr2[48] ‖ pcr8[48] ‖ valid_from_secs[u64 BE] ‖ valid_until_secs[u64 BE, 0=∞] ‖ repro_ref_len[u16 BE] ‖ repro_ref[UTF-8]` (211 + len). |

`leaf_hash_B = leaf_hash(Type-B bytes)`; `leaf_hash_C = leaf_hash(0x12 ‖
registry_entry_bytes)` (the sidecar omits the `0x12`; the verifier re-prepends it).
`repro_ref` canonical form `"git:<40-hex>:eif-sha256:<64-hex>"`.

**C2SP checkpoint note:** body `<origin>\n<tree_size>\n<base64std(root[32])>\n`,
blank line, sig lines `— <name> <base64std(key_hash[4] ‖ sig[64])>`. Both the
registry `checkpoint` (Check 7) and `witness_checkpoint_b64` (Check 6) are this
shape; the registry checkpoint's signature is the L4 LOG key (`0x01`), the witness
checkpoint additionally carries cosignature lines (`0x04`/`0x06`).

---

## 5. Extension registry — entirely unsigned u32 space

`Extensions` keys are `u32`; there is NO negative band. Key `0` is reserved.

| range (dec) | class | introduction | critical-allowed |
|---|---|---|---|
| 1–99 | Core | profile bump + heso-spec + golden vector | yes |
| 100–9999 | HESO-registered | heso-spec registry + golden vectors before first use | yes |
| 10000–2147483647 | Experimental | none required | **FORBIDDEN in crit** |
| 2147483648–4294967295 | Private/vendor | unreserved | **FORBIDDEN in crit** |

Retired keys are permanently reserved (protobuf field-number rule). Introducing a
critical ext in 1–9999 MUST bump `min_verifier > deployed VERIFIER_VERSION` first.
**Phase-0 launch registry is EMPTY** — every Phase-0 `ext` is `None`, and any key
in a signed `crit` list is must-understand-but-unknown ⇒ WITHHELD (PG-4).

---

## 6. Verifier tri-state flow (identical on every surface)

Runs only when `content.enclave_egress` is `Some` (else the receipt is a
witness-mode / fallback receipt that [`action-receipt.md`](./action-receipt.md)
governs). **Tri-state: VALID** (green) / **FAIL** (affirmatively wrong) /
**WITHHELD** (cannot judge safely). Order, short-circuiting on the first terminal
verdict:

> **PG-1..PG-7 → TL-0..TL-2 → PG-equiv → deferred-proof gate → per-proof [Check 0
> → Checks 1–4 → Check 5] → Check 6 → Check 7 (both over `enclave_window_proofs[0]`)
> → combined VALID.**

**PG (pre-gate).**
- **PG-2** `profile` unknown ⇒ WITHHELD `EnclaveUnsupportedContract` (ALWAYS, regardless of `required`).
- **PG-3** `min_verifier > VERIFIER_VERSION` ⇒ WITHHELD `EnclaveVersionTooNew`.
- **PG-4** unknown key in signed `ext.crit` ⇒ WITHHELD `EnclaveUnknownCriticalExtension:{key}`; unknown key NOT in crit ⇒ ignored. Sidecar `ext`/`crit` ⇒ ignored.
- **PG-5** `evidence_type` unknown ⇒ `required` ? FAIL : WITHHELD `EnclaveAttestationUnsupportedProfile`.
- **PG-6** `window_commitment == None` (no signed promise ⇒ no `admitted_at` anchor; runs BEFORE any `admitted_at`-dependent check) ⇒ `required` ? FAIL : WITHHELD `EnclaveProofAbsent`.
- **PG-7** any sidecar `evidence != window_commitment.boot_attestation_b64` ⇒ FAIL `EnclaveBootAttestationMismatch` (ranges over the whole Vec).

**TL (authorization-token signed-core leg)** — needs only signed-core fields, with
`admitted_at` guaranteed by PG-6, so an affirmatively-bad token short-circuits
before any proof is read.
- **TL-0** `format != "biscuit-v3"` ⇒ FAIL `EnclaveTokenMalformed`.
- **TL-1** `expires_at` not RFC-3339 ⇒ FAIL `EnclaveTokenMalformed`.
- **TL-2** `expires_at < admitted_at` ⇒ FAIL `EnclaveTokenExpired`.

**PG-equiv.** ≥2 sidecar entries with identical `evidence` (same boot) but differing
`window_root_hex` ⇒ FAIL `EnclaveEquivocationDetected` (one boot must commit to one
window root).

**Deferred-proof gate (the state machine).** `window_commitment` is `Some` here. The
verifier FIRST branches on whether the receipt carries any `EnclaveWindowProof`. The
lower-bound cross-check `attestation.timestamp > admitted_at ⇒ FAIL
EnclaveTimestampAnomaly` applies in BOTH branches.

- **PROOF-ABSENT (pending).** Evaluate the stapled promise from
  `window_commitment.boot_attestation_b64`. **Normative collapse (this branch only):**
  ANY promise-evaluation failure — bad COSE sig, unpinned root, missing/malformed
  binding, OR a bad PCR0 in the stapled attestation, OR a bad `promise_sig` — collapses
  to a single deterministic **FAIL `EnclaveWindowPromiseInvalid`**. On a well-formed
  promise:
  - `trusted_now ≤ admitted_at + max_merge_delay_secs` ⇒ **WITHHELD `EnclaveWindowPending`**.
  - `trusted_now > admitted_at + max_merge_delay_secs` ⇒ **FAIL `EnclaveWindowPromiseBreached`**.
- **PROOF-PRESENT (sealed).** Do NOT run the collapse; run per-proof Check 0, Checks
  1–5 GRANULARLY, then Check 6, then Check 7. A bad PCR0 here surfaces as the granular
  **FAIL `EnclavePcr0Mismatch`** (Check 4), NOT the collapse.

This is what makes a tampered-PCR0-with-proof (`EnclavePcr0Mismatch`) and a
promise-only-bad-PCR0 (`EnclaveWindowPromiseInvalid`) BOTH satisfiable with
deterministic single tags.

**Check 0 (congruence — runs BEFORE the `attestation_profile` dispatch).** This is the
**two-discriminator profile rule**:
- **C0.1** signed `evidence_type != attestation_profile` (vendor tag) ⇒ FAIL `EnclaveAttestationProfileMismatch`.
- **C0.2** sidecar `profile != enclave_egress.profile` (contract id) ⇒ FAIL `EnclaveContractProfileMismatch`. ANY deviation — a known-different value OR an unknown value — is non-congruent; the sidecar has NO WITHHELD path (a `/1` verifier cannot deterministically route one unknown sidecar profile to FAIL and another to WITHHELD). WITHHELD-on-unknown applies only to the SIGNED-core profile via PG-2.

**Checks 1–4 (attestation, dispatched by `attestation_profile` after Check 0).**
- **C1** COSE parse fail ⇒ FAIL `EnclaveAttestationMalformed:{detail}`; alg ≠ ES384 ⇒ FAIL `EnclaveAttestationWrongAlgorithm`.
- **C2** cabundle root SHA-256 fpr ≠ pinned AWS root ⇒ FAIL `EnclaveChainNotPinnedRoot` (root NEVER read from the bundle).
- **C3** cert not signed by issuer ⇒ FAIL `EnclaveChainInvalid:{detail}`; cert invalid at `attestation.timestamp` ⇒ FAIL `EnclaveCertExpiredAtAttestation:{i}`; cert invalid at `admitted_at` ⇒ FAIL `EnclaveCertExpiredAtAdmittedAt:{i}`; issuer missing `cA:TRUE` ⇒ FAIL `EnclaveIssuerNotCa:{i}`; COSE ES384 sig invalid ⇒ FAIL `EnclaveAttestationSignatureInvalid`.
- **C4** `pcrs[0] ≠` pinned PCR0 ⇒ FAIL `EnclavePcr0Mismatch`; `app_key_spki` absent/malformed ⇒ FAIL `EnclaveAppKeyBindingMissing`; `hpke_pubkey` absent ⇒ FAIL `EnclaveHpkeBindingMissing`; `attestation.public_key` (KMS) absent ⇒ FAIL `EnclaveKmsKeyBindingMissing`. The app-key for Check 5 comes from `app_key_spki`, NEVER `attestation.public_key`.

**Check 5 (window binding — REAL crypto over the wire bytes).**
- `BLAKE3(decode(event_bytes_b64)) ≠ content_digest` ⇒ FAIL `EnclaveContentDigestMismatch` (D1).
- `authorization_token.action_params_hash ≠ event_bytes.action_params_hash` ⇒ FAIL `EnclaveActionParamsMismatch`.
- `authorization_token.token_hash ≠ event_bytes.authorization_token` ⇒ FAIL `EnclaveTokenBindingMismatch`.
- `root_sig_b64` invalid under `app_key_spki` over `window_root_hex` ⇒ FAIL `EnclaveRootSignatureInvalid`.
- Merkle fold ≠ `window_root_hex` ⇒ FAIL `EnclaveInclusionProofInvalid`.

**Proof selector for Checks 6–7 (normative).** Checks 0–5 run per-proof over EVERY
`enclave_window_proofs` entry. Checks 6 (witness) and 7 (registry) are single-proof
legs: when the receipt carries 2+ entries, they evaluate against
`enclave_window_proofs[0]` — the FIRST sidecar entry — and no other. PG-equiv already
forbids two entries that share `evidence` but disagree on `window_root_hex`, so the
first entry is a well-defined choice; pinning index `0` normatively guarantees two
conformant verifiers reach the SAME witness/registry verdict on the SAME receipt rather
than silently selecting different proofs.

**Check 6 (witness quorum — no network).**
- Unknown `policy_version` ⇒ WITHHELD `EnclaveWitnessPolicyUnknown` (`None` ⇒ the launch advisory policy `threshold=1, external=0`).
- `witness_checkpoint_b64` malformed / log-key sig invalid ⇒ FAIL `EnclaveWitnessCheckpointInvalid`.
- **§5.2b window-root inclusion** (required whenever a checkpoint is present, so the VALID path can never green-light cosigs over a checkpoint that does not contain this window's root):
  - checkpoint present AND the carrier (`window_root_inclusion_proof` + `window_root_leaf_index` + `window_seal_time_ms`) absent/partial ⇒ WITHHELD `EnclaveWindowRootInclusionMissing`.
  - carrier present but the reconstructed Type-B leaf does NOT prove into the checkpoint at `window_root_leaf_index` ⇒ FAIL `EnclaveWindowRootInclusionInvalid`.
- per `WitnessCosig`: unknown name / bad `key_id_hex` / bad sig / timestamp outside the active window ⇒ FAIL `EnclaveWitnessCosigInvalid`.
- quorum verdict: cosigs empty AND no checkpoint AND `require_external_min == 0` ⇒ leg VALID + annotation `EnclaveWitnessedSkipped`; cosigs empty AND `require_external_min ≥ 1` ⇒ WITHHELD `EnclaveWitnessQuorumNotMet`; verified `< threshold` or `< require_external_min` ⇒ WITHHELD `EnclaveWitnessQuorumNotMet`; all verify AND quorum met AND §5.2b passed ⇒ leg VALID `EnclaveWitnessedGreen`.

**Check 7 (verify-as-of-mint / release registry — ADVISORY-GATING).** Absent NEVER
gates; present-but-invalid FAILS; the whole verdict is frozen NOW so no later check
can split VALID(old)→FAIL/WITHHELD(new) (a future gating-on-absence semantics arrives
only under a bumped `profile`, already WITHHELD at PG-2).
- `registry_entry_bytes` absent (⇒ whole carrier absent) ⇒ leg VALID + advisory `EnclaveRegistryUnresolved`.
- present but the carrier is partial, OR the `checkpoint` log-key sig invalid, OR the Type-C leaf does NOT fold to `checkpoint.root` at `registry_leaf_index` ⇒ FAIL `EnclaveRegistryProofInvalid`. The index-driven fold is what makes a forged `inclusion_proof` FAIL instead of false-greening.
- inclusion valid but `mint_time_secs` (from `admitted_at`) outside `[valid_from_secs, valid_until_secs]` (`valid_until == 0` ⇒ ∞) ⇒ FAIL `EnclaveRegistryStale` (anti-backdating).
- inclusion valid + time-bounds satisfied ⇒ leg VALID + annotation `EnclaveRegistryResolved`.

**Combined VALID.** TL passes AND Check 0 passes AND Checks 1–5 pass AND the Check-6
leg is VALID (`EnclaveWitnessedGreen` OR `EnclaveWitnessedSkipped` under advisory
policy) AND the Check-7 leg is VALID (`EnclaveRegistryResolved` OR absent-advisory
`EnclaveRegistryUnresolved`) ⇒ **`EnclaveValid`**. Checks 1–5 pass AND Check 6
WITHHELD (incl. `EnclaveWindowRootInclusionMissing`) ⇒ WITHHELD.

`mint_time` / as-of for BREACHED, token-expiry, registry-window and verify-as-of-mint
is `admitted_at` (#45). `attestation.timestamp` is used ONLY for cert-validity
anchoring and the `≤ admitted_at` lower-bound cross-check.

---

## 7. `verdict_tag` catalogue

The single wire owner per outcome. The reference Python verifier returns
`{"state", "tag", "annotations"}`; the `tag` strings below are the same names every
surface emits.

**VALID:** `EnclaveValid`.

**WITHHELD:** `EnclaveUnsupportedContract` · `EnclaveVersionTooNew` ·
`EnclaveUnknownCriticalExtension:{key}` · `EnclaveAttestationUnsupportedProfile`
(required=false) · `EnclaveProofAbsent` (required=false) · `EnclaveWindowPending` ·
`EnclaveWindowRootInclusionMissing` · `EnclaveWitnessPolicyUnknown` ·
`EnclaveWitnessQuorumNotMet`.

**FAIL:** `EnclaveAttestationUnsupportedProfile` (required=true) · `EnclaveProofAbsent`
(required=true) · `EnclaveBootAttestationMismatch` · `EnclaveEquivocationDetected` ·
`EnclaveWindowPromiseInvalid` · `EnclaveWindowPromiseBreached` ·
`EnclaveTimestampAnomaly` · `EnclaveTokenMalformed` · `EnclaveTokenExpired` ·
`EnclaveAttestationProfileMismatch` · `EnclaveContractProfileMismatch` ·
`EnclaveAttestationMalformed:{detail}` · `EnclaveAttestationWrongAlgorithm` ·
`EnclaveChainNotPinnedRoot` · `EnclaveChainInvalid:{detail}` ·
`EnclaveCertExpiredAtAttestation:{i}` · `EnclaveCertExpiredAtAdmittedAt:{i}` ·
`EnclaveIssuerNotCa:{i}` · `EnclaveAttestationSignatureInvalid` · `EnclavePcr0Mismatch`
· `EnclaveAppKeyBindingMissing` · `EnclaveHpkeBindingMissing` ·
`EnclaveKmsKeyBindingMissing` · `EnclaveContentDigestMismatch` ·
`EnclaveActionParamsMismatch` · `EnclaveTokenBindingMismatch` ·
`EnclaveRootSignatureInvalid` · `EnclaveInclusionProofInvalid` ·
`EnclaveWindowRootInclusionInvalid` · `EnclaveWitnessCheckpointInvalid` ·
`EnclaveWitnessCosigInvalid` · `EnclaveRegistryProofInvalid` · `EnclaveRegistryStale`.

**Annotations (non-verdict):** `EnclaveWitnessedGreen` · `EnclaveWitnessedSkipped` ·
`EnclaveRegistryResolved` · `EnclaveRegistryUnresolved` · `EnclaveAdvisory:{msg}` ·
`EnclaveRevocationAdvisory`.

`EnclaveProofAbsent` and `EnclaveAttestationUnsupportedProfile` are the two tags
that appear in BOTH WITHHELD (required=false) and FAIL (required=true), split
exactly by `required`.

**False-green invariant (load-bearing).** An old verifier facing a newer/unknown
receipt returns WITHHELD or FAIL, NEVER VALID on changed semantics. Every FAIL/WITHHELD
outcome any conformance vector expects already has a rule + tag here at freeze time —
a check added later would make an old distributed verifier return VALID where a new
one returns FAIL on the SAME receipt. This is why the registry leg (Check 7) is frozen
NOW as advisory-absent ⇒ VALID + present-invalid ⇒ FAIL, not added later.

---

## 8. Conformance & honest limits

**Round-trip byte-identity (RT-1..10, `vectors/round-trip-goldens.json`).** The four
deterministic-CBOR preimages, the JCS of the signed core / token / sidecar, and the
HPKE/witness-key/base64 helpers each reproduce the Rust kernel golden byte-for-byte.
This is the neutrality proof — a Python stranger computes the same operator-signed
bytes the Rust enclave did — and is asserted by `conformance_check.py` and
`vectors/test_attested_rail.py`.

**Tri-state corpus (`vectors/heso-1.0-attested-rail-vectors.json`).** 54 tri-state
vectors (A valid · B forgery/FAIL · C lifecycle · D forward-compat & congruence · E
registry) plus the I1 impl-discipline test, each `{receipt, ctx, expected:{state,tag}}`.
Every vector verifies to its expected verdict on the reference verifier; B/C/D/E
exercise each FAIL/WITHHELD branch and I1 asserts the app-key is sourced from
`app_key_spki` (a real RSA key in `attestation.public_key` cannot verify the P-384
`root_sig`, so a mis-sourcing verifier would FAIL where the correct one returns VALID).

**What is REAL in the reference verifier.** Every leg that is a pure function of bytes:
the BLAKE3 `content_digest` binding, the params/token congruence over the decoded
`event_bytes`, the SHA-256 window-tree fold, the index-driven RFC-6962 Type-B/Type-C
inclusion folds, the RFC-3339 time math, the profile/version/crit/evidence gating, the
equivocation check, and the **ES384 `root_sig`/`promise_sig`** signatures. The
adversarial tests confirm these are live: tampering the window root, the registry
proof, the event bytes, or the witness pubkey each flips VALID to the precise FAIL tag.

**Modeled signature boundaries (honest limit — Grade-0).** The REFERENCE verifier in
`verifier/heso_verify.py` does NOT re-execute THREE signature-bearing crypto boundaries;
each is supplied as an out-of-band FACT in `ctx` (a Grade-0 model), not re-derived from
the wire bytes. This is a property of the REFERENCE implementation only — the §6 flow
STILL REQUIRES a PRODUCTION verifier to verify each of these signatures for real, and
the FAIL tags §6 emits (`EnclaveAttestationSignatureInvalid`,
`EnclaveWitnessCosigInvalid`, `EnclaveWitnessCheckpointInvalid`,
`EnclaveRegistryProofInvalid`) are the verdicts a real verifier MUST reach on a bad
signature.

1. **AWS-Nitro COSE_Sign1 / cabundle cert-chain / PCR-extraction** (Checks 1–4). A live
   enclave and the AWS root CA are needed to parse the NSM document, so the corpus carries
   the facts that parser WOULD yield — `cose_sig_valid`, `root_fpr`, `chain_valid`,
   `pcr0`, `app_key_spki`, … — keyed by the opaque `evidence` string
   (`ctx["attestations"]`). The live Nitro parser is a separate deliverable.
2. **Witness cosignature raw-signature bytes** (Check 6). `_enclave_cosig_ok` performs the
   REAL structural checks — `key_id_hex` recompute from the policy entry and the cosig
   active-window time bounds — but does NOT Ed25519/ML-DSA-verify the `cosig_line` bytes;
   validity is modeled via `ctx["invalid_cosigs"]`. BOTH the Ed25519 cosig-line
   byte-verification AND ML-DSA-44 support are the Phase-6 follow-up (once the C2SP
   note-verification library is wired). Vectors B22/B23/B25 exercise this rejection path.
3. **Checkpoint log-key signature validity** (Checks 6 and 7). `_checkpoint_from_b64`
   PARSES the C2SP signed note but does NOT verify the witness/registry log key's
   signature over it; validity is modeled via `ctx["invalid_checkpoints"]`.

Every OTHER leg in this module — every leg that is a pure function of the wire bytes,
including the ES384 `root_sig`/`promise_sig` signatures listed above — is byte-real, NOT
modeled. The RT-1..10 byte-identity claim is unaffected: those goldens cover the
operator-signed preimages, not the witness cosig or checkpoint bytes.

**Operational residual.** A `CHARGE_CONFIRMED_SEAL_FAILED` backend state is NOT a wire
field; such a receipt has no `enclave_egress` proof ⇒ the verifier WITHHELDs (the
action fired; the missing proof is an operational residual, not wrongdoing).
