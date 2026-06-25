# ActionReceipt (HESO/1 — core module)

**Status: Normative**

The wire format and verification rule for a **HESO ActionReceipt** — a signed
statement that an AI agent's operator took a specific action under policy, and,
when the action was risk-gated, that an authorized human approved it. This module
specifies the **v2 default** receipt: its envelope, signed content, the
canonicalization / hashing / signing rule, field redaction, and the verify order.

This document is the **independent verification contract**: holding a receipt,
the operator's (and, for a gated action, the approver's) public key, and this
spec, anyone can decide offline whether the receipt is valid — no network, no
clock, no trust beyond the public keys, and without any HESO source. The Rust
reference implementation is `heso-action` (`receipt.rs`, `verify.rs`); the
clean-room second implementation is the open verifier (see
[conformance-and-envelope](../../redesign/standard/conformance-and-envelope.md)).

This module is the **spine** that the sibling modules attach to:

- [`action-receipt-v1.md`](./action-receipt-v1.md) — the frozen v1 suite, kept so
  receipts already minted under v1 verify forever.
- [`chain.md`](./chain.md) — the BLAKE3 per-session chain (a signed-content block
  on the receipt).
- [`time-anchor.md`](./time-anchor.md) — the RFC-3161 trusted-time anchor.
- [`quorum.md`](./quorum.md) — k-of-n (L1-quorum) co-signature.
- [`envelope.md`](../../redesign/standard/conformance-and-envelope.md) — the
  in-toto Statement + DSSE binding that wraps the receipt.

Conformance is claimable **per module**: an implementation MAY conform to
`action-receipt` (this module) without claiming `chain`, `time-anchor`, or
`quorum`.

> **Scope — what an ActionReceipt proves.** It proves the operator signed this
> exact action under this exact policy decision, and (at L1) that an authorized
> human approver co-signed the **same** bytes. It does **NOT** prove the action's
> *outcome* was correct or that a tool returned the truth — that is unprovable
> from the artifact (HESO/1.0 §0.1, consistency-vs-truth). An ActionReceipt is an
> **authorization-and-gate** record: "this action was captured, evaluated against
> policy, gated, (optionally) human-approved, and signed" — not "this action did
> the right thing."

---

## 1. Suite & versioning

The `alg` tag denotes the **full cryptographic suite**, not just the signature
scheme. v2 is a deliberate suite bump over v1.

| Tag | v1 | v2 (this module) |
|---|---|---|
| `alg` (envelope) | `heso-action/v1+ed25519` | `heso-action/v2+ed25519` |
| `content.action_version` | `heso-action/1.0` | `heso-action/2.0` |

| Component | v2 value |
|---|---|
| Canonicalization | RFC 8785 (JCS), ASCII field names |
| Content hash | BLAKE3, lowercase hex |
| Signature | Ed25519 (`verify_strict`: cofactorless, weak/torsion key rejected) |
| Operator signing domain | `heso-action/v1\0` (15 bytes) — see §6 |
| Approver signing domain | `heso-approval/v1\0` (17 bytes) — see §6 |
| Redaction commitment | `salted-blake3/v1` — `BLAKE3(salt ++ field_path ++ value)` |

Canonicalization, content hash, and signature scheme are **UNCHANGED from v1**.
The bump exists solely so a pre-change v1 receipt is never silently reinterpreted
under v2 rules. A verifier that supports only v1 MUST reject a v2 receipt as
*unsupported* (it cannot trust its own canonicalization of an unknown layout),
and vice-versa.

Both new v2 field groups are reserved-absent (`skip_serializing_if`): a v2
**standalone** receipt with no chain block ([`chain.md`](./chain.md)) and no time
anchor ([`time-anchor.md`](./time-anchor.md)) canonicalizes byte-identically to
the old v1 body *except* for the two tags above.

**Version pinning.** Where a receipt's classification depends on the taxonomy, it
pins the `taxonomy_hash` it was classified under (§3.4, ERT), and a verifier MUST
check against that pinned version, never the latest — see ADR
[0012](../../redesign/decisions/0012-taxonomy-versioning-pin-at-signing.md).

**v1 frozen suite.** Changing the canonicalization, the hash, OR the signature
scheme requires a **new `alg` tag** — never a silent change under an existing tag.
A verifier MUST reject an `alg` it does not recognize (it must not assume
JCS/BLAKE3/Ed25519 for an unknown tag). Post-quantum or threshold suites are
added as additional `alg` tags and/or additional `signatures[]` entries; a hybrid
suite MUST bind the PQC signature over `(message || classical_signature)` and
require BOTH components to verify (no "either passes" acceptance).

---

## 2. Envelope

An ActionReceipt is JSON:

```json
{
  "alg": "heso-action/v2+ed25519",
  "content": { "...the signed action statement...", "action_hash": "<blake3-hex>" },
  "signatures": [
    {
      "algorithm": "Ed25519",
      "key_id": "operator",
      "public_key": "<base64 32-byte key>",
      "signature": "<base64 64-byte sig>"
    }
  ]
}
```

- `alg` — the outer envelope tag. MUST be `heso-action/v2+ed25519` for a v2
  receipt. **Distinct** from the plat tag `heso-plat/v1+ed25519`
  (web-observation) and the witness tag `heso-witness/v1+ed25519`, so no other
  artifact can ever be accepted as an ActionReceipt.
- `content` — the signed action statement (§3). Carries its own `action_hash`.
- `signatures` — an **array**. The operator entry (`key_id = "operator"`) is
  ALWAYS present. A second entry (`key_id = "approver"`) is present **only** for a
  single-approver gated action (§5); an L1-quorum carries its approver legs inside
  `content.multi_approval` instead (see [`quorum.md`](./quorum.md)). Every entry
  MUST verify.
- `transparency` — OPTIONAL array, **outside** `content` (reserved for
  transparency-log inclusion proofs; see
  [`transparency.md`](./transparency.md)). Reserved and always empty on the wire
  in this version. Because it is not part of the signed bytes, a future proof can
  be attached to an already-signed receipt without re-signing. Omitted on the wire
  when empty.

---

## 3. Signed content

`content` is an object with these fields (v2.0). Reserved-absent fields use
`skip_serializing_if`, so a receipt that does not use one canonicalizes
byte-identically to a receipt minted before the field existed.

### 3.1 Always-present core fields

| Field | Meaning |
|---|---|
| `action_version` | Format version. `heso-action/2.0`. A verifier that does not recognize the version MUST reject the receipt. |
| `captured_at` | RFC 3339 UTC of the operator's clock at capture. **Informational only — not a trusted timestamp** (see [`time-anchor.md`](./time-anchor.md) for trusted time). |
| `agent_identity` | Base64 of the operator/agent's 32-byte Ed25519 public key. ALWAYS present. An informational mirror of the `"operator"` signature's `public_key`; trust is matched against `signatures[*].public_key`, not this field. |
| `action` | `{ verb, tool_name, target_host?, workflow, account, fields, result_hash?, error?, … }` — what the agent did (§3.3). |
| `policy` | `{ rule_id, rule_display, matched_conditions[], decision_path }` — which policy rule fired and the gate decision (`allow`, `block`, `redact`, `require_approval`). `matched_conditions` is the `(field, op, value)` triples the rule tested, recorded for audit. |
| `trust_level` | `L0` or `L1` — the DERIVED level, embedded for display. A verifier RE-DERIVES it from the signature roles and MUST reject a receipt whose embedded level disagrees (§4 step 7). |
| `action_hash` | Lowercase-hex BLAKE3 self-hash (§4). |

### 3.2 Conditional / reserved-absent content fields

| Field | Type | Presence & verifier behavior |
|---|---|---|
| `approver_decision` | `{ decision, approver_identity, reason, decided_at, sla_minutes? }` | Single-approver gated action only (§5). `decision` ∈ `approved`/`rejected`/`escalated`. |
| `redaction` | `{ mode, markers[], merkle_root? }` | Present only when ≥1 field was redacted (§3.5). |
| `session_id` / `seq` / `prev_receipt_hash` | chain block | Present on a chained receipt — see [`chain.md`](./chain.md). |
| `time_anchor` | `TimeAnchor?` | RFC-3161 trusted-time anchor — see [`time-anchor.md`](./time-anchor.md). |
| `multi_approval` | `MultiApproval?` | L1-quorum (k-of-n) block — see [`quorum.md`](./quorum.md). |
| `anchor_policy` | `Option<"required">` | When `"required"`, the verifier MUST fail closed unless a verified time anchor is present — see [`time-anchor.md`](./time-anchor.md). |
| `guardrail` | `GuardrailRecord?` | Present only when the runtime guardrail detector flagged the action (prompt-injection / jailbreak / tool-poisoning). Signed, so a detection cannot be scrubbed post-hoc. NOT a verify failure on its own — it is an integrity-protected record, not a security gate input. |
| `kind` | `ReceiptKind?` | The receipt's role in the suspend/resume lifecycle. `None` on the wire IS `ReceiptKind::Action` (the standalone fast path); read via the effective-kind accessor, never the raw field. A role-aware verifier maps it to the required signer role. |
| `suspension` | `Suspension?` | Present only on a `Suspended` receipt — the signed park-record (resume-token hash, context_ref pointer + integrity hash, tool binding, policy + approval terms). Signed, so the SLA / approver allowlist / context hash cannot be rewritten after signing. |
| `key_rotation` | `KeyRotation?` | Present only on a `KeyRotation` receipt — the role being rotated, the OUTGOING key (which MUST be this receipt's signer) and the INCOMING key valid from this position on. Honored only because the OUTGOING key authorized it; verified by the rotation-aware chain check (see [`chain.md`](./chain.md)). |
| `nonce` / `attestation` | reserved | Reserved (anti-replay nonce / TEE attestation), absent on the wire in v2. |

A standalone, no-ERT, no-mandate, no-anchor, no-`multi_approval`, no-`anchor_policy`,
`kind = None` v2 receipt is byte-identical to the §7 `988baa2e…` golden — none of
the reserved-absent groups change the golden when absent.

### 3.3 The `action` object

| Field | Meaning |
|---|---|
| `verb` | The **authoritative** coarse lane, one of the FROZEN-7: `payment`, `delete`, `account_change`, `data_export`, `llm_call`, `http_request`, `tool_call`. Every allow/deny, trust-level, and routing decision keys on `verb`. The FROZEN-7 map onto the 5 destructive primitives (move-value / destroy / change-authority / disclose / execute) per the taxonomy spine — see ADR [0001](../../redesign/decisions/0001-taxonomy-spine.md) and [taxonomy](../../redesign/standard/taxonomy.md). |
| `tool_name` | The invoked tool/function identifier. |
| `target_host` | The action's target host, when applicable. Omitted when absent. |
| `workflow` / `account` | The workflow and account the action ran under. |
| `fields` | The action's arguments **after** redaction (§3.5). The signed content never carries a redacted plaintext. |
| `result_hash` | BLAKE3 (64-hex) of the action's bound result. Omitted when absent. |
| `error` | The action's error string. Omitted when absent. |

Two ADDITIVE, reserved-absent **descriptive label** fields ride on `action`:

| Field | Type | Meaning |
|---|---|---|
| `action.domain` | `string?` | The policy-catalog fine lane id (e.g. `"payment"`, `"data_movement"`). |
| `action.action` | `string?` | The fine action id within that lane (e.g. `"authorize_payment"`, `"bulk_export"`). |

These are **purely descriptive** — a richer label over the *same* event the coarse
`verb` already pins. Added within v2 (no v3 bump): because they are
reserved-absent, a receipt with both `None` canonicalizes byte-identically to a v2
body minted before the fields existed.

> **SECURITY (normative):** the verifier MUST NOT trust `domain`/`action` for any
> security decision. They ride inside the signed content (so they are
> integrity-protected — an operator cannot rewrite them without breaking
> `action_hash` and the signature), but `verb` stays the AUTHORITATIVE signed lane
> every decision keys on. A receipt whose `domain`/`action` disagree with its
> `verb`, or that names no real catalog cell, is NOT a verify failure — the verb
> governs. The CLI `verify` MAY print `ACTION: <domain>.<action>` as a display aid.

### 3.4 ERT and mandate (reserved-absent, re-derivable)

| Field | Type | Verifier behavior |
|---|---|---|
| `action.ert` | `Ert?` | The signed Effected-Resource Tuple: the structural `observed_facts`, the pinned `taxonomy_hash`, and the derived `(resource_class, effect, egress)`. **Re-derivable**: a re-deriving verifier replays `classify(observed_facts, taxonomy@taxonomy_hash)` and FAILS CLOSED with `ClassificationMismatch` when the signed class ≠ the re-derived one (or the class's coarse verb ≠ the receipt's `verb`), or `TaxonomyUnavailable` when it does not embed the pinned taxonomy. A plain (non-re-deriving) `open_receipt` does NOT re-derive — a no-ERT receipt is unaffected. The pinned `taxonomy_hash` is the version anchor per ADR [0012](../../redesign/decisions/0012-taxonomy-versioning-pin-at-signing.md). |
| `action.mandate` | `MandateBinding?` | The payment mandate facts bound to the action (id, integrity hash, `mandate_status`, authorized payee/amount/currency). On a `payment` receipt whose bound `mandate_status` is `Invalid`/`Absent`, `open_receipt` FAILS CLOSED with `MandateRejected`. A payment with NO binding is left to the policy floor at gate time, not failed here; a non-payment receipt is unaffected. |

---

## 3.5 Field redaction (pre-sign) — the secret never enters the signed bytes

A captured action's arguments may contain secrets (a card number, an API key, a
prompt with PII). HESO redacts matched fields **before** the canonical bytes `C`
are computed, so the operator never signs over a plaintext secret and `action_hash`
is taken over the already-redacted `action.fields`. This is the load-bearing
invariant: **the signed bytes never contain the redacted value.** Two modes:

- **`destructive`** — the value is dropped and replaced with the literal
  `"[redacted]"`. Irrecoverable. Each marker is
  `{ field_path, algorithm: "drop/v1", commitment: "" }`; the record's
  `merkle_root` is absent. Backs `#[heso.destructive]`.
- **`commit_and_reveal`** — the value is replaced with `{"_sd": "<commitment>"}`
  where

  ```
  commitment = lowercase_hex(BLAKE3(salt ++ field_path ++ value_json_bytes))
  ```

  `salt` is a per-field 32-byte random value; `field_path` is the dotted path
  within `action.fields`; `value_json_bytes` is the field value's canonical JSON
  bytes. The field path is mixed in so the same secret committed under two
  different paths yields two distinct commitments. The salt + plaintext are sealed
  in an **off-wire sidecar** (never in the signed receipt), so an authorized holder
  can later *reveal* the field by recomputing the commitment and checking it equals
  the marker. Each marker is
  `{ field_path, algorithm: "salted-blake3/v1", commitment: "<64-hex>" }`. The
  record's `merkle_root` is `lowercase_hex(BLAKE3(c0 ++ "\n" ++ c1 ++ "\n" ++ …))`
  over the ordered commitment hex strings (each followed by a `\n` separator).
  Backs `#[heso.tool(redact=[…])]`.

A verifier checks **marker well-formedness** (§4 step 6): a `commit_and_reveal`
marker MUST name `salted-blake3/v1` and carry a 64-lowercase-hex commitment; a
`destructive` marker MUST name no commitment scheme and carry an empty commitment.
A holder of the sidecar additionally re-runs the *reveal* check (recompute the
commitment; equal ⇒ the revealed value is what was committed). The verifier never
sees the salt or plaintext, so it can confirm the record is well-formed but cannot
itself recover the value — exactly the point.

**Redaction commitment golden vector.** For `field_path = "card_number"`, value
`"4242424242424242"` (committed as its canonical JSON, i.e. the 18 bytes including
the surrounding quotes), and the all-`0x09` salt (`salt = [9u8; 32]`):

```
commitment = blake3_hex( [09]*32 ++ "card_number" ++ "\"4242424242424242\"" )
```

The commitment / `merkle_root` byte rules are pinned by
`commit_is_deterministic_for_a_fixed_salt`, `commitment_is_field_path_bound`, and
`merkle_root_changes_with_the_commitment_set` in `crates/heso-action/src/redact.rs`;
the reveal round-trip by `reveal_recomputes_a_valid_commitment` /
`a_tampered_reveal_fails`.

---

## 4. Canonicalization, hashing, and signing — the load-bearing rule

This is the rule a clean-room verifier MUST implement. Both the self-hash and the
signature are computed over the **same** canonical bytes `C`.

1. **Strip the self-hash.** Take the `content` object and remove its **top-level**
   `action_hash` field. (A hash field cannot contain its own digest.)
2. **Canonicalize (RFC 8785 / JCS).** Serialize the stripped object with
   [RFC 8785 JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785):
   sorted keys (by UTF-16 code unit; HESO field names are all ASCII so this equals
   byte order), minimal number formatting, no insignificant whitespace. This is
   `action_canonical_bytes(content)` in the kernel. Call the result `C`.
   > Step 1 is the action-receipt-specific part and MUST be done first; feeding a
   > raw on-wire `content` (which contains `action_hash`) straight into the
   > canonicalizer produces the wrong bytes.
3. **Self-hash.** `action_hash = lowercase_hex(BLAKE3(C))` (64 hex chars). The
   content self-hash is `BLAKE3(C)` with **no** hash-input domain prefix; cross-type
   confusion is prevented at the *signature* layer by the domain prefix (§6), not at
   the content-hash layer.
4. **Sign / verify.** The operator's signed payload is:

   ```
   payload = ACTION_SIGNING_DOMAIN ++ C
   ```

   The signature is Ed25519 over `payload`, verified with **`verify_strict`**
   (RFC 8032 canonical-scalar check + weak/torsion public-key rejection — MUST,
   since an approver/third-party key may appear). See §6 for the domain bytes.

---

## 5. The approver co-signature (L0 → L1, single-approver)

When the policy gate returns `require_approval`, the action is **suspended** until
an authorized human approver clears it. On approval, the operator assembles the
final `content` with the approver's `approver_decision` record embedded and
`trust_level = L1`, operator-signs it, and the approver **co-signs the identical
canonical bytes** `C` under a distinct domain:

```
approver_payload = APPROVAL_SIGNING_DOMAIN ++ C
```

The approver signs the **same** `C` the operator signed — never a different body —
so a single-approver L1 receipt is two signatures over one statement. The operator
therefore vouches for the **entire** record, the approver's decision included.
Because the approver record is part of the signed body, the operator MUST sign the
body *with the approver record already present* (the reference assembler refuses to
attach an approver signature over a body the operator signature does not cover).
The approver entry is tagged `key_id = "approver"`.

The k-of-n (L1-quorum) shape binds the human leg **differently** and is specified
separately in [`quorum.md`](./quorum.md); both shapes derive **L1**.

### 5.1 Trust levels

| Level | Signatures | Means |
|---|---|---|
| **L0** | operator only | The operator authorized this action under this policy decision (an ungated allow/redact path). |
| **L1** | operator + approval | A gated action a human cleared — EITHER a single approver co-signing the same bytes (this module), OR a k-of-n quorum ([`quorum.md`](./quorum.md)). Both shapes derive **L1**; the quorum carries a `content.multi_approval` block that distinguishes it and is NOT a higher level. |

`L2` (standing-authority) and `L3` (external co-sign) are **RESERVED and NOT
built** — there is no such `TrustLevel` variant. The transparency layer
([`transparency.md`](./transparency.md)) ships as offline RFC-6962 proof primitives
only and MUST NOT be promoted to a trust level. A verifier MUST derive the trust
level from the verified roles and MUST NOT honor an embedded `trust_level` it
cannot back with signatures.

---

## 6. Domain separation (RESOLVED — was the §3.5.1 forward-compat TODO)

The earlier web-observation Receipt (HESO/1.0 §3.5.1) deferred receipt domain
separation as a forward-compat SHOULD, relying on schema divergence rather than a
prefix. **The ActionReceipt construction RESOLVES that gap normatively:** every
ActionReceipt signature MUST be computed over a NUL-terminated domain prefix
prepended to `C`. This is not optional, not forward-compat, and not version-gated —
it is part of the v1 and v2 suites and is the cross-construction-confusion guard
for the whole agent-compliance layer.

| Domain constant | Bytes | Length | Prepended before |
|---|---|---|---|
| `ACTION_SIGNING_DOMAIN` | `heso-action/v1\0` | 15 | the **operator** signature over `C` (§4 step 4) |
| `APPROVAL_SIGNING_DOMAIN` | `heso-approval/v1\0` | 17 | the single-approver / per-leg **approver** co-signature over `C` (§5, [`quorum.md`](./quorum.md)) |
| `RECEIPT_CHAIN_DOMAIN` | `heso-rcpt-chain/v1\0` | 19 | the chain-link **hash** input — NOT a signing domain (see [`chain.md`](./chain.md)) |

**Why a NUL terminator (no length prefix needed).** A signing domain is prepended
to the canonical content bytes before signing. RFC 8785 (JCS) output is JSON text
and never contains a raw NUL (`0x00`), so the domain prefix and `C` are provably
disjoint without a length prefix — nothing in `C` can "look like" the end of the
domain. (Chain-link inputs are length-prefixed instead, because they concatenate
non-JCS fields — see [`chain.md`](./chain.md).)

**Disjointness is normative.** `ACTION_SIGNING_DOMAIN`, `APPROVAL_SIGNING_DOMAIN`,
and every sibling domain (the web-observation plat domain `heso-plat/v1\0`, the
witness domain `heso-witness/v1\0`, `RECEIPT_CHAIN_DOMAIN`, and the
suspend/decision/mandate/delegation/approval-token domains the kernel carries) MUST
be pairwise disjoint, so a signature minted over one payload shape can never be
replayed as another. A signature minted for one domain MUST NOT verify for another.
The kernel pins the exact bytes and proves pairwise disjointness in the
`dump_signing_domains` test (`crates/heso-action/src/domain.rs`).

> **Note on the web-observation `heso-receipt/v1\0` SHOULD.** That deferred prefix
> in HESO/1.0 §3.5.1 belongs to the **web-observation Receipt** (the plat/cassette
> layer), a different module — see
> [`web-observation`](../HESO-1.0.md). It is independent of, and does not collide
> with, the ActionReceipt domains specified here. This module does not depend on
> that future revision; the ActionReceipt's own domain separation is complete.

---

## 7. Golden vectors

A conformant implementation MUST reproduce these values. The operator identity is
the all-zero 32-byte Ed25519 seed (the project-wide test vector), whose public key
is `O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=`.

### 7.1 v2 default (standalone, no chain / no anchor / no labels)

Over the fixed v2 content (`action_version = "heso-action/2.0"`, the all-zero seed,
no chain block, no anchor, `domain`/`action` both `None`):

```
action_hash = 988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d
signature   = ujGbJO2VR2PpaguiG3NegMWAyQLWJlgAVxuKnwaeV8KsMbtT4K/f8lGhLrNI3NSxbIXQnwZGCS1b4BtXnRMQAQ==
```

Pinned by `golden_zero_seed_receipt_is_byte_stable` in
`crates/heso-action/src/verify.rs` and `crates/heso-engine/src/sign.rs`. That the
all-`None` descriptive labels do not change this body is pinned by
`domain_action_none_is_byte_identical_to_pre_field_v2_body` in
`crates/heso-action/src/receipt.rs`.

### 7.2 v2 with descriptive labels set

The SAME fixed content but with `action.domain = "payment"`,
`action.action = "authorize_payment"` (a real signed-byte change, hence its own
vector):

```
action_hash = 8857f29f3167272258d009477b53f78cb0072deb7b9d5bd59ce03cb2d3561a3a
signature   = liwRem2jfebT+/5hvCXYBWWzfKnINRssJqd6n8lcisWDleN62h8nWaNrlg1Z+N/KE43T65MykikiFOIVm7roAg==
```

Pinned by `golden_zero_seed_domain_action_receipt_is_byte_stable` in
`crates/heso-action/src/verify.rs` and
`setting_domain_action_changes_the_canonical_bytes` in
`crates/heso-action/src/receipt.rs`.

(The chain-link golden lives in [`chain.md`](./chain.md); the v1 golden in
[`action-receipt-v1.md`](./action-receipt-v1.md); the DSSE/PAE golden in
[conformance-and-envelope](../../redesign/standard/conformance-and-envelope.md).)

---

## 8. Verification order

A verifier MUST apply these in order, short-circuiting on the first failure, and
map the outcome to an exit code:

1. `alg == "heso-action/v2+ed25519"` (v2) — else **wrong algorithm** (exit 2).
2. `action_version` recognized (`heso-action/2.0`) — else **unsupported** (exit 2).
3. Recomputed `action_hash` (§4) equals the embedded value — else **hash mismatch /
   tampered** (exit 1); signatures are not checked.
4. Exactly one `"operator"` signature entry verifies over
   `ACTION_SIGNING_DOMAIN ++ C` — else **invalid signature** (exit 1); a missing,
   duplicated, or unknown-role entry is **malformed** (exit 2).
5. If an `"approver"` entry is present, it verifies over
   `APPROVAL_SIGNING_DOMAIN ++ C` (the **same** `C`, distinct domain) — else
   **invalid signature** (exit 1). For the L1-quorum shape, apply the quorum check
   in [`quorum.md`](./quorum.md) instead (`ThresholdNotMet` when fewer than
   `threshold` legs verify).
6. Every `redaction.markers[]` entry is well-formed for its mode (§3.5) — else
   **malformed redaction** (exit 1).
7. The trust level RE-DERIVED from the verified roles (operator only ⇒ L0;
   operator + approver / quorum ⇒ L1) equals the embedded `content.trust_level` —
   else **trust-level mismatch** (exit 1). The embedded field is display-only.
8. **(optional, module-gated)** If the receipt carries a `time_anchor` or
   `anchor_policy = "required"`, apply the [`time-anchor.md`](./time-anchor.md)
   checks. If it carries a chain block and the verifier claims chain conformance,
   apply the [`chain.md`](./chain.md) inter-link invariants. If it carries an ERT
   and the verifier re-derives, apply the §3.4 re-derivation. Transparency
   ([`transparency.md`](./transparency.md)) is not enforced inline.

All pass → **valid** (exit 0), carrying the re-derived L0/L1.

> **Ordering is load-bearing.** A forged operator signature is *invalid signature*
> (step 4) even if the receipt also lies about its trust level (step 7) — the
> signature check precedes the trust re-derivation. A content byte flip is *hash
> mismatch* (step 3) before any signature is checked.

---

## 9. APIs (informative)

```rust
// canonical bytes + self-hash
heso_action::receipt::action_canonical_bytes(&ActionContent) -> Vec<u8>   // = C
heso_action::receipt::action_hash(&ActionContent)            -> String    // 64-hex
heso_action::receipt::anchored_content_hash(&ActionContent)  -> String    // pre-anchor; see time-anchor.md

// verify
heso_action::verify::open_receipt(&ActionReceipt)            -> ActionOutcome
heso_action::verify::open_receipt_with_time(&ActionReceipt)  -> (ActionOutcome, TimeStatus)  // see time-anchor.md
heso_action::verify::open_receipt_rederiving(&ActionReceipt) -> ActionOutcome  // re-derives ERT (§3.4)

// constants
heso_action::domain::{ ACTION_ENVELOPE_ALG /* v2 */, ACTION_VERSION /* 2.0 */,
                       ACTION_ENVELOPE_ALG_V1, ACTION_VERSION_V1,
                       ACTION_SIGNING_DOMAIN, APPROVAL_SIGNING_DOMAIN }
```
