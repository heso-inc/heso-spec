# ActionReceipt v1 (HESO/1 — frozen legacy module)

**Status: Normative (frozen).**

The **v1** suite of the HESO ActionReceipt. v1 is **frozen and byte-stable**: it
is kept so receipts already minted under it verify forever, exactly as ADR
[0012](../../redesign/decisions/0012-taxonomy-versioning-pin-at-signing.md) (law at
the time of signing) and the v1/v2 coexistence precedent require. New receipts are
minted under [`action-receipt.md`](./action-receipt.md) (v2); this module exists
only so a verifier can still validate a v1 artifact.

A verifier that supports only v1 MUST reject a v2 receipt as *unsupported*, and a
v2-only verifier MUST reject a v1 receipt — neither can trust its own
canonicalization of the other's layout. The two suites differ **only** in the
`alg` envelope tag and the `content.action_version` string (see
[`action-receipt.md` §1](./action-receipt.md)); the canonicalization (RFC 8785 /
JCS), content hash (BLAKE3), signature scheme (Ed25519 `verify_strict`), and the
domain prefixes are identical across v1 and v2.

> **Scope.** Identical to v2: an ActionReceipt proves the operator signed this
> exact action under this exact policy decision, and (at L1) that an authorized
> human co-signed the same bytes. It does **NOT** prove the action's outcome was
> correct (HESO/1.0 §0.1).

---

## 1. Envelope

A v1 ActionReceipt is JSON:

```json
{
  "alg": "heso-action/v1+ed25519",
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

- `alg` — MUST be `heso-action/v1+ed25519`. Distinct from the plat tag
  `heso-plat/v1+ed25519` and the witness tag `heso-witness/v1+ed25519`.
- `content` — the signed action statement (§2). Carries its own `action_hash`.
- `signatures` — an array. The operator entry (`key_id = "operator"`) is ALWAYS
  present; a second entry (`key_id = "approver"`) is present **only** for a gated,
  human-cleared action (§3.6). Every entry MUST verify.
- `transparency` — OPTIONAL array **outside** `content`, reserved for
  transparency-log inclusion proofs (see [`transparency.md`](./transparency.md));
  **reserved and always empty on the wire in v1**. Because it is not part of the
  signed bytes, a future proof could be attached to an already-signed receipt
  without re-signing. Omitted on the wire when empty.

---

## 2. Signed content (v1.0)

`content` is an object with these fields:

| Field | Meaning |
|---|---|
| `action_version` | Format version. `heso-action/1.0` in v1. A verifier that does not recognize the version MUST reject the receipt. |
| `captured_at` | RFC 3339 UTC of the operator's clock at capture. **Informational only — not a trusted timestamp.** |
| `agent_identity` | Base64 of the operator/agent's 32-byte Ed25519 public key. ALWAYS present — it pins which key the operator signature must match. An informational mirror of the `"operator"` signature's `public_key`; trust is matched against `signatures[*].public_key`, not this field. |
| `action` | `{ verb, tool_name, target_host?, workflow, account, fields, result_hash?, error? }` — what the agent did. `verb` is one of `llm_call`, `tool_call`, `http_request`, `payment`, `data_export`, `account_change`, `delete`. `fields` holds the action's arguments **after** redaction (§3.5). `target_host`/`result_hash`/`error` are omitted when absent. |
| `policy` | `{ rule_id, rule_display, matched_conditions[], decision_path }` — which policy rule fired and the gate decision. `decision_path` ∈ `allow`, `block`, `redact`, `require_approval`. `matched_conditions` is the `(field, op, value)` triples the rule tested. |
| `approver_decision` | `{ decision (approved\|rejected\|escalated), approver_identity, reason, decided_at, sla_minutes? }` — the human approver's verdict. Present **only** when gated to `require_approval`; omitted otherwise. |
| `redaction` | `{ mode (destructive\|commit_and_reveal), markers[], merkle_root? }` — what was redacted before hashing (§3.5). Present **only** when ≥1 field was redacted. |
| `trust_level` | `L0` or `L1` — the DERIVED level, embedded for display. RE-DERIVED by the verifier (§4 step 7). |
| `action_hash` | Lowercase-hex BLAKE3 self-hash (§3). |
| `nonce` / `time_anchor` / `attestation` | Reserved, omitted when absent. |

Reserved fields use "omit when empty/absent" so reserving them changes no v1 bytes.
A later phase that fills a **signed-content** slot MUST bump `action_version` — which
is exactly what v2 ([`action-receipt.md`](./action-receipt.md)) does.

---

## 3. Canonicalization, hashing, and signing — the load-bearing rule

Both the self-hash and the signature are computed over the **same** canonical bytes
`C`. This rule is **byte-identical** to v2 ([`action-receipt.md` §4](./action-receipt.md));
only `action_version` differs.

1. **Strip the self-hash.** Remove the **top-level** `action_hash` from `content`.
2. **Canonicalize (RFC 8785 / JCS).** Sorted keys (UTF-16 code-unit order; ASCII
   field names ⇒ byte order), minimal number formatting, no insignificant
   whitespace. This equals `heso_verify::canonical_bytes` from the open HESO
   runtime, which additionally strips a top-level `plat_hash` (an action `content`
   never has one, so that is a no-op here). Call the result `C`.
   > `heso-verify` strips `plat_hash`, **not** `action_hash`. Step 1 is the
   > action-receipt-specific part and MUST be done first.
3. **Self-hash.** `action_hash = lowercase_hex(BLAKE3(C))` (64 hex chars).
4. **Sign / verify.** `payload = ACTION_SIGNING_DOMAIN ++ C`, where
   `ACTION_SIGNING_DOMAIN` is the 15 bytes `heso-action/v1\0`. Ed25519 over
   `payload`, verified with **`verify_strict`** (canonical-scalar check +
   weak/torsion-key rejection). See [`action-receipt.md` §6](./action-receipt.md)
   for the full domain-separation rule (NUL terminator, pairwise disjointness).

---

## 3.5 Field redaction (pre-sign)

Identical to v2 — the secret never enters the signed bytes. See
[`action-receipt.md` §3.5](./action-receipt.md) for the two modes
(`destructive` / `commit_and_reveal`), the commitment formula
`BLAKE3(salt ++ field_path ++ value_json_bytes)`, the `merkle_root` rule, and the
golden commitment vector. The byte rules are pinned by the same
`crates/heso-action/src/redact.rs` tests.

## 3.6 The approver co-signature (L0 → L1)

When the gate returns `require_approval`, the operator assembles the final `content`
with the approver's `approver_decision` embedded and `trust_level = L1`,
operator-signs it, and the approver **co-signs the identical canonical bytes** `C`
under a distinct domain:

```
approver_payload = APPROVAL_SIGNING_DOMAIN ++ C
```

`APPROVAL_SIGNING_DOMAIN` is the 17 bytes `heso-approval/v1\0`. The approver signs
the **same** `C` the operator signed, so an L1 receipt is two signatures over one
statement. The distinct domain is load-bearing: an operator authorization (under
`heso-action/v1\0`) can never be replayed as an approver decision (under
`heso-approval/v1\0`) even though both cover identical bytes. The approver entry is
tagged `key_id = "approver"`. The operator MUST sign the body *with the approver
record already present*.

(v1 has **no** k-of-n quorum shape — that is a v2 signed-content feature; see
[`quorum.md`](./quorum.md).)

---

## 4. Verification order

A verifier MUST apply these in order, short-circuiting on the first failure:

1. `alg == "heso-action/v1+ed25519"` — else **wrong algorithm** (exit 2).
2. `action_version` recognized (`heso-action/1.0`) — else **unsupported** (exit 2).
3. Recomputed `action_hash` (§3) equals the embedded value — else **hash mismatch /
   tampered** (exit 1); signatures are not checked.
4. Exactly one `"operator"` signature verifies over `ACTION_SIGNING_DOMAIN ++ C` —
   else **invalid signature** (exit 1); a missing, duplicated, or unknown-role entry
   is **malformed** (exit 2).
5. If an `"approver"` entry is present, it verifies over
   `APPROVAL_SIGNING_DOMAIN ++ C` (same `C`, distinct domain) — else **invalid
   signature** (exit 1).
6. Every `redaction.markers[]` entry is well-formed for its mode (§3.5) — else
   **malformed redaction** (exit 1).
7. The trust level RE-DERIVED from the verified roles (operator only ⇒ L0; operator
   + approver ⇒ L1) equals the embedded `content.trust_level` — else **trust-level
   mismatch** (exit 1).
8. (reserved) optional transparency — not enforced in v1.0.

All pass → **valid** (exit 0), carrying the re-derived L0/L1.

> **Ordering is load-bearing.** A forged operator signature is *invalid signature*
> (step 4) even if the receipt lies about its trust level (step 7). A content byte
> flip is *hash mismatch* (step 3) before any signature is checked.

---

## 5. Golden vector (frozen v1)

A conformant implementation MUST reproduce these values. The operator identity is
the all-zero 32-byte Ed25519 seed, whose public key is
`O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=`.

Over this exact `content` (an ungated `allow` LLM call — before `agent_identity` and
`action_hash` are stamped; `agent_identity` set to the public key above,
`action_hash` to the result of §3):

```json
{
  "action_version": "heso-action/1.0",
  "captured_at": "2026-05-29T12:00:00Z",
  "agent_identity": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
  "action": {
    "verb": "llm_call",
    "tool_name": "openai.chat.completions",
    "target_host": "api.openai.com",
    "workflow": "research-run-7",
    "account": "acct_acme",
    "fields": { "prompt": "summarize the filing", "model": "gpt-4o" },
    "result_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "policy": {
    "rule_id": "allow-llm",
    "rule_display": "allow llm_call to api.openai.com",
    "matched_conditions": [ { "field": "verb", "op": "eq", "value": "llm_call" } ],
    "decision_path": "allow"
  },
  "trust_level": "L0"
}
```

the results are:

```
action_hash = 71a19e51a663b8a04ce78cd0e6f5f46ef145ed4cd589e6acb35865ec56cef021
signature   = MTEAUAJSoGynP2UxsokGM6Lxf5UJG3i2qoM4Tdc3twAwO6NO5lt2Hvy2VzlZlLh3czawfXMEKEURq0GB2bhkBQ==
```

These literals are this module's own v1 reference vector, reproducible from the §3
rules. The in-code `golden_zero_seed_receipt_is_byte_stable` tests in
`crates/heso-action/src/{receipt.rs,verify.rs}` and `crates/heso-engine/src/sign.rs`
pin the engine's **default v2** envelope (the regenerated v2 values in
[`action-receipt.md` §7](./action-receipt.md)), NOT these v1 literals. The v1 path
remains valid and byte-stable for receipts already minted under it; these v1
literals are pinned by this document. Any drift in canonicalization, the domain
prefix, or serde field handling changes them.

> The pipeline (`heso-engine`) stamps its *own* `policy` block, so an end-to-end
> engine receipt under a different rule has a different `action_hash` and signature
> than this fixture — expected. This vector pins the *format*; the pipeline's own
> golden (`crates/heso-engine/tests/pipeline.rs`) pins the engine-produced bytes.

---

## 6. Reserved slots (forward-compatible)

All reserved slots use "omit when empty/absent", so reserving them changes no v1
signed bytes. A phase that fills a **signed-content** slot MUST bump
`action_version` (v2 does this); `transparency[]` lives outside `content`, so a
transparency proof attaches without re-signing.

| Slot | Purpose | Filled in |
|---|---|---|
| `content.nonce` | requester freshness nonce (anti-replay of an entire receipt) | reserved (v2 too) |
| `content.time_anchor` | trusted-time countersignature (RFC 3161 / Roughtime) | v2 — [`time-anchor.md`](./time-anchor.md) |
| `content.attestation` | TEE attestation binding a measured enclave to this receipt | reserved |
| `content.action.result_hash` | BLAKE3 of the action's bound result | present when a result is bound |
| `content.redaction.merkle_root` | the set-commitment over `commit_and_reveal` markers | present in that mode |
| `content.session_id` / `seq` / `prev_receipt_hash` | session chain block | v2 — [`chain.md`](./chain.md) |
| `content.multi_approval` | k-of-n quorum block | v2 — [`quorum.md`](./quorum.md) |
| `transparency[]` | future RFC-6962 inclusion proofs — always empty on the wire today | [`transparency.md`](./transparency.md) |
