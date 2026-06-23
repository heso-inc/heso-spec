# Quorum — k-of-n co-signature (HESO/1 — quorum module)

**Status: Normative.**

The **L1-quorum** lane: a k-of-n human co-signature shape for a gated
[ActionReceipt](./action-receipt.md). Where single-approver L1
([`action-receipt.md` §5](./action-receipt.md)) is two signatures over **one** body,
a quorum binds the human leg differently — and that difference is the whole honesty
story, and the reason a quorum is **not** ranked above single-approver L1.

It is a **v2** signed-content feature carried in `content.multi_approval`; v1
([`action-receipt-v1.md`](./action-receipt-v1.md)) has no quorum shape. Conformance
is claimable per module: an implementation MAY claim `action-receipt` without
claiming `quorum`.

A quorum receipt derives `TrustLevel::L1` **WITH** the `multi_approval` block — it
distinguishes the quorum shape of L1 from the single-approver shape, **NOT** a higher
level. There is **no** `L2` variant; `L2`/`L3` are RESERVED and NOT BUILT (see
[`action-receipt.md` §5.1](./action-receipt.md)).

---

## 1. The `content.multi_approval` and `content.anchor_policy` fields

Both reserved-absent (`#[serde(default, skip_serializing_if = "Option::is_none")]`),
so a receipt that uses neither canonicalizes byte-identically to the
[`action-receipt.md` §7](./action-receipt.md) golden.

| Field | Type | Meaning |
|---|---|---|
| `content.multi_approval` | `MultiApproval?` | Present only on an L1-quorum receipt. Carries `threshold: u32`, `roster: Vec<String>` (the permitted approver pubkeys, base64, **sorted ascending**), and `approvers: Vec<ApproverRecord>` (the k collected approvals, **sorted ascending by base64 approver identity**). |
| `content.anchor_policy` | `Option<"required">` | The trusted-time enforcement knob — specified in [`time-anchor.md` §4](./time-anchor.md). |

---

## 2. The two-canonical rule (M-B)

There is **no single shared body** in a quorum. Instead there are **two distinct
canonical forms**:

1. **The operator base** (`build_quorum_base`): the quorum content with `approvers`
   **emptied** — only the action, the `threshold`, and the sorted `roster`. The
   operator signs *this* under `ACTION_SIGNING_DOMAIN`
   ([`action-receipt.md` §6](./action-receipt.md)). So the operator vouches for
   *the action, the threshold, and which keys are eligible* — and **nothing about
   any individual approval**.

2. **The per-approver body**: for each collected approval, that approver signs

   ```
   APPROVAL_SIGNING_DOMAIN ++ multi_approver_canonical(base, own_record)
   ```

   — the base **plus that approver's own record** — under the **same** 17-byte
   `heso-approval/v1\0` co-sign domain single-approver L1 uses (distinct from the
   23-byte decision-token domain). Each approver vouches **only for their own leg**:
   their `reason`, their `decided_at`, their identity.

---

## 3. Consequence (normative honesty)

An L1-quorum receipt's `approvers[i].reason` and `approvers[i].decided_at` are bound
**solely by approver `i`'s own signature**. The operator never signed over them.

> A verifier MUST NOT read an L1-quorum receipt as the operator attesting to any
> approver's stated reason or timestamp — only that the operator authorized the
> action under this threshold and roster, and that ≥ `threshold` distinct roster
> members each signed their own leg.

This is why the quorum is a **narrower, more honest** claim than single-approver L1,
and is therefore **not ranked above it** — both are L1; the quorum is distinguished
by its `multi_approval` block, never by a level number. (Trusted time, when present,
binds only the assembled body, never any approver's `decided_at` — see
[`time-anchor.md` §3](./time-anchor.md).)

---

## 4. Verify

A verifier claiming quorum conformance MUST:

1. Verify the operator signature over `ACTION_SIGNING_DOMAIN ++ build_quorum_base`
   (the approvers-emptied base).
2. For each `approvers[i]`, verify its leg signature over
   `APPROVAL_SIGNING_DOMAIN ++ multi_approver_canonical(base, approvers[i])`, where
   approver `i`'s public key is a member of `roster`.
3. Require **≥ `threshold` distinct** roster members to have a verifying leg — else
   `ThresholdNotMet { have, need }`.
4. Re-derive `TrustLevel::L1` WITH the `multi_approval` block present.

`ActionOutcome` gains:

- `ThresholdNotMet { have, need }` — fewer than `threshold` approver legs verify.
- `AnchorRequired` — `anchor_policy = "required"` but no verified anchor (see
  [`time-anchor.md`](./time-anchor.md)).

---

## 5. Canonicalization stays the Rust moat

The browser never hand-assembles either canonical form. `quorumCosignPayload(...)`
in `@hesohq/verify-wasm` produces the per-approver leg bytes
(`APPROVAL_SIGNING_DOMAIN ++ multi_approver_canonical`) so canonicalization stays the
Rust moat on every plane. Assembly into the final receipt
(`assemble_quorum_from_parts`) is operator-side, in-core, and MUST verify
`Valid(L1)` with the `multi_approval` block present before returning. The cloud holds
no signing key and re-canonicalizes nothing — it relays approver legs verbatim.
`OperatorKeyMismatch` is a DISTINCT typed signal across each boundary.

---

## 6. APIs (informative)

```rust
// operator-side assembly (in-core; loads operator key, verifies Valid(L1) + multi_approval):
//   napi @hesohq/node:  assembleQuorumFromParts(suspendedContentJson, threshold, rosterJson, partsJson, projectRoot, keyPassphrase?) -> Buffer
//   py   heso._core:     assemble_quorum_from_parts(operator_key, suspended_content_json, threshold, roster_json, parts_json) -> bytes
// browser per-approver leg (verify-wasm; canonicalization stays the Rust moat, no sign):
//   wasm @hesohq/verify-wasm: quorumCosignPayload(suspendedContentJson, threshold, rosterJson, approverRecordJson) -> Uint8Array
//                              = APPROVAL_SIGNING_DOMAIN ++ multi_approver_canonical
// ActionOutcome adds: ThresholdNotMet{have,need}, AnchorRequired
// constant: heso_action::domain::APPROVAL_SIGNING_DOMAIN
```
