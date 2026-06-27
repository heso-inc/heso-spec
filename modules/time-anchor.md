# Time Anchor (HESO/1 — time-anchor module)

**Status: Normative.**

The **RFC-3161 trusted-time anchor**: an optional, fail-closed countersignature
that binds an [ActionReceipt](./action-receipt.md) to an *existed-no-later-than*
instant from an independent Time-Stamping Authority (TSA). The anchor is a
reserved-absent signed-content field on the v2 receipt; this module specifies its
shape, its verify rule, the honest semantics of the timestamp, and the
`anchor_policy` enforcement knob.

It is a **v2** feature — v1 ([`action-receipt-v1.md`](./action-receipt-v1.md))
reserves `content.time_anchor` but never fills it. Conformance is claimable per
module: an implementation MAY claim `action-receipt` without claiming
`time-anchor`.

**Anchorless by default.** An **absent** anchor is NOT a failure — it is the
separate `TimeStatus::NoTrustedTime` status line. Enforcement of a *required* anchor
is the verifier's job, driven by `content.anchor_policy` (§4). Because the anchor is
reserved-absent, a no-anchor v2 receipt canonicalizes byte-identically to the §7
golden in [`action-receipt.md`](./action-receipt.md).

---

## 1. The `content.time_anchor` field

`content.time_anchor` (absent ⇒ "no trusted time"; present ⇒ verified fail-closed):

| Field | Type | Meaning |
|---|---|---|
| `kind` | `string` | MUST be `"rfc3161"`. |
| `token_b64` | `string` | base64 DER RFC-3161 Time-Stamp Token (CMS `SignedData` / `TSTInfo`). |
| `tsa` | `string` | TSA name/URL (informational; trust is the pinned roots, not this). |
| `anchored_hash` | `string` | 64-hex BLAKE3 — the **pre-anchor** content hash: `action_hash` computed with **both** `action_hash` and `time_anchor` excluded, since an anchor cannot certify the hash that contains it. |

The pre-anchor hash is `heso_action::receipt::anchored_content_hash(&ActionContent)`.

---

## 2. Verify rule (always compiled, always fail-closed)

A verifier claiming time-anchor conformance MUST, when an anchor is present:

1. `kind == "rfc3161"`.
2. `anchored_hash` is 64-lower-hex AND equals the recomputed **pre-anchor** hash
   (§1).
3. `token_b64` is non-empty valid base64.

Then, **only under the `tsa` cargo feature**, the RFC-3161 CMS/TSTInfo token is
cryptographically verified — its `messageImprint` is `anchored_hash`, its signer
cert carries the `id-kp-timeStamping` EKU and chains to a **pinned in-binary TSA
root**.

With the `tsa` feature **OFF**, a present anchor that passes the preconditions STILL
fails closed (`TimeAnchorUnverifiable`) — such a build never vouches for time it
cannot verify. An **absent** anchor is not a failure; it is
`TimeStatus::NoTrustedTime`.

> **Published-artifact reality (2026-06-27).** The **heso-wasm** proof-page build
> is compiled **with** `tsa` enabled: trusted-time verify is live on that surface
> and a valid anchor resolves to `AnchoredRfc3161`, not `TimeAnchorUnverifiable`.
> The **published Python wheel** also ships the `tsa` feature enabled and exposes
> `request_time_anchor` for production minting — the feature gate is a Rust source
> boundary, not a published-package boundary.

The producer side (token *requesting*) is feature-gated in the Rust source
(`#[cfg(feature = "tsa")] request_time_anchor`); the **verify side is always real**.

---

## 3. genTime semantics (normative honesty)

When an anchor verifies, the TSTInfo `genTime` is surfaced as
`AnchoredRfc3161 { gen_time }`. It is an **existed-no-later-than** bound on the
*assembled body the anchor commits to* — nothing more.

Because `anchored_hash` is the **pre-anchor** content hash and the anchor is
requested **after** the human approval is assembled (the two-phase path: assemble
the post-approval L1 body, then stamp it), `genTime` proves only that **this
assembled body existed by that instant**. It is **NOT** a proof of *when the human
decided*.

Each approver's `decided_at` is **approver-claimed and operator-untrusted** — bound
(in single-approver L1) by the approver's own co-signature over the body and (in an
L1-quorum) solely by that approver's own leg (see [`quorum.md`](./quorum.md)), never
certified by the TSA.

> **A verifier MUST present trusted time as "the approved action existed by
> `genTime`", never as "the human decided at `genTime`".**

---

## 4. `content.anchor_policy` — requiring an anchor

A reserved-absent signed-content field,
`#[serde(default, skip_serializing_if = "Option::is_none")]`:

| Field | Type | Meaning |
|---|---|---|
| `content.anchor_policy` | `Option<"required">` | When `"required"`, the verifier MUST fail closed with `AnchorRequired` unless trusted time is present and verified (§2). Absent ⇒ the default anchorless-by-default posture (an absent anchor is `NoTrustedTime`, not a failure). |

Because it is reserved-absent, a receipt without it canonicalizes byte-identically to
the [`action-receipt.md` §7](./action-receipt.md) golden.

---

## 5. Outcomes

A time-aware verify (`open_receipt_with_time`) returns the receipt outcome plus a
`TimeStatus`:

- `TimeStatus::NoTrustedTime` — no anchor present (and `anchor_policy` not
  `"required"`).
- `TimeStatus::AnchoredRfc3161 { gen_time }` — anchor present and verified.
- `ActionOutcome::TimeAnchorUnverifiable(String)` — anchor present but unverifiable
  (preconditions failed, or `tsa` feature off in a custom library build; the
  published heso-wasm and Python wheel builds have `tsa` enabled).
- `ActionOutcome::AnchorRequired` — `anchor_policy = "required"` but no verified
  anchor.

---

## 6. APIs (informative)

```rust
heso_action::verify::open_receipt_with_time(&ActionReceipt) -> (ActionOutcome, TimeStatus)
// TimeStatus::{ NoTrustedTime, AnchoredRfc3161{gen_time} }
// ActionOutcome adds: TimeAnchorUnverifiable(String), AnchorRequired
heso_action::tsa::verify_time_anchor(&TimeAnchor, anchored_hash: &str) -> Result<String, String>
heso_action::receipt::anchored_content_hash(&ActionContent) -> String   // the pre-anchor hash
#[cfg(feature = "tsa")] heso_action::tsa::request_time_anchor(action_hash, tsa_url) -> Result<TimeAnchor, String>
// ↑ feature-gated in Rust source; unconditionally available in the published Python wheel and heso-wasm.
// constant: heso_action::domain::TIME_ANCHOR_RFC3161
```
