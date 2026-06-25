# Session Chain (HESO/1 — chain module)

**Status: Normative.**

The **BLAKE3 cross-receipt session chain**: a hash-linked, per-session audit chain
over [ActionReceipts](./action-receipt.md). The chain block is a set of
reserved-absent signed-content fields on the v2 receipt; this module specifies the
link-input bytes, the chain-link hash, and the inter-link invariants a verifier
checks. It is a **v2** feature — v1 ([`action-receipt-v1.md`](./action-receipt-v1.md))
carries no chain block.

Conformance is claimable per module: an implementation MAY claim
`action-receipt + chain` conformance independently of `time-anchor` or `quorum`.

The chain block is part of `action_canonical_bytes` (so the chain fields are
integrity-protected by `action_hash` + the operator signature — an operator cannot
re-point a link without breaking its own signature) and is `skip_serializing_if`
reserved-absent, so a **standalone** receipt with no chain block canonicalizes
byte-identically to a chainless v2 body
([`action-receipt.md` §7](./action-receipt.md)).

---

## 1. Chain block fields

Three signed-content fields, all on `content`:

| Field | Type | Meaning |
|---|---|---|
| `content.session_id` | `string?` | The session a chain belongs to. Identical across every link. Present on every chained receipt (genesis included); absent on a standalone one. |
| `content.seq` | `u64?` | Monotonic position within the session. Genesis is `0`; each successor is exactly +1. Present iff `session_id` is. |
| `content.prev_receipt_hash` | `string?` | 64-hex BLAKE3 of the predecessor's chain-link input (§2). `None`/empty for genesis. Lives in signed content, so an operator cannot re-point a link without breaking its own signature. |

`seq` is present iff `session_id` is present; a receipt with one but not the other
is **malformed**.

---

## 2. The chain-link input and link hash

`prev_receipt_hash` of the *next* receipt commits to the **chain-link input** of its
predecessor — domain-separated and **length-prefixed** so adjacent fields cannot be
slid across boundaries to forge an order:

```
link_input = RECEIPT_CHAIN_DOMAIN ++ LP(session_id) ++ LP(seq_le_u64) ++ LP(action_hash)
LP(x)      = len(x) as u64-le ++ x
RECEIPT_CHAIN_DOMAIN = "heso-rcpt-chain/v1\0"   (19 bytes)
link_hash  = lowercase_hex(BLAKE3(link_input))   (64 hex)
```

- `session_id` is its UTF-8 bytes; `seq_le_u64` is the 8-byte little-endian `seq`;
  `action_hash` is the predecessor receipt's 64-hex content self-hash
  ([`action-receipt.md` §4](./action-receipt.md)).
- `RECEIPT_CHAIN_DOMAIN` is a **hash-input separator**, NOT a signing domain — no
  Ed25519 signature is ever computed over it. It is pinned pairwise-disjoint from
  every signing domain (operator/approver/plat/witness/suspend/decision/mandate/
  delegation/approval-token) in the kernel's `dump_signing_domains` test, so the
  chain-link digest can never collide with a signing payload, a content hash, or a
  redaction commitment. See [`action-receipt.md` §6](./action-receipt.md) for the
  full domain table.
- **Why length-prefixed here (not NUL-disjoint like the signing domains).** The link
  input concatenates non-JCS fields (`session_id`, a raw little-endian integer, a
  hex string), so the NUL-disjointness argument that protects the JCS signing
  payload does not apply; explicit `u64-le` length prefixes make every boundary
  unambiguous.

---

## 3. Inter-link invariants (verify)

`verify_action_receipt_chain(&[ActionReceipt]) -> ChainOutcome` runs the full
per-receipt offline check ([`action-receipt.md` §8](./action-receipt.md)) on every
link, then the inter-link invariants. A verifier claiming chain conformance MUST
enforce all of:

1. **Genesis.** The first link has `seq == 0` and `prev_receipt_hash` is
   `None`/empty.
2. **Monotonic gapless seq.** Each successor's `seq` is exactly the predecessor's
   `+1` — no gaps (a drop) and no repeats/regressions (a reorder or insert).
3. **Stable `session_id`.** Every link carries the same `session_id`; a foreign
   `session_id` is a reorder/insert.
4. **Link continuity.** Each `prev_receipt_hash` equals the recomputed `link_hash`
   (§2) of the **actual** predecessor.

The outcome **names** the failure:

- `ContentTamper { seq, reason }` — a link's own crypto failed (hash/signature).
- `LinkBroken { seq, detail }` — a drop (seq gap), a reorder/insert (seq
  repeat/regression or foreign `session_id`), or a re-pointed `prev_receipt_hash`.
- `Empty` — fail closed; an empty slice is **never** `Valid`.
- `Valid { length }` — all links pass.

---

## 4. Key-rotation-aware chaining

When a link is a `ReceiptKind::KeyRotation` receipt (see
[`action-receipt.md` §3.2](./action-receipt.md)), the operator signing key changes
mid-session. The rotation is honored **only because the OUTGOING key authorized it**:
the rotation receipt MUST be signed by the OUTGOING key, and it carries the INCOMING
key valid from that position on. The rotation-aware chain check
(`verify_session_chain_with_rotation`) verifies each link under the key in force at
its `seq` and verifies the rotation receipt itself under the OUTGOING key before
switching. A rotation not signed by the outgoing key breaks the chain.

---

## 5. Golden vector

The genesis link hash of a fixed two-receipt zero-seed chain
(`session_id = "sess-golden"`, `seq = 0`):

```
genesis_link_hash = 8dfc58fd55076aeeffea330e3c8259e98d7cf8fa09e6e85150358edc2122eda9
```

Pinned by `golden_genesis_link_hash_is_byte_stable` in
`crates/heso-action/src/chain.rs`.

---

## 6. APIs (informative)

```rust
heso_action::chain::link_input(&ActionContent) -> Vec<u8>
heso_action::chain::link_hash(&ActionContent)  -> String          // 64-hex
heso_action::chain::bind_into_chain(&mut ActionContent, session_id: &str, prev: Option<&ActionContent>)
heso_action::chain::verify_action_receipt_chain(&[ActionReceipt]) -> ChainOutcome
// ChainOutcome::{ Valid{length}, ContentTamper{seq,reason}, LinkBroken{seq,detail}, Empty }
// constant: heso_action::domain::RECEIPT_CHAIN_DOMAIN
```
