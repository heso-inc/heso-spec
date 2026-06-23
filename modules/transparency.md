# HESO/1 — Transparency Module

**Status: Normative.** Key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY are to be interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

The transparency module specifies an [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) SHA-256 Merkle tree over HESO Action Receipts and the two offline proof primitives — **inclusion** and **consistency** — that let an independent, off-the-shelf RFC-6962 verifier check, with **no HESO-specific code**, that a receipt sits in the tree and that the tree has only ever grown.

This module is the *format and proof* spec. It defines the leaf shape, the tree hashing, the proof verification rules, and the interop reference vectors. It is deliberately silent on *who operates the log* and *how proofs are transported*; the witnessed-network topology (checkpoints, cosignatures, tile serving) is a separate concern bound to the [Tessera / `tlog-tiles`](../../redesign/decisions/0008-tessera-transparency-network.md) decision and is summarised, not specified, in [§6](#6-the-witnessed-network-forward-slot).

This module layers *on top of* the [action-receipt](./action-receipt.md) and [chain](./chain.md) modules. A receipt is valid on its own; transparency is an evidence substrate over the **order** receipts were logged in, **outside** the signed receipt content. It is conformance-claimable independently: an implementation MAY conform to `action-receipt` + `chain` + `transparency` without claiming `envelope`, `time-anchor`, or `quorum`.

---

## 1. The two-hash layering (read this first)

HESO uses **two different hash functions for two different jobs and MUST NOT mix them**:

| Layer | Hash | Answers | Where |
|---|---|---|---|
| **Content** | **BLAKE3** | *WHAT* action was taken | `action_hash`, the chain link, `plat_hash`, the redaction commitment |
| **Order** | **SHA-256** | *the ORDER* receipts were logged in | the RFC-6962 Merkle tree |

- A transparency **leaf value** is a receipt's BLAKE3 `action_hash` — the 32 raw content bytes (the WHAT). See [§2](#2-leaves).
- The **tree** over those leaves is **SHA-256 RFC-6962** (the ORDER). The tree is SHA-256 and not BLAKE3 for exactly one reason: **interop**. An unmodified, off-the-shelf RFC-6962 verifier can check it. That is the entire point of this layer.

A BLAKE3 digest MUST only ever appear as a leaf *value* (fed into the RFC-6962 *leaf hash*). A SHA-256 tree hash MUST NOT be treated as content. The single crossing point between the two domains is the leaf-value bridge in [§2.1](#21-the-leaf-value-bridge).

---

## 2. Leaves

The tree's leaves are the **audit chain's `action_hash` values, in `seq` order** — one leaf per signed action, in the same order as the BLAKE3 [chain](./chain.md). The chain already guarantees order and tamper-evidence over *content*; the transparency tree adds a SHA-256 commitment over that *same order* that an RFC-6962 verifier can recompute.

- Leaf `i` MUST be `leaf_value(entry[i].action_hash)`, where `entry[i].seq == i`.
- The leaf set MUST be the receipts in strict `seq` order with no gaps, reorders, or duplicates. Order is defined by the chain, not by wall-clock time.

> **Privacy boundary (normative).** A leaf is a 32-byte BLAKE3 *commitment*, never a receipt body. An implementation MUST NOT place raw action content into a transparency leaf. This makes "raw content never leaves the customer boundary" a property of the format itself: a tree built per this module reveals only fingerprints and order. (The witnessed-network engine additionally enforces a 64 KB entry cap as a mechanical backstop — see [§6](#6-the-witnessed-network-forward-slot).)

### 2.1 The leaf-value bridge

```
leaf_value(action_hash) -> [u8; 32]
```

`leaf_value` decodes a receipt's `action_hash` from its 64-character lowercase-hex textual form into its 32 raw bytes. It MUST:

- require **exactly 64 characters**, each in `[0-9a-f]`;
- **reject** uppercase hex, non-hex characters, and any length other than 64 (fail-closed);
- produce exactly 32 bytes.

This is the only point where the BLAKE3 content domain crosses into the SHA-256 order domain. Each receipt therefore maps to **one** canonical 32-byte leaf value.

---

## 3. RFC-6962 tree hashing

The tree hashing is RFC-6962 §2.1, unmodified:

```
leaf_hash(value) = SHA-256(0x00 || value)
node_hash(l, r)  = SHA-256(0x01 || l || r)
empty_tree_root  = SHA-256("")   == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

- The `0x00` (leaf) and `0x01` (node) domain prefixes are REQUIRED. They make the tree shape part of the hash — the RFC-6962 second-preimage guard. An implementation MUST NOT omit or alter them.
- For `n > 1` leaves the tree splits at `k` = **the largest power of two strictly less than `n`** (NOT `n/2`). The left subtree is `D[0:k]`, the right subtree is `D[k:n]`. This left-full / right-remainder shape is what makes appends incremental and is the exact shape every interoperating RFC-6962 verifier expects.
- The leaf values are hashed in `leaf_hash` form; `node_hash` is applied to the **subtree roots**, not to raw leaf values.

### 3.1 Inclusion proofs

An **inclusion proof** for leaf index `m` in a tree of size `n` is the ordered list of sibling hashes (`PATH(m, D[0:n])`, RFC-6962 §2.1.1) that recompute the root from `leaf_hash(value)`.

```
verify_inclusion(leaf_value, index, tree_size, root, proof) -> bool
```

The verifier MUST:

1. reject if `index >= tree_size` or `tree_size == 0`;
2. start from `leaf_hash(leaf_value)`;
3. fold the proof hashes in order, choosing left/right sibling placement from the bit pattern of `index` relative to `tree_size` exactly as RFC-6962 §2.1.1 prescribes;
4. accept iff the recomputed root equals `root`, byte-for-byte;
5. reject a proof of the wrong length for `(index, tree_size)`.

### 3.2 Consistency proofs

A **consistency proof** (`PROOF(m, D[0:n])`, RFC-6962 §2.1.2) proves that the size-`n` tree is an **append-only extension** of the size-`m` tree — the old root is still a prefix, history was not rewritten.

```
verify_consistency(old_size, old_root, new_size, new_root, proof) -> bool
```

The verifier MUST:

1. reject if `old_size == 0`, `old_size > new_size`, or `new_size == 0`;
2. when `old_size == new_size`, accept iff `old_root == new_root` and the proof is empty;
3. otherwise reconstruct both the claimed old root and the new root from the proof per RFC-6962 §2.1.2 and accept iff **both** match the supplied roots byte-for-byte;
4. reject a proof of the wrong length for `(old_size, new_size)`.

`verify_inclusion` and `verify_consistency` MUST be **pure functions** of their `(value | roots | sizes | proof)` arguments — no tree state. A clean-room verifier reproduces them from a proof alone. The stateful producer side (append, root, build inclusion/consistency proofs) is an implementation detail of the log operator and is not normative for *verification* conformance.

---

## 4. Binding to the receipt

Transparency lives **outside** the signed content of an Action Receipt.

- A receipt's optional `transparency[]` slot is reserved for stapled proofs. It is **not** covered by `action_hash` and **not** covered by any signature. Adding or removing a proof MUST NOT change `action_hash` or invalidate a signature.
- The receipt verifier ([action-receipt §verify order](./action-receipt.md)) MUST NOT require transparency to be present, and MUST NOT treat an absent or empty `transparency[]` as a verification failure. A receipt verifies precisely on its content and signatures.
- A relying party that wants tree-membership assurance composes the [§3](#3-rfc-6962-tree-hashing) primitives itself over the receipts it holds: decode each `action_hash` via [`leaf_value`](#21-the-leaf-value-bridge), order by chain `seq`, and run `verify_inclusion` / `verify_consistency` against a root it has obtained.

> **Honesty boundary (normative).** Transparency proves **inclusion and append-only order**, not **truth**. An inclusion proof shows a receipt is in *a* tree at *a* position; it does not show the content is accurate, nor — on its own — that the operator showed the *same* tree to everyone (the split-view / equivocation problem). Split-view defense requires an independent witness whose key is outside the operator's control; see [§6](#6-the-witnessed-network-forward-slot). An implementation MUST NOT describe a bare inclusion proof as "witnessed accountability" or "public transparency."

---

## 5. Interop reference vectors

A conformant implementation MUST reproduce the **published RFC-6962 reference test tree** so that its tree hashing is interoperable with the same vectors CT monitors use. The canonical CT test inputs are the 8 leaf values:

```
[ "", 00, 10, 2021, 30313233, 4041424344454647, 505152535455565758595a5b5c5d5e5f ]
```

`merkle_tree_hash` over the first `n` inputs MUST equal:

```
n=0  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
n=1  6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
n=2  fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125
n=3  aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77
n=4  d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7
n=5  1dcadf8bda03bf92d0ee3d5dc9a2a46eb460efad001f1b28f1804b82a6a72537
n=6  17c1852c508e1c962451b5a8b1add18fec073708c393651aa1ffbad00ed34c20
n=7  5c9d6283894312cd8dde52269ae3e6e72dc88c15560d3569b2613fe73352bd58
```

Reference proofs that MUST verify against the roots above:

```
incl(index=0, tree_size=7) = [ 96a296d2…09cfc7, 5f083f0a…de3031e, 3e10ecd5…cda98848 ]
cons(old_size=4, new_size=7) = [ 3e10ecd5…cda98848 ]
```

These roots, the full per-leaf inclusion sets, and the `old_size ∈ {1,2,3,4,6}` consistency proofs are published in the open `vectors/` corpus (`rfc6962-roots`, licensed CC0) and are regenerated from the reference implementation in CI — see [conformance-and-envelope §2](../../redesign/standard/conformance-and-envelope.md). The Rust reference, the clean-room Python verifier, and the WASM verify surface MUST all reproduce them byte-for-byte.

---

## 6. The witnessed-network forward slot

A transparency tree on its own does not stop a malicious log operator from showing **different verifiers different trees** (a split view / equivocation). The standard defense is a signed, append-only **checkpoint** cross-checked by an independent **witness**.

This module specifies the **format and the offline proof math** ([§2](#2-leaves)–[§5](#5-interop-reference-vectors)) — the part a relying party needs to verify proofs it is handed. The **witnessed network** that produces and serves those proofs (checkpoint signing, witness cosignatures, the C2SP signed-note / `tlog-checkpoint` wire format, tile serving) is bound to the [Tessera / `tlog-tiles` decision (ADR 0008)](../../redesign/decisions/0008-tessera-transparency-network.md) and lives in the proof-and-transparency architecture, not in this format spec.

Where ADR 0008 informs the **wire/leaf shape**, this module is aligned with it:

- **Leaf = BLAKE3 commitment, never a body.** Tessera's 64 KB entry cap mechanically backstops the [§2](#2-leaves) commitment-only rule — a full receipt body would not fit.
- **`tlog-tiles` read API.** The witnessed network serves entries as tiles per `c2sp.org/tlog-tiles`, so a C2SP-compatible client obtains the [§3](#3-rfc-6962-tree-hashing) inclusion/consistency proofs with off-the-shelf tooling. The leaf and tree-hashing rules in this module are exactly the ones a `tlog-tiles` client expects.
- **Checkpoints carry a root.** A signed checkpoint commits to a `(tree_size, root)`; verifying a checkpoint signature and a witness cosignature is the split-view defense layered *on top of* the proof primitives here. The note/cosignature format is normative in the witnessed-network spec, not here.

The forward slot layers on top of [§3](#3-rfc-6962-tree-hashing) **without changing** the leaf rule, the tree hashing, or the receipt verify order. A conformant `transparency` implementation that ships only the offline proof primitives is conformant for this module; the witnessed-network guarantees are an additional, separately-specified surface.

---

## 7. Versioning

| Component | v1 |
|---|---|
| Tree hash | SHA-256, RFC-6962 (`0x00` leaf / `0x01` node prefixes) |
| Leaf value | raw 32-byte BLAKE3 `action_hash` |
| Leaf-value decode | exactly 64 lowercase-hex `action_hash` → 32 bytes |

A different tree hash or a different leaf rule is a **breaking change** and MUST be published as a new transparency version (a v2 tree), never a silent change under v1. Old and new versions coexist and remain independently verifiable — the same immutable-version discipline the rest of the standard follows (see [ADR 0012 — pin at signing](../../redesign/decisions/0012-taxonomy-versioning-pin-at-signing.md)).

---

## 8. Pointers

- [action-receipt.md](./action-receipt.md) — the signed receipt whose `action_hash` is the leaf value; transparency is outside its signed content.
- [chain.md](./chain.md) — the BLAKE3 session chain that defines leaf order (`seq`).
- [envelope.md](./envelope.md) — the in-toto/DSSE envelope; a relying party's full check is *verify the envelope* **then** *verify the inclusion proof* defined here.
- [conformance-and-envelope.md](../../redesign/standard/conformance-and-envelope.md) — the conformance model, the `rfc6962-roots` vectors, and the clean-room verifiers.
- [ADR 0008 — Tessera / `tlog-tiles`](../../redesign/decisions/0008-tessera-transparency-network.md) — the witnessed-network engine and the wire/leaf shape this module aligns to.
- [ADR 0012 — pin at signing](../../redesign/decisions/0012-taxonomy-versioning-pin-at-signing.md) — the immutable-version discipline mirrored in [§7](#7-versioning).
