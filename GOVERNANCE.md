# HESO/1 Governance — Versioning & Extension Policy

**Status: Normative (process)**

This document governs how the HESO/1 open standard evolves: how it is
versioned, what counts as a breaking change, how `taxonomy_hash` gates
compatibility, and the RFC-style process for making normative changes. It uses
RFC-2119 keywords (MUST / SHOULD / MAY).

`heso-spec` is the **sole home** of HESO/1. Implementations vendor *from* this
repo (pinned to a commit SHA, with a CI drift gate); they MUST NOT shadow or
privately fork the normative artifacts. Any change to those artifacts is
governed by this document.

---

## 1. What is under governance

The governed surface is exactly the **normative** material a third party
verifies against:

| Artifact | Home | Versioning unit |
|---|---|---|
| Destructive-primitive taxonomy bundle | [`taxonomy.toml`](./taxonomy.toml) + [`registry.toml`](./registry.toml) + [`taxonomy/extensions/`](./taxonomy/extensions/) + [`modules/taxonomy.md`](./modules/taxonomy.md) | `taxonomy_hash` (content-addressed) + a HESO/1 taxonomy version label |
| ActionReceipt format | [`modules/action-receipt.md`](./modules/action-receipt.md) (+ [`action-receipt-v1.md`](./modules/action-receipt-v1.md)) | module SemVer + `predicateType` URI version |
| Session chain | [`modules/chain.md`](./modules/chain.md) | module SemVer |
| Transparency | [`modules/transparency.md`](./modules/transparency.md) | module SemVer |
| Time-anchor | [`modules/time-anchor.md`](./modules/time-anchor.md) | module SemVer |
| Quorum | [`modules/quorum.md`](./modules/quorum.md) | module SemVer |
| Envelope (in-toto + DSSE) | [`modules/envelope.md`](./modules/envelope.md) | `predicateType` URI version |
| Web-observation (plat/cassette) | [`modules/web-observation.md`](./modules/web-observation.md) / [`HESO-1.0.md`](./HESO-1.0.md) | module SemVer |
| Conformance vectors | [`vectors/`](./vectors/) | regenerated from the reference, never hand-edited |
| Taxonomy-extension registry | [`registry.toml`](./registry.toml) + [`modules/taxonomy-extension-registry.md`](./modules/taxonomy-extension-registry.md) | append-only ledger |

The **auditor catalog** ([`catalog.toml`](./catalog.toml)) is open but
descriptive, not the structural spine. Edits to it are governed for collision-
freedom but **never move `taxonomy_hash`** (§4.3).

**Out of scope of this standard** (governed elsewhere, in the closed cloud):
compliance `controls.toml`, the compliance packs, the commitment store, and the
proof/exhibit builder. See the spec map's open/closed split.

---

## 2. The version model

HESO/1 is a **suite of independently-versioned modules**, not one omnibus
document. This is deliberate: a relying party can conform to "action-receipt +
chain + transparency" without claiming time-anchor or quorum, and a module can
ship a patch without re-versioning the whole suite.

### 2.1 Three coordinates

1. **Suite version** — `HESO/1`. The major suite identity. A `HESO/2` would be a
   parallel, coexisting suite (the CT v1/v2 precedent), never an in-place mutation
   of `HESO/1`.
2. **Module version** — each module carries a `MAJOR.MINOR.PATCH` SemVer in its
   own spec file header. The meaning is normative (§3).
3. **Content-addressed version** — the taxonomy is *additionally* content-
   addressed by `taxonomy_hash` ([taxonomy.md §4](./modules/taxonomy.md)) and the
   envelope predicate by its `predicateType` URI. These are the bytes a verifier
   actually pins against; the human-facing labels are for citation.

### 2.2 SemVer, applied to a normative spec

For a module spec, SemVer means **conformance compatibility**, not API surface:

- **PATCH** — editorial only. Clarifications, typo fixes, added examples, tighter
  prose. MUST NOT change any conforming implementation's behavior and MUST NOT
  change any vector or any hash.
- **MINOR** — backward-compatible additive change. A conformant
  *verifier* for the new MINOR still accepts every artifact a conformant verifier
  for the prior MINOR accepted. New optional fields, new registered extensions,
  new vectors. MUST NOT invalidate previously-valid artifacts.
- **MAJOR** — breaking change (§3). Requires a superseding ADR and a new,
  coexisting version; the old version stays published and verifiable forever.

A module's version label MUST be present in its spec header and MUST move
according to these rules in the same change that lands the modification.

---

## 3. What is a breaking change

A change is **breaking** (MAJOR) if it can cause **any** of:

1. An artifact that was valid under the prior version to **fail** verification
   under the new version, or vice-versa (a verdict flip).
2. A byte change to canonicalization, the BLAKE3 domain-separation tags, the
   PAE pre-image, the verify order, or the signature pre-image — anything that
   changes the bytes a signer signs or a verifier checks.
3. A change to `taxonomy_hash` for the *same logical rulebook* (i.e. the
   canonical projection rules change, not the rows). Adding/removing/reordering
   rows is *also* a new taxonomy version, but is handled under §4 (it is never an
   in-place edit regardless).
4. A change to a `predicateType` URI's schema that an existing external verifier
   built against would reject.
5. Removal or narrowing of a previously-normative guarantee.

A change is **non-breaking** (MINOR) if it is strictly additive and every
previously-valid artifact stays valid: a new optional field a verifier ignores
if absent, a new registered taxonomy extension (which maps onto an existing
primitive — §4), a new conformance vector covering existing behavior, a new
module added to the suite.

A change is **editorial** (PATCH) if it changes no behavior, no bytes, and no
vector.

> **The hard rule:** you **never** mutate a published version to "fix" it in
> place. Same immutability discipline as an accepted ADR and an applied Supabase
> migration — an edited-after-publication version silently rewrites history that
> signed receipts depend on. A fix is always a **new forward version**; the old
> one stays published. This is the same immutable "pin at signing" rule defined in [§4](#4-taxonomy_hash-and-compatibility-gating).

---

## 4. `taxonomy_hash` and compatibility gating

The taxonomy is the load-bearing version surface, because every signed receipt
records the classifier it was minted under. The governance rule here directly
realizes **ADR-0012 — pin at signing, immutable versions**.

### 4.1 Pin at signing, verify against the pinned version

- Every receipt MUST pin the `taxonomy_hash` (and taxonomy version label) it was
  classified under.
- A verifier MUST verify a receipt against **its pinned** taxonomy version, never
  against the latest. An old receipt verifies under its own era's rules forever;
  a later bug-fix MUST NOT orphan it. This is the "law at the time of signing"
  principle.

### 4.2 Every change is a new, immutable published version

- Any change to the **normative classification bundle** (classes, rows,
  predicates, priority, coarse-verb mapping, active registry entries, or active
  extension manifests) produces a **new** `taxonomy_hash` and a **new** published
  version. The prior version stays published and conformance-vectored forever.
- A published taxonomy version MUST NOT be mutated. Old and new versions
  **coexist** (CT v1/v2 precedent).
- Each published version MUST ship: the canonical taxonomy-bundle projection, its
  `taxonomy_hash`, a `taxonomy-classify` golden vector set, and a `CHANGELOG.md`
  entry linking the superseded version.

### 4.3 What moves the hash, and what does not

`taxonomy_hash` is **BLAKE3 over the RFC-8785 (JCS) canonical projection** of the
**normative classification bundle only** — classes, rows, predicates, priority,
the verb→primitive mapping, and active registry extensions. It is deliberately
**not** computed over:

- Comments in `taxonomy.toml`.
- Non-normative registry or manifest metadata.
- The auditor labels in `catalog.toml` (descriptive layer).
- Any non-normative metadata.

So descriptive churn (catalog label edits, comment edits) **never** moves the
hash. The hash tracks **behavior**, not prose. A change that moves the hash is by
definition a new taxonomy version (§4.2); a change that does not move the hash is
editorial (PATCH) for the taxonomy module.

### 4.4 Verification vs analysis

Verification (pinned) and analysis (latest) are separate, per ADR-0012:

- **Verification** always uses the receipt's pinned taxonomy version.
- **Analysis / alerting** MAY re-run today's rulebook over old actions to surface
  "this would classify differently now." That is a **new finding**, not a rewrite
  of the old receipt. An implementation MUST NOT present a re-classification as if
  it changed the original signed record.

---

## 5. The extension policy

The taxonomy is extensible **without forking the spine**. The five destructive
primitives are a **closed core**; extensions add resolution detail at the leaves,
they never invent a sixth primitive.

- An extension (a vendor class, a private fact, a fine label) MUST be **namespaced**
  as `<ns>/<name>` (e.g. `acme/internal-ledger`). A bare, un-namespaced name is
  **reserved for the core HESO/1 taxonomy**.
- An extension MUST map, structurally, onto exactly one of the five canonical
  primitives. The spine is fixed; only the leaves grow.
- Implementations MUST reject a **core-namespace** name they do not recognize
  (deny-unknown applies to names, not just actions).
- Extensions are recorded in the open, machine-readable
  [taxonomy-extension registry](./registry.toml) — see
  [`modules/taxonomy-extension-registry.md`](./modules/taxonomy-extension-registry.md)
  for the registration process. Registering an extension is a spec-repo
  contribution **with conformance vectors**, not a private edit to a vendored
  copy.

> **Distinct from policy-rule namespacing.** This governs *taxonomy-class*
> extensions. A customer naming a *local policy rule* `<ns>/<name>` in their
> `heso.toml` is a separate, local concern (RFC-0005). A policy rule *references*
> a primitive; it never extends the taxonomy. The two namespaces are kept apart.

---

## 6. The spec-change (RFC) process

Normative changes follow an **RFC → review → ADR** flow that mirrors the project's
RFC discipline. The split is deliberate: an RFC works *out* an unsettled design;
an ADR records a decision *already made*.

1. **Open question.** A change starts as a problem statement. If the answer is
   obvious and the change is editorial/additive, skip to step 5 with a PR.
2. **RFC.** For any change that touches the wire contract, the trust model, the
   taxonomy spine, or adds a module, write an RFC: `Problem`, `Solution`,
   `Alternatives`, `Consequences`, and a **Conformance impact** section that
   states whether vectors, hashes, or the `predicateType` change. An RFC with no
   rejected alternatives is an ADR wearing a costume.
3. **Review.** `Draft` → `Reviewed`. Open threads resolved or explicitly deferred.
4. **ADR.** On acceptance, write a short, immutable, NNNN-numbered ADR that
   records the decision and links back to the RFC. The RFC flips to `Accepted`
   and stops changing. Reverse a decision only by a higher-numbered superseding
   ADR — never by editing the accepted one.
5. **Land it.** The PR MUST: update the affected module spec(s) and bump their
   version per §2/§3; regenerate (never hand-edit) any affected vectors; add a
   `CHANGELOG.md` entry; and, for taxonomy changes, publish the new
   `taxonomy_hash`. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the mechanics
   and the conformance-vector requirement.

Trivial work — fixing a typo, adding an example, wiring a lint gate — does **not**
need an RFC. Reserve RFCs for net-new modules and wire-contract / trust-model
changes.

---

## 7. License posture

Per the [`README.md`](./README.md) and [`NOTICE`](./NOTICE):

- **Spec text** (this file, the modules, `HESO-1.0.md`, the prose) — **CC BY 4.0**.
- **Conformance vectors** (`vectors/`) — **CC0** (public domain), so anyone can
  run conformance with zero friction.
- **`catalog.toml`** — open, but a deliberate descriptive layer, not the spine.
- The **HESO** name is a reserved trademark; "HESO/1-conformant" is a permitted
  description, "HESO" as a product name is not. See [`NOTICE`](./NOTICE).

The license boundary is the **repo** boundary: everything in `heso-spec` is the
open standard; the plan-gated compliance product lives in a separate, closed repo.

---

## 8. See also

- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to propose a change + the
  conformance-vector requirement.
- [`CHANGELOG.md`](./CHANGELOG.md) — per-module change history.
- [`SECURITY.md`](./SECURITY.md) — vulnerability disclosure.
- [`registry.toml`](./registry.toml) + [`modules/taxonomy-extension-registry.md`](./modules/taxonomy-extension-registry.md) — the namespaced extension registry.
- [`modules/taxonomy.md`](./modules/taxonomy.md) — the taxonomy spine and hash rule.
- [`modules/envelope.md`](./modules/envelope.md) — the in-toto/DSSE envelope binding.
