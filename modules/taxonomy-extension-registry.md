# Module: Taxonomy-Extension Registry

**Status: Normative (HESO/1)**

The open, machine-readable registry for **namespaced taxonomy extensions**. The
[taxonomy module](./taxonomy.md) mandates that any extension be namespaced
`<ns>/<name>` and map onto exactly one of the five canonical destructive
primitives. This module specifies the *process and ledger* that makes that
mandate real: where namespaces are allocated, how an extension is registered, and
what conformance it must carry. The machine-readable ledger is
[`../registry.toml`](../registry.toml).

Keywords MUST / SHOULD / MAY are RFC-2119.

---

## 1. Why a registry exists

The taxonomy spine is a **closed core of five primitives** — `move-value`,
`destroy`, `change-authority`, `disclose`, `execute`. It is deliberately not
extensible at the spine: nobody adds a sixth primitive. But the **leaves** must
grow — a vendor needs to teach the classifier that *their* internal ledger
endpoint is `move-value`, or that *their* PII-egress surface is `disclose`,
without forking the standard.

Without a registry, "extensible" is a comment in
[`../taxonomy.toml`](../taxonomy.toml), not a process. Two vendors could both
claim `internal-ledger`; nobody could discover what `acme/pii-egress` means; and
an extension could ship with no proof it classifies the way it claims. The
registry fixes all three:

- It makes `<ns>/` namespaces **collision-free** (one owner per namespace,
  append-only).
- It gives third parties a **single place to discover** what a registered
  extension means and which primitive it maps onto.
- It enforces that every extension ships **conformance vectors** — an extension
  is not conformant until a second implementation can prove it classifies as
  claimed.

This is what keeps HESO an *open trust standard* and not a vendor's private
taxonomy: anyone can extend, in the open, against the same closed predicate
vocabulary, mapping to the same five primitives.

---

## 2. The namespace rule

- A **bare, un-namespaced** name (`payment_endpoint`, `bulk_data`, …) is
  **RESERVED for the core HESO/1 taxonomy**. An extension MUST NOT use a bare
  name. Implementations MUST reject a core-namespace name they do not recognize
  (deny-unknown applies to names, not just actions).
- Every extension id MUST be `<ns>/<name>` where `<ns>` is an **allocated**
  namespace recorded in [`../registry.toml`](../registry.toml) and `<name>` is a
  lower-kebab token unique within that namespace.
- A namespace is allocated to **exactly one owner**, first-come, recorded once,
  and **never reassigned** (append-only).

> **Distinct from policy-rule namespacing.** This registry governs *taxonomy-class*
> extensions only. A customer naming a *local policy rule* `<ns>/<name>` in their
> `heso.toml` is a separate, local concern (RFC-0005) — a policy rule *references*
> a primitive; it never extends the taxonomy and never appears in this registry.

---

## 3. What an extension may and may not do

An extension is **add-only, namespaced, and monotonic** — exactly the grammar the
gold-master [`../taxonomy.toml`](../taxonomy.toml) loader enforces fail-closed:

An extension MAY:

- Add a new `[[class]]` whose `id` is `<ns>/<name>`. A new class is inserted by
  priority **just above the `unresolved` residual** — it can only **narrow** the
  residual lane, never pre-empt a built-in dangerous lane.
- Add members to a built-in class's predicate sets via `[[extend]]` (more hosts /
  suffixes / path globs / argv tokens) — strictly **growing** what is caught.

An extension MUST NOT:

- Introduce a sixth primitive. Every extension `primitive` MUST be one of the
  five canonical primitives.
- Relabel a built-in class's `coarse_verb` / primitive to a **laxer** one
  (monotonic narrowing — never widen what reaches the world).
- Add a class that laxes the `unresolved` residual.
- Redefine, shadow, or remove a built-in (bare-name) id.
- Move `taxonomy_hash` for the core taxonomy. A registered extension is its own
  versioned artifact; it does not mutate the core spine's hash.

The loader rejects any violation at load time (fail-closed), and the registry
review rejects any registration that violates these rules.

---

## 4. The registration process

Registering an extension is a **spec-repo contribution with conformance vectors**,
not a private edit to a vendored copy. The steps, per
[`../CONTRIBUTING.md`](../CONTRIBUTING.md):

1. **Allocate (or reuse) a namespace.** Add a `[[namespace]]` entry to
   [`../registry.toml`](../registry.toml) with `ns`, `owner`, `contact`,
   `registered`, and an optional `homepage`. If your namespace already exists, skip
   this step.
2. **Define the extension** in your own `[[class]]` / `[[extend]]` form, mapped to
   exactly one of the five primitives (§3).
3. **Add a `[[extension]]` entry** to [`../registry.toml`](../registry.toml) with
   `id`, `kind` (`class` | `extend`), `primitive`, `summary`, `vectors`, `status`
   = `"active"`, and `registered`.
4. **Ship classify vectors.** Add a `taxonomy-classify` golden set covering the
   extension (input facts → expected `<ns>/<name>` class + primitive +
   `taxonomy_hash`), generated from the reference — **never hand-written**. The
   `vectors` field MUST point at them. An extension with no published classify
   vectors is **NOT conformant** and MUST NOT be merged.
5. **Prove the second implementation agrees.** The clean-room verifier must
   classify the extension's vectors identically. Extend it in the same PR if
   needed.
6. **Changelog.** Add a `CHANGELOG.md` entry under the `taxonomy` module.

A wire/trust-affecting extension (one that changes the predicate vocabulary
itself — which an extension must NOT do) would require an RFC; a normal
leaf-extension does not, but it always requires the vectors above.

---

## 5. Lifecycle and immutability

[`../registry.toml`](../registry.toml) is **append-only**:

- An extension is **retired** by setting `status = "deprecated"` (and optionally
  `superseded_by`), **never** by deletion. Old receipts that referenced the
  extension must still resolve, and old `taxonomy_hash` versions that included it
  stay published and verifiable forever ([ADR-0012](../../redesign/decisions/0012-taxonomy-versioning-pin-at-signing.md)).
- A namespace, once allocated, is never reassigned to a different owner.
- A change to an extension's *behavior* is a new immutable taxonomy version (a new
  `taxonomy_hash`), the same as any taxonomy change — see
  [`taxonomy.md` §4](./taxonomy.md) and [`../GOVERNANCE.md` §4](../GOVERNANCE.md).

---

## 6. The current registry

The core HESO/1 taxonomy ships with **zero** registered extensions. The empty
[`../registry.toml`](../registry.toml) is intentional — it stands the process up
before anyone needs it, so the first third-party namespace has a real, discoverable
home rather than an ad-hoc edit. See the commented example shape in that file.

---

## 7. See also

- [`taxonomy.md`](./taxonomy.md) — the taxonomy module (the five primitives, the
  predicate vocabulary, `taxonomy_hash`, the namespaced-extension rule this
  registry implements).
- [`../registry.toml`](../registry.toml) — the machine-readable ledger.
- [`../GOVERNANCE.md`](../GOVERNANCE.md) — versioning & the extension policy.
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — the contribution + conformance-vector
  requirement.
- [`../taxonomy.toml`](../taxonomy.toml) — the gold-master data and its extension
  grammar (`[[class]]` / `[[extend]]`, monotonic narrowing).
