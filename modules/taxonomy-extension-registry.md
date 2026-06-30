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

Without a registry, "extensible" is a comment in the taxonomy bundle, not a
process. Two vendors could both
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

> **Distinct from policy-rule namespacing.** This registry governs taxonomy
> extension manifests only. A customer naming a *local policy rule* `<ns>/<name>` in their
> `heso.toml` is a separate, local concern (RFC-0005) — a policy rule *references*
> a primitive; it never extends the taxonomy and never appears in this registry.

---

## 3. What an extension may and may not do

An extension is **add-only, namespaced, and monotonic** — exactly the grammar the
taxonomy bundle loader enforces fail-closed. HESO/1.1.0 supports registered
`kind = "extend"` manifests only:

An extension MAY:

- Add predicate rows to a built-in class through an `extend` manifest — strictly
  **growing** what is caught. First-party provider packs use this for well-known
  host facts.

An extension MUST NOT:

- Introduce a sixth primitive. Every extension `primitive` MUST be one of the
  five canonical primitives.
- Relabel a built-in class's `coarse_verb` / primitive to a **laxer** one
  (monotonic narrowing — never widen what reaches the world).
- Add a rule that laxes the `unresolved` residual.
- Redefine, shadow, or remove a built-in (bare-name) id.
- Weaken the taxonomy bundle hash. Active extensions are part of the bundle
  projection, and each extension also has its own content hash.

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
2. **Define the `extend` manifest** under `taxonomy/extensions/<ns>/`, mapped to
   exactly one target class and that class's primitive (§3).
3. **Add a `[[extension]]` entry** to [`../registry.toml`](../registry.toml) with
   `id`, `kind`, `target_class`, `primitive`, `manifest`, `summary`, `vectors`,
   `status = "active"`, and `registered`.
4. **Ship classify vectors.** Add a `taxonomy-classify` golden set covering the
   extension (input facts → expected target class + primitive + `taxonomy_hash`),
   generated from the reference — **never hand-written**. The
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
  stay published and verifiable forever.
- A namespace, once allocated, is never reassigned to a different owner.
- A change to an extension's *behavior* is a new immutable taxonomy version (a new
  `taxonomy_hash`), the same as any taxonomy change — see
  [`taxonomy.md` §4](./taxonomy.md) and [`../GOVERNANCE.md` §4](../GOVERNANCE.md).

---

## 6. The current registry

The registry currently allocates the first-party `heso` namespace and active
well-known provider packs:

- `heso/payment-providers`
- `heso/identity-providers`
- `heso/secret-stores`
- `heso/model-providers`
- `heso/messaging-providers`

These packs are governed registry data, not core spine. They can grow by
published versioned manifests and vectors without turning HESO/1 into a giant
hard-coded vendor list.

---

## 7. See also

- [`taxonomy.md`](./taxonomy.md) — the taxonomy module (the five primitives, the
  predicate vocabulary, `taxonomy_hash`, the namespaced-extension rule this
  registry implements).
- [`../registry.toml`](../registry.toml) — the machine-readable ledger.
- [`../GOVERNANCE.md`](../GOVERNANCE.md) — versioning & the extension policy.
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — the contribution + conformance-vector
  requirement.
- [`../taxonomy.toml`](../taxonomy.toml) and
  [`../taxonomy/extensions/`](../taxonomy/extensions/) — the core spine and
  registered extension manifests.
