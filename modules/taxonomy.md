# HESO/1 — Destructive-Primitive Taxonomy

**Status: Normative** · Module: `taxonomy` · HESO/1

> The canonical, deterministic, **structural** classification of what an agent
> action does to the world. `classify` is a **total** function over a **closed**
> predicate vocabulary, hashed and versioned, that maps every action to a stable
> class, primitive, and outcome. The spine has exactly **five destructive
> primitives**; `observe` and `residual` are outcomes, not extra primitives.

The gold-master data this prose defines is the **taxonomy bundle**:
[`../taxonomy.toml`](../taxonomy.toml) for the core spine,
[`../registry.toml`](../registry.toml) for active extension discovery, and the
manifest files under [`../taxonomy/extensions/`](../taxonomy/extensions/). The
prose is the normative interpretation; the data files are the executable rules.
A clean-room re-implementer MUST be able to build a byte-identical classifier
from this module plus that bundle plus the published `taxonomy-classify` vectors,
with no access to the kernel source.

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY are to be
interpreted as in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

Sibling modules: [observed-facts.md](./observed-facts.md) (defines the normalized
facts classification consumes), [action-receipt.md](./action-receipt.md) (carries
the classification + the pinned hash), [envelope.md](./envelope.md) (the DSSE /
in-toto wrapper), and [transparency.md](./transparency.md) (the log the
classified receipt is admitted to).

---

## 1. The five destructive primitives (the canonical spine)

Every agent action that touches the world MUST be classified, by its
**structural effect**, into exactly one of five destructive primitives. An action
MUST NOT be classified by the name of the tool, function, or framework that
emitted it. *Classify by effect, not by name* is the whole discipline: a tool
called `helper.run()` that issues a card charge is **`move-value`**, never
`execute`, because of what it does to the world, not what it is called.

| Primitive | Effect on the world | Canonical rail-boundary example |
|---|---|---|
| **`move-value`** | Transfers economic value out of the principal's control | a payment / charge / payout / transfer |
| **`destroy`** | Irreversibly removes or mutates state | a delete / drop / overwrite / terminate; AWS `DeleteObject`, `TerminateInstances` |
| **`change-authority`** | Alters who can do what — identity, grants, roles, keys | an IAM grant, role change, key rotation, account modification |
| **`disclose`** | Sends in-scope data across a trust boundary | a bulk data export, a secret read, a transfer-out of sensitive rows |
| **`execute`** | Runs an effectful action that is none of the above | a generic tool call, an HTTP request, a code/command run |

These five — and only these five — are the **spec spine**. The closed core set
is fixed by this module; it MUST NOT be grown except by a superseding ADR. Growth
happens only at the *leaves*, via the namespaced extension mechanism (§7), and an
extension MUST map onto one of these five — it MUST NOT invent a sixth primitive.

Two handling rules complete the picture so the function is total:

- **`observe`** — the *non-destructive* sibling of `execute`. A read, a model /
  LLM call, or a retrieval whose structural effect is read-only and crosses no
  disclosure boundary is `observe`, while the same surface with a world-changing
  effect is `execute`. The split is **structural** (does the call change or leak
  the world?), never nominal. `observe` is a benign outcome, not a primitive that
  policy gates by default.
- **`residual`** — the explicit **unresolved** lane. When no predicate row
  matches, the action MUST NOT silently become `execute` or "safe"; it lands in
  `residual` and is treated under **deny-unknown** discipline (§4). `residual` is
  a first-class outcome, not an error.

This module's canonical spine reconciles with the shipped **frozen-7 coarse
verbs** in §6. The verbs are a descriptive sub-vocabulary that maps onto the
five; the **five primitives, not the verbs, are canonical**. Read §6 before
assuming the verbs and primitives are 1:1 — they are close but not identical.

---

## 2. The predicate vocabulary

Classification is driven by a **closed set** of predicate kinds. A re-implementer
MUST NOT invent a new predicate kind; the vocabulary is fixed by this module and
any growth is a spec change (a new ADR + vectors), never an ad-hoc field. This
closedness is what makes `classify` deterministic across Rust, Python,
TypeScript, and the clean-room verifier.

### 2.1 The closed kind set

The canonical kind names are exactly those in `taxonomy.toml`. An unknown kind
MUST be a load-time error (fail-closed), never a runtime guess.

| Predicate kind | Matches on | Parameter keys | Example |
|---|---|---|---|
| `host_set` | the resolved destination host | `hosts` (exact, lower-cased) · `host_suffixes` (e.g. `.stripe.com`) | `api.stripe.com`, `*.amazonaws.com` |
| `path_glob` | the request path / realpath | `path_globs` (anchored, RE2-translatable; `*` = one segment, `**` = any) | `/v*/payment_intents*` |
| `method_set` | the parsed HTTP method | `methods` | `{POST, DELETE}` |
| `argv_token` | a **whole** argv / SQL token | `tokens` (token = a maximal alphanumeric run; never a substring) | `rm`, `drop`, `truncate` |
| `row_threshold` | the observed row/record count | `threshold` (matches when `row_count_estimate >= threshold`; absent count is no-match) | `rows >= 1000` |
| `fact_flag` | a single named boolean observed fact | `flag` (matches when the signed fact is `true`) | `is_payment`, `is_secret` |
| `always` | unconditional match (the residual floor) | — | the `unresolved` class only |

Two notes a re-implementer MUST honour:

- **`path_glob` is anchored and segment-aware.** `*` matches exactly one path
  segment; `**` matches any number. There is no fuzzy or substring matching. Two
  conformant implementations MUST agree on the RE2-translation; the
  `taxonomy-classify` vectors pin the edge cases.
- **`row_threshold` and `fact_flag` are what make the taxonomy structural rather
  than surface-string matching.** "1,000+ rows leaving" is a disclosure
  regardless of which endpoint served it. An absent `row_count_estimate` is a
  no-match; an observed but indeterminate count MUST be represented by
  `row_count_unknown = true`, which fails safe into `bulk_data`.

### 2.2 How predicates and rows compose

A taxonomy **class** is a list of predicate **rows**.

- **Within a row, predicates AND together** — all parameters of the row's kind
  must hold for the row to match. (In the gold master each `[[class.predicate]]`
  is a single-kind row; an implementation MUST treat a row as matched only when
  that row's kind matches.)
- **Across rows, classes OR** — a class matches if **any** of its rows matches.
  This is how "payment-API path grammar OR the `is_payment` body fact =>
  `payment_endpoint`" is encoded on the core class. Provider host rows are added
  by active extension manifests from the registry.

### 2.3 Priority order — first match wins

Classes are evaluated in a **fixed priority order**, highest structural impact
first, and the **first class that matches wins**. Order is **semantic**, not
cosmetic, and it is fixed by the order of `[[class]]` blocks in `taxonomy.toml`.
The shipped priority, high to low:

```
payment_endpoint  >  destructive_op  >  identity_endpoint  >  secret_store  >
bulk_data  >  model_endpoint  >  messaging_endpoint  >  generic_network  >
local_compute  >  unresolved (residual)
```

This encodes that **`move-value` beats `execute`** when an action is *both* a
payment and an HTTP request, and that a **`destroy` of an IAM resource is first a
`destroy`** (it sits above `identity_endpoint`). An action is classified by its
**most consequential** structural effect; ties are broken by this fixed order,
**not** by evaluation order in any one implementation. Same `taxonomy.toml` +
same action ⇒ same primitive, everywhere.

---

## 3. The classes (gold-master, normative)

The ten classes in [`../taxonomy.toml`](../taxonomy.toml) are the normative
realisation of the spine. Each class carries a stable `id`, a frozen `coarse_verb`
(§6), a structural `effect`, and its OR-ed predicate rows. The full predicate
parameter sets are defined **once** in the taxonomy bundle and MUST NOT be
restated here — this table is the index, the bundle is the data.

| # | Class `id` | `coarse_verb` | `effect` | Canonical primitive (§6) | Matched by |
|---|---|---|---|---|---|
| 1 | `payment_endpoint` | `payment` | `spend` | **`move-value`** | payment-API path grammar · `is_payment` fact · registered payment-provider extensions |
| 2 | `destructive_op` | `delete` | `destroy` | **`destroy`** | `DELETE` method · destructive argv/SQL tokens · `effect_destructive` fact |
| 3 | `identity_endpoint` | `account_change` | `grant` | **`change-authority`** | permission-mutation path grammar · `is_identity_change` fact · registered identity-provider extensions |
| 4 | `secret_store` | `data_export` | `transfer_out` | **`disclose`** | secret-path globs · `is_secret` fact · registered secret-store extensions |
| 5 | `bulk_data` | `data_export` | `transfer_out` | **`disclose`** | `row_count_estimate >= 1000` · `row_count_unknown` fact |
| 6 | `model_endpoint` | `llm_call` | `observe` | **`execute`** primitive, `observe` outcome | inference path grammar · `is_model_call` fact · registered model-provider extensions |
| 7 | `messaging_endpoint` | `http_request` | `transfer_out` | **`execute`** | comms path grammar · registered messaging-provider extensions |
| 8 | `generic_network` | `http_request` | `transfer_out` | **`execute`** / **`observe`** | `has_host` fact · any parsed HTTP method |
| 9 | `local_compute` | `tool_call` | `mutate` | **`execute`** / **`observe`** | `is_local_compute` fact |
| 10 | `unresolved` | `tool_call` | `effect_unknown` | **`execute`** primitive, `residual` outcome | `always` (unconditional residual) |

The `effect` token is one of the closed structural-effect set:
`observe | mutate | destroy | transfer_out | spend | grant | effect_unknown`.
This is a descriptor on the class. The **primitive** is the canonical
classification of record and is derived per §6. The **outcome** is derived from
the class: `observe` for read-only `observe` effects, `residual` for
`unresolved`, and `destructive` for the five destructive primitive lanes.

---

## 4. Totality and deny-unknown

`classify` is a **total** function over a **closed** vocabulary. Three
properties, all enforced **mechanically**, define conformance:

1. **Totality.** Every possible action MUST map to exactly one outcome. There is
   no "no result" / `null` branch. Totality is guaranteed by the unconditional
   `unresolved` class (kind `always`, evaluated last) and MUST be enforced at
   **parse time** of `taxonomy.toml`: a parser SHALL refuse to load a taxonomy
   whose last class is not an unconditional residual, so an incomplete taxonomy
   fails to load rather than silently leaking actions.
2. **Closed vocabulary.** Only the seven predicate kinds in §2.1 exist. An
   unknown kind MUST be a load error, not a runtime guess. The structural-effect
   set and the coarse-verb set are likewise closed.
3. **Deny-unknown.** When no class's rows match, the action resolves to
   `residual` (the `unresolved` lane). `residual` MUST be treated as
   **deny-unknown**: the *least*-trusted classification, gated as if it were the
   most dangerous primitive until a human or policy says otherwise. The gate
   **fails closed** on `residual`. Unknown ⇒ unsafe.

The combination is the safety property the assurance story rests on: an action
can never reach the world through a HESO gate having been *silently* deemed safe.
Either it classified to a known primitive (and was gated accordingly), or it
landed in `residual` (and was denied / escalated). There is no third door.
"Allow" is never a default.

---

## 5. `taxonomy_hash`: canonicalization and versioning

The taxonomy is **content-addressed**. `taxonomy_hash` is the version identifier
both parties cite to prove they classified under the same rules. Getting the
canonicalization byte-exact is what makes two independent implementations agree
on *which version they speak*.

### 5.1 The canonicalization rule (exact)

```
taxonomy_hash = BLAKE3( RFC8785-JCS( normative_projection(parsed_taxonomy_bundle) ) )
```

Computed in three steps, in this order:

1. **Parse + validate** the taxonomy bundle: `taxonomy.toml`, `registry.toml`,
   and every active extension manifest named by the registry. Totality,
   closed-vocabulary, namespace, target-class, and primitive-match checks MUST
   pass first; an invalid bundle has no hash.
2. **Normative projection.** Project the parsed bundle to a JSON value that
   contains **only normative classification inputs** and **nothing else**. The
   projection has this top-level shape:

   ```json
   {
     "projection_version": 1,
     "coarse_verb_map": { "...": "..." },
     "classes": [ "...ordered class projections..." ],
     "extensions": [ { "id": "<ns>/<name>", "hash": "<extension_hash>" } ]
   }
   ```

   - **Include:** the ordered list of classes, each with its `id`,
     `coarse_verb`, `effect`, and its ordered list of predicate rows; each row's
     `kind` and that kind's parameter set (`hosts`, `host_suffixes`,
     `path_globs`, `methods`, `tokens`, `threshold`, `flag` — whichever the kind
     defines). **Class order and row order are part of the projection** (priority
     is semantic, §2.3) and MUST be preserved. The class list is projected after
     active `extend` manifests have appended their rows.
   - **Include:** the frozen coarse-verb-to-primitive map (§6) and the sorted
     list of active extension ids plus their `extension_hash`.
   - **Exclude:** all comments, all whitespace, all TOML key ordering, and all
     **descriptive** data — in particular the auditor labels in
     [`catalog.toml`](../catalog.toml) are *not* part of the projection. Descriptive
     churn MUST NOT move the hash. The hash tracks **behavior**, not prose.
3. **Canonicalize + hash.** Serialize the projection with **RFC 8785 (JCS)**
   canonical JSON (the same canonicalization the kernel uses for receipt bodies —
   see [action-receipt.md](./action-receipt.md)), then take the **BLAKE3** digest
   of those canonical bytes. The hex digest is `taxonomy_hash`.

Because JCS sorts object keys and fixes number/string formatting, and because the
projection strips everything non-normative, two implementations that follow this
rule produce a **byte-identical** `taxonomy_hash` for the same classification
behavior — and a **different** hash the instant any class, predicate, parameter,
or ordering changes. The `taxonomy-classify` conformance vectors include the
expected `taxonomy_hash`, so an implementation that canonicalizes or hashes
differently is caught mechanically.

### 5.2 Versioning policy — pin at signing

The rules a conformant implementation MUST follow:

- **Every receipt pins the `taxonomy_hash` it was classified under.** A signed
  [ActionReceipt](./action-receipt.md) carries the hash, so a verifier can prove
  *which* version of the taxonomy produced the classification — auditable, not
  asserted.
- **Verification always checks against the pinned version, never the latest.** An
  old receipt MUST verify under its own era's rules forever ("law at the time of
  signing"). A bug-fix MUST NOT orphan prior history.
- **Any change is a new, published, immutable version** (a new hash). The old
  version stays published and verifiable forever. An implementation MUST NOT
  silently mutate a published version — same immutability discipline as accepted
  ADRs and applied migrations.
- **Verification (pinned) is separate from analysis (latest).** Analysis /
  alerting MAY re-run today's taxonomy over old actions to surface "this would be
  classified differently now" — that is a **new finding**, never a rewrite of the
  old receipt. Old and new versions coexist (the CT v1/v2 precedent).

---

## 6. Reconciliation: the frozen-7 coarse verbs → the five primitives

This is the **load-bearing** mapping of the whole module. The shipped kernel and
the gold-master `taxonomy.toml` were built around **seven frozen coarse verbs** —
`payment`, `delete`, `account_change`, `data_export`, `llm_call`,
`http_request`, `tool_call`. The canonical spine is the **five destructive
primitives**. They are close but **not** 1:1. HESO/1 resolves this by making the
five the canonical spine and mapping the seven verbs onto them; it does **not**
paper over the gap with a cross-reference.

The mapping below is normative. It is immutable for HESO/1 unless a superseding
module version is published:

| Frozen-7 verb | Primitive |
| --- | --- |
| `payment` | `move-value` |
| `delete` | `destroy` |
| `account_change` | `change-authority` |
| `data_export` | `disclose` |
| `http_request` | `execute` (effect-classified at the gate) |
| `tool_call` | `execute` (effect-classified at the gate) |
| `llm_call` | `execute` (effect-classified at the gate) |

### 6.1 The coarse-verb laxity lattice

The seven verbs form a strict→lax lattice, used to reject any override that
**widens** a built-in classification:

```
payment > delete > account_change > data_export > llm_call > http_request > tool_call
```

A customer override (§7) MAY keep a built-in class's `coarse_verb` or refuse the
action; it MUST NOT relabel a built-in to a **laxer** verb (monotonic narrowing).
The loader MUST reject any down-lattice relabel at load time, fail-closed.

### 6.2 The three mechanism verbs collapse to `execute`

`http_request`, `tool_call`, and `llm_call` are **mechanism** verbs, not effect
verbs — they describe *how* an action was issued, not *what* it does. At the
spine level they collapse to **`execute`**. Crucially:

- **The gate re-classifies their actual effect where it can detect one.** An
  `http_request` whose structural fingerprint matches a payment rail is
  `move-value`, not `execute` — the priority order (§2.3) puts
  `payment_endpoint` above `generic_network`, so the consequential effect wins
  before the mechanism class is ever reached. Likewise an `http_request` to an
  IAM host is `change-authority`, and a large export is `disclose`.
- **Where the gate cannot detect a more specific effect, the action lands in
  `execute`** (or, with a read-only structural effect, in the benign `observe`
  sibling — `model_endpoint` defaults to `observe`; a `local_compute` or
  `generic_network` read is `observe`, the same surface with a world-changing
  effect is `execute`). `execute` is therefore the **catch-all to watch for
  under-classification**.
- **The verb is preserved on the receipt as a descriptor, never as the
  classification of record.** Mechanism signal survives (an auditor still sees it
  was a Stripe `payment` or an `http_request`) — it just rides along; the
  primitive is the canonical fact.

### 6.3 Legacy receipts carry a verb, not a primitive

Already-signed frozen-7 receipts stay **byte-stable and verifiable forever**. The
mapping table above is applied at **read / classify time**, not by re-signing —
which is exactly why the table is itself normative and lives in the spec (and in
this module). A verifier reading a legacy receipt maps its recorded verb to the
primitive via §6's table; it MUST NOT re-sign or mutate the receipt to "upgrade"
it.

---

## 7. Namespaced extension and the registry process

The taxonomy is extensible **without forking the spine**. Extension is
**add-only**, **namespaced**, and **monotonic**. The first-party `heso/*`
provider manifests use the same mechanism as third parties; they are not special
hard-coded branches in the classifier.

### 7.1 Namespacing rules

- A **bare** (un-namespaced) `id` is **reserved for the core HESO/1 taxonomy**.
  An implementation MUST reject a core-namespace name it does not recognise
  (deny-unknown applies to *names* too).
- An extension `id` MUST be namespaced `<ns>/<name>` (e.g.
  `acme/internal-ledger`, `myco/pii-egress`). `<ns>` is the registered namespace;
  `<name>` is the extension-local manifest name.
- HESO/1.1.0 registry entries support `kind = "extend"` only. An extension
  manifest MUST target one existing core class and MUST map to that class's
  primitive. Extensions add resolution detail; they MUST NOT invent a sixth
  primitive. The spine is fixed; only the leaves grow.

### 7.2 What an extension MAY and MUST NOT do

A conformant loader MUST enforce, fail-closed at load time:

- An extension **MAY add predicate rows** to one built-in class via an `extend`
  manifest. First-party provider packs use this to add `host_set` rows outside
  the core spine. This strictly **grows** what is caught, which is always safe.
- An extension **MUST NOT** relabel a built-in class's `coarse_verb` to a laxer
  one (§6.1 lattice), **MUST NOT** add an `unresolved`-laxing rule, and **MUST
  NOT** redefine a built-in `id`.

Because extensions can only grow what an existing class catches, an extension can
never make a previously-gated action *pass* — it can only move an action into a
same-or-stricter named core lane.

### 7.3 The registry process

Extensions are recorded in an **open, machine-readable registry** governed by the
spec repo, the single source of truth for what every `<ns>/` name means. The
process:

1. **Namespace allocation.** A third party requests a namespace via a spec-repo
   contribution (see the repo's `CONTRIBUTING.md` / `GOVERNANCE.md`). Namespaces
   are first-come, collision-free, and recorded in the registry; a namespace MUST
   NOT be reassigned once allocated.
2. **Manifest registration.** Registering an extension means contributing (a)
   its namespaced `id` + `kind = "extend"` + target class + primitive, (b) its
   manifest file with predicate rows over the **same closed vocabulary** (§2 —
   no new predicate kinds), and (c) `taxonomy-classify` vectors proving its
   behavior.
   Registration is a spec-repo change with vectors, **not** a private edit to a
   vendored copy.
3. **Discovery.** The registry gives relying parties a single place to look up
   what an extension means, so an auditor encountering `acme/internal-ledger` on
   a receipt can resolve it to a known primitive and a known structural test.

This is how HESO stays an *open trust standard* and not a vendor's private
taxonomy: anyone can extend within the discipline, in the open, against the same
closed predicate vocabulary, mapping to the same five primitives.

> **Distinct from policy-rule namespacing.** This section governs
> **taxonomy-class** extensions — structural, spec-repo-governed, registry-backed.
> A customer naming a *local policy rule* `<ns>/<name>` in their `heso.toml` is a
> separate, local concern; a policy rule *references* a primitive/class, it never
> extends the taxonomy. The two namespaces are deliberately kept apart.

---

## 8. Conformance and the vendor contract

- **One canonical home.** This module plus the taxonomy bundle
  ([`../taxonomy.toml`](../taxonomy.toml), [`../registry.toml`](../registry.toml),
  and [`../taxonomy/extensions/`](../taxonomy/extensions/)) are the only
  normative home of the taxonomy. The kernel classifier, every SDK, the gate, and
  the conformance vectors point here; nothing restates the spine.
- **Vendored via pinned-sha + drift gate.** Implementation repos MUST vendor
  the taxonomy bundle pinned to a specific `heso-spec` commit sha, and a CI drift
  gate MUST fail the build if any vendored copy differs from `heso-spec@<sha>`.
  Impl repos MUST NOT hand-copy or fork the data files.
- **Proven by vectors.** The `taxonomy-classify` goldens (structural input →
  primitive + coarse verb + `taxonomy_hash`) are the cross-language test corpus;
  the Rust reference, the clean-room Python `classify()`, and the WASM verify
  surface MUST all agree on them.
- **Bound into receipts.** Receipts carry the classification and the pinned
  `taxonomy_hash`. The DSSE/in-toto envelope wraps the receipt; it does not
  redefine classification. See [action-receipt.md](./action-receipt.md) and
  [envelope.md](./envelope.md).

---

## 9. Pointers

- **Gold-master data** — [`../taxonomy.toml`](../taxonomy.toml),
  [`../registry.toml`](../registry.toml), and
  [`../taxonomy/extensions/`](../taxonomy/extensions/).
- **Sibling modules** — [action-receipt.md](./action-receipt.md) ·
  [envelope.md](./envelope.md) · [transparency.md](./transparency.md) ·
  [observed-facts.md](./observed-facts.md)
- **Conformance vectors** — [`../vectors/`](../vectors/)
