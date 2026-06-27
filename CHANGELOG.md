# Changelog — HESO/1

**Status: Normative (process)** · Per-module change history for the HESO/1 open
standard. The format is per-module (not one flat list) because the standard is a
suite of independently-versioned modules — see
[`GOVERNANCE.md` §2](./GOVERNANCE.md).

Each entry records: the module version, the date, a one-line summary, and links
to the governing RFC/ADR. Editorial (PATCH) entries are kept terse; normative
(MINOR/MAJOR) entries link the conformance vectors that landed with them.

> Immutability reminder ([GOVERNANCE §3](./GOVERNANCE.md)): published versions are
> never mutated in place. Every fix is a new forward version; superseded versions
> stay published and verifiable. This log is append-only.

---

## Suite

### HESO/1 — 2026-06-18 — P1 absorption (in progress)

`heso-spec` becomes the **sole home** of HESO/1. The crown jewels (taxonomy,
ActionReceipt, transparency, envelope) move out of the closed repos into this
open repo; the web-observation spec is demoted from "the spec" to one module of
the suite. Governance artifacts (this file, `GOVERNANCE.md`, `CONTRIBUTING.md`,
`SECURITY.md`, the taxonomy-extension registry) are added — the repo previously
had none.

- Realises: [refactor/spec-repo.md](../redesign/refactor/spec-repo.md) (P1).
- Locks applied: [ADR-0001 — taxonomy spine (5 primitives)](../redesign/decisions/0001-taxonomy-spine.md),
  [ADR-0009 — in-toto/DSSE envelope](../redesign/decisions/0009-in-toto-dsse-envelope.md),
  [ADR-0012 — versioning, pin at signing](../redesign/decisions/0012-taxonomy-versioning-pin-at-signing.md).

---

## taxonomy

### 1.0.0 — 2026-06-18 — initial normative prose + gold-master data

- `taxonomy.toml` lifted **verbatim** (byte-identical) from the closed enterprise
  repo and made the open gold-master data.
- New normative prose module `modules/taxonomy.md`: the five destructive
  primitives (`move-value` / `destroy` / `change-authority` / `disclose` /
  `execute`), the closed predicate vocabulary, totality + deny-unknown, the
  `taxonomy_hash` canonicalization (BLAKE3 over the RFC-8785/JCS projection of
  the normative classification data only), and the FROZEN-7 → 5 reconciliation.
- Canonical spine fixed at **5 primitives** with the 7 coarse verbs as a
  descriptive sub-vocabulary mapping onto it ([ADR-0001](../redesign/decisions/0001-taxonomy-spine.md)).
- Versioning policy: pin-at-signing, immutable published versions
  ([ADR-0012](../redesign/decisions/0012-taxonomy-versioning-pin-at-signing.md)).
- New: open, machine-readable taxonomy-extension registry
  ([`registry.toml`](./registry.toml) + [`modules/taxonomy-extension-registry.md`](./modules/taxonomy-extension-registry.md)).
- Vectors: `taxonomy-classify` golden set (generated from the reference).

---

## action-receipt

### 2.0.0 — 2026-06-18 — absorbed as the default, omnibus split

- Absorbed from `ACTION-RECEIPT-2.0.md` as the default receipt format.
- `ACTION-RECEIPT-1.0.md` retained byte-stable as `modules/action-receipt-v1.md`
  so legacy receipts still verify forever.
- The v2 omnibus is **split** into focused modules so conformance is claimable
  per-module: `action-receipt` (core) / `chain` / `time-anchor` / `quorum` /
  `envelope`.
- The deferred `§3.5.1` receipt domain-separation TODO is resolved in the
  absorbed module (no TODO carried forward).
- Vectors: `action-receipt-v2` golden set (generated from the reference).

---

## chain

### 1.0.0 — 2026-06-18 — split out of the v2 omnibus

- The BLAKE3 hash-linked per-session audit chain, with its domain-separated link,
  extracted into its own module so it is independently conformance-claimable.
- Vectors: `chain` golden set.

---

## transparency

### 1.1.0 — 2026-06-27 — witness-quorum honesty rule (normative)

- **(D) Witness honesty: declared-but-unmet ⇒ fail closed; undeclared-absent ⇒
  valid silence.** New normative rule in §4: when a receipt or verifier configuration
  declares a witness or cosignature requirement and that requirement is present but
  unmet, a verifier MUST fail closed and MUST NOT surface the result as verified.
  The undeclared-absent case remains valid silence — no declared requirement, no
  cosignature present — and MUST be reported honestly as `NotWitnessed` (not a
  failure). A bare inclusion proof with no cosignature MUST NOT be described as
  "witnessed." The live external witness service is not yet operational; this rule
  governs verifier enforcement of any declared requirement regardless of network
  liveness.

### 1.0.0 — 2026-06-18 — absorbed

- Absorbed from `TRANSPARENCY-1.0.md`: RFC-6962 Merkle inclusion + consistency
  proofs over receipt commitments (the honesty boundary — proves inclusion, not
  truth).
- Vectors: `rfc6962-roots` (the published CT test-tree interop roots).

---

## time-anchor

### 1.1.0 — 2026-06-27 — published artifacts ship tsa; anchor_policy pipeline-stamped

- **(B) heso-wasm ships tsa verify.** The proof-page WASM build is now compiled
  with the `tsa` feature enabled. A valid RFC-3161 anchor on this surface resolves
  to `AnchoredRfc3161 { gen_time }`, not `TimeAnchorUnverifiable`. The verify side
  was always normative; this entry records that the blanket "tsa off ⇒
  `TimeAnchorUnverifiable`" framing no longer applies to the published WASM artifact.
- **(A) Published Python wheel ships tsa-net mint.** The published `heso` Python
  wheel is built with the `tsa` feature enabled and exposes `request_time_anchor`
  for production use. The `#[cfg(feature = "tsa")]` gate is a Rust source boundary,
  not a published-package boundary.
- **(C) Pipeline stamps `anchor_policy = "required"` when config-gated.** When
  `anchor_policy` enforcement is enabled in the HESO pipeline configuration, the
  pipeline stamps `anchor_policy = "required"` into `content` before signing; the
  verifier enforces it fail-closed per §4. Receipts produced without the config flag
  carry no `anchor_policy` and remain anchorless-by-default. See
  [`action-receipt.md §8 pipeline-stamp note`](./action-receipt.md).

### 1.0.0 — 2026-06-18 — split out of the v2 omnibus

- RFC-3161 TSA token binding over a receipt/checkpoint; verify side normative,
  request side feature-gated.

---

## quorum

### 1.0.0 — 2026-06-18 — split out of the v2 omnibus

- k-of-n approval re-derivation semantics (an L1 receipt with a `multi_approval`
  block; honestly narrower per approver, never a higher trust level).

---

## envelope

### 1.0.0 — 2026-06-18 — new: in-toto Statement + DSSE binding

- New module. ActionReceipt wrapped as an in-toto v1 Statement (HESO/1
  `predicateType` whose predicate schema **is** the taxonomy) inside a DSSE
  v1.0.2 envelope. SLSA precedent (open predicate, closed builder).
- The exact PAE pre-image rule is normative and byte-pinned across the Rust
  signer, the Python verifier, and the WASM surface
  ([ADR-0009](../redesign/decisions/0009-in-toto-dsse-envelope.md)).
- Vectors: `dsse-pae` golden (the single most error-prone byte-level rule).

---

## web-observation

### 1.0.0 — 2026-06-18 — demoted from "the spec" to one module

- `HESO-1.0.md` (plat / cassette / sealed-plat) kept **verbatim** but demoted
  from being the whole standard to one module of the suite. No behavior change;
  it remains canonical and vector-backed.
- Cleanup landing with the demotion: tidy the non-contiguous `§1.5`/`§1.6`
  section-numbering gaps; resolve the deferred receipt domain-separation TODO in
  the absorbed action-receipt module.
- Vectors unchanged: `plat_vectors`, `sealed_envelope_vector`, `signing_domain_hex`.
