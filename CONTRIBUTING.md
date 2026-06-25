# Contributing to HESO/1

**Status: Normative (process)**

This is the open HESO/1 specification. Contributions are welcome — and because a
trust standard is only as good as its discipline, the bar for **normative**
changes is deliberately high. This document explains how to propose a change,
when an RFC is required, and the **hard conformance-vector requirement** that
gates every behavior-affecting change.

Keywords MUST / SHOULD / MAY are RFC-2119.

---

## 1. Two kinds of contribution

| Kind | Examples | Process |
|---|---|---|
| **Editorial** | typo, clarified prose, a new example, a broken link | PR only. PATCH bump on the affected module. No vectors needed. |
| **Normative** | new field, new module, taxonomy change, canonicalization/PAE/chain change, new registered extension | RFC → review → ADR → PR **with vectors**. See §3–§5. |

If you are unsure which one you have: if it could change what any conformant
implementation *accepts or rejects*, or change any byte a signer signs or a
verifier checks, it is **normative**.

---

## 2. Before you start

1. **Read the governing docs.** [`GOVERNANCE.md`](./GOVERNANCE.md) (versioning &
   extension policy), the module spec you are touching under
   [`modules/`](./modules/), and the relevant locked decision records (the ADRs).
2. **One canonical home per fact.** Do not restate the taxonomy, the envelope, or
   any module's rules in a second place — cross-link the canonical home instead.
   A PR that duplicates a normative fact will be asked to delete the copy.
3. **Never hand-edit a vector.** Vectors in [`vectors/`](./vectors/) are
   generated from the reference implementation and CC0. Hand-editing one defeats
   the entire conformance guarantee. See §4.
4. **Never mutate a published version in place.** Fixes are forward-only new
   versions (GOVERNANCE §3). This is the same immutability discipline as an
   applied database migration or an accepted ADR.

---

## 3. The RFC process for normative changes

Normative changes go through **RFC → review → ADR**, mirroring the project's RFC
discipline:

1. **Frame the problem.** State what is unsettled and why now.
2. **Write the RFC** with this section spine (every RFC follows it so reviews are
   comparable):
   - **Problem** — what is unsettled, and why now.
   - **Solution** — concrete enough to build from.
   - **Alternatives** — what else was considered and why it loses. *(An RFC with
     no rejected alternatives is an ADR wearing a costume.)*
   - **Consequences** — what this commits the standard to; what it makes hard
     later; new open questions.
   - **Conformance impact** — **mandatory.** Does it change the wire contract or
     vectors? (canonical bytes, BLAKE3 domain tags, `taxonomy_hash`, the DSSE/PAE
     pre-image, chain links, the `predicateType` schema — anything cross-language.)
3. **Review.** `Draft` → `Reviewed`: open threads resolved or explicitly deferred.
4. **Accept → ADR.** On acceptance write a short, immutable, NNNN-numbered ADR
   recording the decision and linking back to the RFC. The RFC flips to
   `Accepted` and freezes. Reverse a decision only via a higher-numbered
   superseding ADR; never edit an accepted one.

Skip the RFC only for editorial work. Net-new modules, taxonomy-spine changes,
and any wire-contract / trust-model change always need one.

---

## 4. The conformance-vector requirement (the hard rule)

**Any change that affects behavior MUST ship conformance vectors that cover it,
and those vectors MUST be generated — never hand-written.** This is the single
non-negotiable rule of this repo. A normative change without vectors will not be
merged.

Concretely, your PR MUST:

1. **Add or update golden vectors** in [`vectors/`](./vectors/) covering the new
   or changed behavior (e.g. `action-receipt-v2`, `chain`, `taxonomy-classify`,
   `rfc6962-roots`, `dsse-pae`). Vectors are input + expected output as data
   (`canonical_bytes_hex`, the BLAKE3 fingerprint, the Ed25519 signature, the
   expected verdict, the expected `taxonomy_hash`).
2. **Generate them from the reference implementation**, not by hand. The CI
   conformance gate regenerates vectors from the reference and **fails the build
   on any drift** — so a hand-edited or placeholder value cannot ship.
3. **Prove the second implementation agrees.** A module is conformant only when an
   implementation independent of the Rust reference (the clean-room Python
   verifier in [`verifier/`](./verifier/), and where applicable the WASM verify
   surface) passes the same vectors. Two unrelated code paths agreeing on the
   published bytes is what turns "we pass our own tests" into a real guarantee.
   If your change adds a behavior the clean-room verifier does not yet cover,
   extend the verifier in the same PR.
4. **For a taxonomy change**, publish the new `taxonomy_hash` and a
   `taxonomy-classify` golden set for the new immutable version (the old version
   stays published — GOVERNANCE §4).
5. **For an extension**, register it in [`registry.toml`](./registry.toml) and add
   the classify vectors — see
   [`modules/taxonomy-extension-registry.md`](./modules/taxonomy-extension-registry.md).

> **Why so strict:** the whole open-standard claim is "anyone can verify a HESO
> implementation is correct *without trusting us*." That is only credible if every
> normative statement has a published, runnable, machine-checkable vector and at
> least two implementations that agree on it.

---

## 5. Versioning your change

Bump the affected module's version per [`GOVERNANCE.md` §2–§3](./GOVERNANCE.md)
**in the same PR**:

- **PATCH** — editorial, no behavior/byte/vector change.
- **MINOR** — additive, backward-compatible (every previously-valid artifact stays
  valid).
- **MAJOR** — breaking (a verdict flip, a byte change, a removed guarantee).
  Requires a superseding ADR and a new coexisting version; the old one stays
  published.

Then add a [`CHANGELOG.md`](./CHANGELOG.md) entry under the affected module with
the version, the date, a one-line summary, and links to the RFC/ADR.

---

## 6. PR checklist

Before opening a PR for a normative change, confirm:

- [ ] An accepted RFC + linked ADR exist (for wire/trust/taxonomy/new-module changes).
- [ ] The affected module spec(s) updated; version bumped per §5.
- [ ] Conformance vectors added/updated and **generated from the reference** (§4).
- [ ] The clean-room verifier passes the new vectors (extended if needed).
- [ ] For taxonomy changes: new immutable `taxonomy_hash` published; old version retained.
- [ ] For extensions: registered in `registry.toml` with vectors.
- [ ] `CHANGELOG.md` entry added.
- [ ] No normative fact duplicated; cross-links point to the one canonical home.
- [ ] No published version mutated in place.

---

## 7. License of contributions

By contributing you agree your contribution is licensed under the repo's posture:
**spec text under CC BY 4.0**, **conformance vectors under CC0**. See
[`LICENSE`](./LICENSE), [`NOTICE`](./NOTICE), and [`GOVERNANCE.md` §7](./GOVERNANCE.md).

---

## 8. See also

- [`GOVERNANCE.md`](./GOVERNANCE.md) — versioning & extension policy.
- [`SECURITY.md`](./SECURITY.md) — report a vulnerability, don't open a public PR.
- [`CHANGELOG.md`](./CHANGELOG.md) — per-module history.
- [`modules/taxonomy.md`](./modules/taxonomy.md) — the taxonomy module (the crown jewel).
- [`modules/taxonomy-extension-registry.md`](./modules/taxonomy-extension-registry.md) — registering an extension.
