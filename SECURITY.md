# Security Policy — HESO/1

**Status: Normative (process)**

HESO/1 is a **trust standard**: its entire value is that an Action Receipt can be
verified offline, by anyone, without trusting whoever produced it. A flaw in the
specification or in the reference verifiers is therefore a flaw in the trust
itself. We treat security reports accordingly.

This policy covers the **specification text**, the **conformance vectors**, and
the **reference verifiers in this repo** (`verifier/`). The Rust reference runtime
and the cloud services have their own policies in their own repos.

---

## 1. What to report

Report anything that could let a party **forge, alter, or mis-verify** a record,
or that makes a conformant verifier reach the wrong verdict. Examples:

- A canonicalization, BLAKE3 domain-separation, chain-link, or **PAE** ambiguity
  that lets two implementations disagree on the bytes a signature covers — i.e. a
  receipt that verifies in one conformant implementation but not another, or a
  signature that can be made to cover different content.
- A taxonomy `classify()` ambiguity that lets an action be **mis-classified** —
  especially anything that lets a destructive action (`move-value`, `destroy`,
  `change-authority`, `disclose`) be classified as benign, or that defeats the
  **deny-unknown / residual** floor.
- A `taxonomy_hash` or version-pinning weakness that lets the **pinned**
  classifier be spoofed, downgraded, or detached from the receipt (see
  [ADR-0012](../redesign/decisions/0012-taxonomy-versioning-pin-at-signing.md)).
- A flaw in the in-toto/DSSE envelope binding — a signature-stripping,
  payload-substitution, downgrade, or replay path
  ([ADR-0009](../redesign/decisions/0009-in-toto-dsse-envelope.md)).
- A transparency-proof flaw (an inclusion/consistency proof that can be forged or
  that admits a split view).
- A bug in a **reference verifier** in this repo that accepts a tampered record or
  rejects a valid one.
- A redaction / commit-and-reveal flaw that leaks redacted data or lets a reveal
  be substituted.

If you are unsure whether something is a security issue or just a spec bug,
**report it privately first**. We would rather triage a non-issue than have a real
one filed as a public bug.

---

## 2. How to report — please disclose privately

**Do not open a public issue or PR for a security vulnerability.** A public report
on a verification flaw is itself a window of exposure for everyone relying on the
standard.

Preferred channels:

1. **GitHub private vulnerability reporting** — use the repository's *Security →
   Report a vulnerability* (GitHub Security Advisories). This is the preferred path.
2. **Email** — `security@heso.ca`. Encrypt if you can; ask for a key if you need
   one. Use a subject prefixed `[HESO/1 SECURITY]`.

Please include: the affected artifact (spec section / module / vector / verifier
file), a description of the flaw, a **minimal reproduction** (a sample record,
vector, or PAE pre-image that demonstrates the disagreement is ideal), and the
impact you believe it has.

---

## 3. What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | within **3 business days** |
| Initial assessment (severity + whether we accept it) | within **10 business days** |
| Fix / mitigation plan shared with you | as soon as it is scoped |

We practice **coordinated disclosure**. We will agree an embargo window with you,
fix it (a fix is always a **new forward version** — published versions are never
mutated in place, per [GOVERNANCE §3](./GOVERNANCE.md)), publish the corrected
spec/vectors, and then disclose. We will credit you in the advisory and the
[`CHANGELOG.md`](./CHANGELOG.md) unless you prefer to remain anonymous.

A fix that changes verification behavior follows the normal process: a new
immutable module version + regenerated conformance vectors + a `CHANGELOG.md`
entry. A misclassification fix produces a **new published taxonomy version**; per
ADR-0012 it does **not** orphan or retroactively invalidate receipts signed under
the old version (they verify under their own era's rules) — but it is flagged for
analysis.

---

## 4. Scope

**In scope:** the spec text (`HESO-1.0.md`, `modules/`), `taxonomy.toml`,
`catalog.toml`, `registry.toml`, the conformance vectors, and the reference
verifiers under `verifier/`.

**Out of scope (report elsewhere):** the closed cloud services, the proof/exhibit
builder, the commitment store, and the Rust reference runtime — each has its own
security policy in its own repository. General spec clarifications and editorial
fixes are not security issues — open a normal PR per [`CONTRIBUTING.md`](./CONTRIBUTING.md).

---

## 5. Safe harbor

We will not pursue or support legal action against good-faith security research
that follows this policy: research conducted without privacy violations, without
data destruction, and without degradation of services, and that gives us a
reasonable time to respond before any public disclosure. If in doubt about
whether your testing is in good faith, ask us first.

---

## 6. See also

- [`GOVERNANCE.md`](./GOVERNANCE.md) — versioning; how a fix is published.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — the normal (non-security) change process.
- [`CHANGELOG.md`](./CHANGELOG.md) — where fixes and credits are recorded.
