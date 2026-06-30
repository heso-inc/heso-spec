# HESO/1 — The Open Standard

**An open standard for auditable, independently-verifiable records of what an automated agent did — verifiable offline, by anyone, with no engine, no network, no clock, and no trust in whoever produced it.**

This repository is the **sole home** of the HESO/1 specification. Implementations
(the Rust kernel, the SDKs, the cloud) vendor *from* here, pinned to a commit
SHA; nothing shadows or privately forks the normative artifacts.

HESO's business is in the rails + assurance, not in owning the spec — so the
thing that decides "what did this agent action *do*" is open, hashed, and
independently re-implementable from prose + TOML + vectors.

---

## What HESO/1 covers

HESO/1 is a **suite of independently-versioned, independently-conformance-claimable
modules** — not one omnibus document. You can conform to "action-receipt + chain +
transparency" without claiming time-anchor or quorum.

| Module | File | What it is |
|---|---|---|
| **taxonomy** | [`modules/taxonomy.md`](./modules/taxonomy.md) + [`taxonomy.toml`](./taxonomy.toml) + [`registry.toml`](./registry.toml) + [`taxonomy/extensions/`](./taxonomy/extensions/) | The crown jewel: the structural, classify-by-effect destructive-primitive taxonomy bundle (`move-value` / `destroy` / `change-authority` / `disclose` / `execute`), hashed and versioned. |
| **action-receipt** | [`modules/action-receipt.md`](./modules/action-receipt.md) (+ [`action-receipt-v1.md`](./modules/action-receipt-v1.md)) | The signed, canonicalized record of one classified agent action. v2 default; v1 frozen for byte-stable legacy receipts. |
| **chain** | [`modules/chain.md`](./modules/chain.md) | The BLAKE3 hash-linked per-session audit chain over receipts. |
| **transparency** | [`modules/transparency.md`](./modules/transparency.md) | RFC-6962 Merkle inclusion + consistency proofs over receipt commitments. |
| **time-anchor** | [`modules/time-anchor.md`](./modules/time-anchor.md) | RFC-3161 trusted-timestamp binding over a receipt/checkpoint. |
| **quorum** | [`modules/quorum.md`](./modules/quorum.md) | k-of-n approval re-derivation semantics. |
| **envelope** | [`modules/envelope.md`](./modules/envelope.md) | in-toto Statement + DSSE binding; a HESO/1 `predicateType` whose predicate schema *is* the taxonomy. |
| **web-observation** | [`HESO-1.0.md`](./HESO-1.0.md) / [`modules/web-observation.md`](./modules/web-observation.md) | The original plat / cassette / sealed-plat web-observation format. **Demoted** from "the spec" to one module of the suite. |
| **taxonomy-extension registry** | [`modules/taxonomy-extension-registry.md`](./modules/taxonomy-extension-registry.md) + [`registry.toml`](./registry.toml) | The open, machine-readable, namespaced registry for taxonomy extensions. |
| **auditor catalog** | [`catalog.toml`](./catalog.toml) | The open descriptive label layer riding on the taxonomy spine. |
| **conformance vectors + verifier** | [`vectors/`](./vectors/), [`verifier/`](./verifier/) | The byte-checkable golden corpus + the clean-room Python verifier (a second implementation, independent of the Rust kernel). |

**The standard deliberately does NOT cover** the plan-gated assurance product —
the compliance `controls.toml` + packs, the commitment store, and the
proof/exhibit builder. Those live in the closed cloud repo. The line is sharp on
purpose: **a third party can implement and verify everything in this repo without
paying HESO a cent.**

---

## What HESO/1 proves — and what it does not

HESO/1 gives you **consistency, tamper-evidence, and reproducibility**: a verifier
can confirm a signed record is byte-for-byte what was signed, that it chains to
its session, and that it sits in the transparency log. Change one byte and
verification fails.

It does **not** by itself prove the content reflects reality against an *untrusted
operator* — whoever ran the agent holds the signing key and can author a fresh,
valid record. Closing that gap requires a trust anchor outside the operator (a
notary, a TEE, a transparency witness) and is addressed by the transparency and
time-anchor modules and the trust grades. Be precise about that when you build on
it.

---

## Quickstart — verify a run three independent ways

A real signed record ships at [`examples/sample-sealed-plat.json`](./examples/sample-sealed-plat.json). Every verifier exits `0` for a valid record and non-zero when it rejects one.

### 1. Python clean-room verifier (no Rust)

```sh
cd verifier
pip install -r requirements.txt
python heso_verify.py ../examples/sample-sealed-plat.json
```
Tamper one byte and it refuses (`FAIL HashMismatch`, exit 2).

### 2. Standalone Rust verifier (reference impl)

From the kernel repo:
```sh
cargo run -p heso-verify -- /path/to/sample-sealed-plat.json
```
A tampered record prints `FAIL … HASH MISMATCH` and exits 2.

### 3. Conformance suite

```sh
cd verifier
python run_vectors.py
python conformance_check.py
```
The interop check is the load-bearing one: Python (`rfc8785`) and the Rust
reference (`serde_jcs`) produce **byte-identical** canonical JSON and each
verifies the other's signatures — that is what makes "anyone can verify" true
rather than asserted. Vectors are **generated from the reference, never hand-edited**.

---

## Governance

A real open standard needs the artifacts that let it be safely extended and
trusted. They live here:

| Doc | What |
|---|---|
| [`GOVERNANCE.md`](./GOVERNANCE.md) | Versioning + extension policy: how the suite versions, what a breaking change is, how `taxonomy_hash` gates compatibility, and the RFC → ADR spec-change process. |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | How to propose a normative change, and the **conformance-vector requirement** for any behavior-affecting change. |
| [`CHANGELOG.md`](./CHANGELOG.md) | Per-module change history. |
| [`SECURITY.md`](./SECURITY.md) | Private vulnerability-disclosure process. |
| [`registry.toml`](./registry.toml) | The machine-readable taxonomy-extension registry. |

---

## License

The license boundary is the **repo** boundary — everything here is the open
standard.

- **Specification text** — this README, [`HESO-1.0.md`](./HESO-1.0.md), everything
  under [`modules/`](./modules/), the governance docs, and the data files'
  normative prose — is **CC BY 4.0**. SPDX: `CC-BY-4.0`. See [`LICENSE`](./LICENSE).
- **Conformance vectors** ([`vectors/`](./vectors/)) are **CC0** (public domain),
  so anyone can run conformance with zero friction. SPDX: `CC0-1.0`.
- [`catalog.toml`](./catalog.toml) is open, but a deliberate descriptive layer —
  not the structural spine.

Anyone may build a conformant implementation and describe it as
"HESO/1-conformant". The **HESO** name itself is a reserved trademark — see
[`NOTICE`](./NOTICE).
