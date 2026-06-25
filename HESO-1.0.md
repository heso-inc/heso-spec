# HESO/1 — Specification Entry / Index

**Status:** Entry page (non-normative). **Reference implementation:** the
HESO kernel. **Normative content:** lives in [`modules/`](./modules/).

> **What changed.** HESO/1 used to be a single document — *this file* — that
> specified only the web-observation layer (plat / cassette / sealed-plat).
> HESO/1 is now a **module suite**: a set of focused, independently
> conformance-claimable normative specs under [`modules/`](./modules/). The
> web-observation format that used to live here **verbatim** is now one module,
> [`modules/web-observation.md`](./modules/web-observation.md) — substance
> unchanged, only re-homed and re-numbered contiguously. No normative content
> was lost; it moved.

This page is the stable index into the standard. It is **not** normative — the
modules are. If prose here and a module ever disagree, the module wins.

---

## Module suite

HESO/1 is a versioned suite. Each module is self-contained, uses RFC-2119
language, and is conformance-claimable on its own — an implementation may
conform to a subset (e.g. "web-observation + action-receipt + chain") without
claiming the rest.

| Module | File | What it is |
|---|---|---|
| **web-observation** | [`modules/web-observation.md`](./modules/web-observation.md) | plat / cassette / sealed-plat — the original Grade-0 web-observation artifact format. **This is the former §1–§4 of this document.** |
| **action-receipt** | [`modules/action-receipt.md`](./modules/action-receipt.md) (+ `action-receipt-v1.md`) | The signed agent-action receipt: canonicalization, BLAKE3 content hash, Ed25519 signature, verify order, redaction reveal. |
| **chain** | [`modules/chain.md`](./modules/chain.md) | The BLAKE3 hash-linked per-session audit chain over receipts. |
| **taxonomy** | [`modules/taxonomy.md`](./modules/taxonomy.md) (+ `taxonomy.toml` gold-master) | The destructive-primitive taxonomy — the classify-by-effect spine (move-value / destroy / change-authority / disclose / execute). |
| **transparency** | [`modules/transparency.md`](./modules/transparency.md) | RFC-6962 Merkle inclusion + consistency proofs over receipt commitments. |
| **time-anchor** | [`modules/time-anchor.md`](./modules/time-anchor.md) | RFC-3161 TSA token binding over a receipt/checkpoint. |
| **quorum** | [`modules/quorum.md`](./modules/quorum.md) | k-of-n approval re-derivation semantics. |
| **envelope** | [`modules/envelope.md`](./modules/envelope.md) | in-toto Statement + DSSE binding; the HESO/1 `predicateType` whose schema *is* the taxonomy. |

The gold-master data backing the modules — [`taxonomy.toml`](./taxonomy.toml)
(the taxonomy spine) and [`catalog.toml`](./catalog.toml) (the open auditor
label layer) — lives at the repo root and is vendored by implementations via
pinned-sha.

---

## Where the old sections went

`HESO-1.0.md` §0–§6 (overview, plat, cassette, sealed envelope, determinism,
trust grades, conformance) were the web-observation spec. They moved
**verbatim in substance** into
[`modules/web-observation.md`](./modules/web-observation.md). The only edits
were mechanical: the non-contiguous §1.5/§1.6 numbering gaps (an artifact of
reverse-extraction) were closed, and cross-links now point at sibling modules.

| Old section (this file) | Now lives in `modules/web-observation.md` |
|---|---|
| §0 Overview / §0.1 consistency-vs-truth | §0 / §0.1 |
| §1 Plat (§1.1–§1.4.2, §1.7–§1.9) | §1 Plat (§1.1–§1.4.1, §1.5–§1.7) — renumbered contiguous |
| §2 Cassette | §2 Cassette |
| §3 Sealed envelope (receipt) | §3 Sealed envelope (sealed plat) |
| §4 Determinism contract | §4 Determinism contract |
| §5 Trust grades | §5 Trust grades |
| §6 Conformance | §6 Conformance |

> **Renumbering note.** Old plat sub-sections §1.7 (canonicalization), §1.8
> (content hash), and §1.9 (vectors) are now §1.5, §1.6, and §1.7 respectively
> in the module. Old step-timestamp §1.4.2 is now §1.4.1.

<!--
  ANCHOR PRESERVATION — old deep links into this document.
  HESO/1.0 §1–§4 was once specified inline here under these heading anchors:
    #0-overview  #01-what-heso-proves--and-what-it-does-not
    #1-plat  #11-definition  #12-common-fields-informative  #13-seed
    #14-stepped-runs  #142-step-timestamps  #17-canonicalization
    #18-content-hash-plat_hash  #19-canonical-test-vectors-conformance
    #2-cassette  #21-definition  #22-records  #23-response-body-digest
    #24-content-addressing-invariant-normative  #25-replay--lookup
    #26-binding-to-the-plat
    #3-sealed-envelope-receipt  #30-artifact-taxonomy  #31-shape  #32-signing
    #33-algorithm-tag  #34-verification-order-normative  #341-ed25519-strictness
    #35-receipt-signing  #351-receipt-domain-separation-forward-compat
    #4-determinism-contract  #5-trust-grades-informative  #6-conformance
  These now resolve in modules/web-observation.md (numbering made contiguous:
  former §1.7/§1.8/§1.9 → §1.5/§1.6/§1.7; former §1.4.2 → §1.4.1).
  A bare link to this file (no fragment, or an unknown fragment) lands on this
  index, which routes here from the table above.
-->

---

## Conventions (apply across all modules)

Key words MUST, MUST NOT, SHOULD, MAY are per RFC 2119. All hashes are BLAKE3
unless a module states otherwise. All canonicalization is RFC 8785 (JCS), with
object field names restricted to ASCII (see
[`modules/web-observation.md`](./modules/web-observation.md) §1.5). Each module
pins its own canonical test vectors as the ground truth if prose and code
disagree.

---

## See also

- [`modules/`](./modules/) — the normative module specs.
- [`taxonomy.toml`](./taxonomy.toml) · [`catalog.toml`](./catalog.toml) — the
  gold-master data.
- [`vectors/`](./vectors/) — the cross-language conformance corpus.
- [`verifier/`](./verifier/) — the clean-room reference verifier.
