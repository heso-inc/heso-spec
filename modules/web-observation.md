# HESO/1 — Web-Observation Module (plat / cassette / sealed-plat)

**Status: Normative.**

> This module is the original HESO/1.0 web-observation artifact format —
> **plat**, **cassette**, and **sealed-plat** — which was once the whole of
> "the spec" and is now **one module** of the HESO/1 suite (see the legacy
> [`../HESO-1.0.md`](../HESO-1.0.md) entry page and the
> [spec map](../HESO-1.0.md#module-suite)). The substance below is carried
> **verbatim** from the former `HESO-1.0.md` §1–§4: it is canonical,
> vector-backed, and unchanged. Only the section numbering has been made
> contiguous (the reverse-extraction left §1.5/§1.6 gaps) and cross-links
> re-pointed at sibling modules.

This document specifies the wire formats and verification rules of the HESO/1
web-observation module. Any program that produces and verifies the artifacts
below according to these rules is conformant to this module — it need not share
code with the reference implementation. The module is reverse-extracted from the
reference implementation and pinned to the canonical test vectors in §1.8; those
vectors are the ground truth if prose and code ever disagree.

Key words MUST, MUST NOT, SHOULD, MAY are per RFC 2119. All hashes are
BLAKE3 unless stated. All canonicalization is RFC 8785 (JCS).

**Sibling modules:** the agent-action half of HESO/1 — the signed
[ActionReceipt](./action-receipt.md), the [session chain](./chain.md), the
[transparency log](./transparency.md), the [time anchor](./time-anchor.md), the
[quorum rule](./quorum.md), and the [in-toto/DSSE envelope](./envelope.md) — is
a SEPARATE artifact family. This module covers web observation only.

---

## §0 Overview

HESO web observation is a protocol for **auditable web observation and action by
automated agents**. A run produces three artifacts:

- a **plat** (§1) — a canonical JSON record of what the agent observed/did;
- a **cassette** (§2) — the ordered network trace that backs the plat and
  enables byte-identical replay;
- a **sealed envelope** (§3) — the plat bound to an Ed25519 signature (the
  "sealed plat").

### §0.1 What this module proves — and what it does not

This module provides **tamper-evidence and reproducibility**. A verifier holding
only the artifacts and a conformant implementation can confirm that the plat is
byte-for-byte what was signed and that it reproduces from the cassette. This
is **consistency**, not a proof that the observed content reflects reality.

> Proving content against an *untrusted operator* is impossible from the
> artifacts alone: the operator holds the signing key and the session keys, so
> a self-signed plat attests "this operator produced exactly these bytes," not
> "these bytes came from the real web." Closing that gap requires a trust
> anchor outside the operator and is **out of scope for this module** — it is
> the domain of the higher trust grades (§5) and of the agent-action modules
> (see [action-receipt.md](./action-receipt.md) and
> [transparency.md](./transparency.md)).

This boundary is the whole reason for the trust grades in §5. The artifacts
this module specifies are **Grade 0**.

---

## §1 Plat

### §1.1 Definition

A plat is a JSON object describing a single page observation, or a stepped run
over pages. Its field set is **open and extensible**. The normative rule is:
**every field present in the plat body is covered by the content hash (§1.7),
except the top-level `plat_hash` field itself.**

### §1.2 Common fields (informative)

The reference implementation commonly emits: `input_url` (verbatim user input),
`url` (parsed, post-redirect), `title`, `description`, `tree` (content surface),
`actions`, `forms`, `cookies`, `console`, `scripts`, `framework`,
`http_status`, `partial`, `partial_reason`, `plan`, `steps`, `linked_pages`,
`inline_data`, `data_attrs`, `text`. **None are required by §1.** Presence and
absence are themselves meaningful: a field set to `""`, set to `null`, or
absent all hash differently (§1.8 V6a/V6b/V6c).

### §1.3 Seed

- `seed` (integer, default 0): the RNG seed used for the run. Recorded so the
  plat is self-describingly reproducible; covered by `plat_hash`. A verifier
  replays with this seed.

### §1.4 Stepped runs

When a run executes a plan, the plat carries `plan` (the requested verbs) and
`steps`. Each step object has the shape:

```json
{ "index", "verb", "action", "url_before", "url_after",
  "status", "observed", "started_at", "finished_at" }
```

#### §1.4.1 Step timestamps

`started_at`/`finished_at` are LOGICAL, not wall-clock. For 0-based step index
i:

```
started_at  = RFC3339(i*2   ms since 1970-01-01T00:00:00Z)
finished_at = RFC3339(i*2+1 ms since 1970-01-01T00:00:00Z)
```

A conformant stamper MUST use this; a verifier MUST accept it. Wall-clock is
excluded to preserve §4 determinism.

### §1.5 Canonicalization

Canonical bytes are the RFC 8785 (JCS) serialization of the value: object keys
sorted, ECMA-262 number serialization, JCS string escapes. **Unicode is NOT
normalized** — NFC and NFD are different inputs and MUST hash distinctly.
Implementations MUST use a conformant JCS encoder (the reference uses
`serde_jcs`).

All object field NAMES in plat and receipt artifacts MUST be ASCII
(U+0020–U+007E). RFC 8785 sorts object keys by UTF-16 code units; some JCS
libraries sort by UTF-8 bytes, diverging only for non-ASCII (specifically
supplementary-plane) keys. Restricting field names to ASCII eliminates this
ambiguity and guarantees cross-implementation byte-identical canonicalization.
User-supplied data appears only in VALUES, which are unaffected.

### §1.6 Content hash (`plat_hash`)

`plat_hash` is the lowercase-hex BLAKE3 (64 chars, 256 bits) of the canonical
bytes of the plat body **with the top-level `plat_hash` field removed before
canonicalization**.

- Only the **top level** `plat_hash` is excluded — a hash field cannot contain
  its own digest. **Nested** `plat_hash` values (e.g. inside `linked_pages[*]`)
  are ordinary content and ARE hashed: a parent plat thereby commits,
  Merkle-style, to its children's hashes.
- To verify: recompute and compare against the embedded `plat_hash`. Equal =
  intact; unequal = tampered. A missing or non-string `plat_hash` is a distinct
  error class, not a tamper signal.

### §1.7 Canonical test vectors (conformance)

A conformant implementation MUST reproduce these `body → plat_hash` pairs.

**V1 — minimal plat**
```json
{"input_url":"https://example.com/","url":"https://example.com/","title":"Example","description":"","tree":[],"actions":[]}
```
→ `bc272895d75d0d780e6304e2cbd15a7a67819a3909c1aa5c51f7b5bbb28abccf`

**V2 — Merkle parent over two child plat_hashes** (proves nested `plat_hash` is hashed)
```json
{"input_url":"https://example.com/","url":"https://example.com/","title":"Parent","description":"","tree":[],"actions":[],"linked_pages":[{"url":"https://example.com/a","plat_hash":"aaaa"},{"url":"https://example.com/b","plat_hash":"bbbb"}]}
```
→ `f098b1ac08693b85c05fc9465a9f7763d22fb8563e292b025f7dbab9cc67ac62`

**V6 — empty vs null vs absent `title` MUST differ** (same body otherwise: `input_url`/`url`=`https://example.com/`, `description:""`, `tree:[]`, `actions:[]`)
- V6a `"title":""`    → `121f46f2d02fafadb811cd0ff2a1b7e5d6f64a381af29b36295384ba96f91c4b`
- V6b `"title":null`  → `801a174528591c1ef1cd3e3d249f76f277be8e84675b4758791b1e1355d2aa41`
- V6c `title` absent  → `e53bdc36b6aa0dbc27679d4c1a0dae825e9f500c48915357f9e34dfd49cb8c45`

The hashes above are the **bare** bodies (no `seed` field). They are pinned by
the `heso_1_0_section_1_9_spec_vectors_bare` test and can be dumped with:
```
cargo test -p heso-engine-fetch plat::tests::heso_1_0_section_1_9_spec_vectors_bare -- --nocapture
```
Real plats also carry the `seed` field (§1.3); the seeded V1–V8 bodies plus the
full machine-checkable suite (with `canonical_bytes_hex`) live in
`vectors/heso-1.0-vectors.json`, regenerated by the `heso_1_0_section_1_9_vectors`
test.

---

## §2 Cassette

### §2.1 Definition

A cassette is an ordered log of the HTTP exchanges observed during a run,
enabling deterministic replay. Wire shape:

```json
{ "records": [
  { "method": "GET",
    "url": "https://example.com/",
    "final_url": "https://example.com/",
    "request_body_b64": "",
    "status": 200,
    "response_headers": [["content-type","text/html"]],
    "response_body_b64": "PCFET0NUWVBF…",
    "response_body_blake3": "ab12…" }
] }
```

### §2.2 Records

- `method` — uppercase canonical HTTP method.
- `url` — the requested URL (the lookup key); pre-redirect; byte-exact.
- `final_url` — the post-redirect URL the response came from; equals `url`
  when no redirect was followed.
- `request_body_b64`, `response_body_b64` — standard base64 (RFC 4648) of the
  raw bytes. An empty body is the empty string `""`, never `null`.
- `status` — HTTP status code.
- `response_headers` — ordered `[name, value]` pairs. Names lowercased, values
  raw. Repeats preserved (e.g. multiple `set-cookie`); server ordering
  preserved so replay reproduces byte-identical header lists.

### §2.3 Response body digest

`response_body_blake3` — lowercase hex (64 chars) BLAKE3 of the raw response
body bytes (the same bytes `response_body_b64` encodes).

### §2.4 Content-addressing invariant (normative)

At decode time a verifier MUST check

```
response_body_blake3 == lowercase_hex(BLAKE3(base64_decode(response_body_b64)))
```

and MUST treat any mismatch — or a syntactically malformed digest — as a
malformed-cassette error (the record cannot be trusted to address its content).
Legacy cassettes predating §2.3 carry an empty digest; the check is skipped
**only** for the empty case so older recordings still load.

### §2.5 Replay & lookup

Replay resolves each request by exact match on `(method, url, request_body)` —
method case-insensitive on the query side; `url` and body byte-exact —
returning the first matching record in insertion order. A request with no
matching record MUST surface a **cassette miss** error. An implementation MUST
NOT silently fall back to a live fetch; doing so would break determinism and
hide page drift from the caller.

### §2.6 Binding to the plat

A cassette MAY ride inside the plat body, in which case it is covered by
`plat_hash` (§1.6) like any other field. The determinism contract (§4) is:
**the same cassette MUST reproduce the same `plat_hash`.**

---

## §3 Sealed envelope (sealed plat)

### §3.0 Artifact taxonomy

There are two independently-signed artifact types. A **SealedPlat** (§3.1–§3.4)
binds a plat body to an Ed25519 signature with domain prefix `heso-plat/v1\0`. A
**Receipt** (detected by a `trace_hash` field) is a SEPARATE type with its own
signing convention (§3.5). They are not interchangeable. The full agent-action
Receipt format is specified in the sibling
[action-receipt.md](./action-receipt.md) module; this module specifies only the
web-observation SealedPlat and the legacy receipt-signing rule §3.5 retains for
back-compat.

### §3.1 Shape

```json
{
  "alg": "heso-plat/v1+ed25519",
  "content": { "…the plat body…": "…", "plat_hash": "<blake3-hex>" },
  "signature": { "algorithm": "Ed25519", "public_key": "<base64>", "signature": "<base64>" }
}
```

The envelope is the unit of trust: holding a sealed envelope and a conformant
verifier is sufficient to decide whether `content` was produced by the holder
of `signature.public_key` and is byte-for-byte what they signed — no key
distribution, no network, no clock.

### §3.2 Signing

The signed message is `SIGNING_DOMAIN ++ canonical_bytes(content)`, where

```
SIGNING_DOMAIN = "heso-plat/v1\0"
```

`SIGNING_DOMAIN` is the 12 ASCII bytes of `heso-plat/v1` followed by one NUL
byte (0x00) — exactly 13 bytes. The final byte is 0x00 (NUL), NOT 0x0A
(newline). NUL is chosen because RFC 8785 JSON never emits a raw NUL, so domain
and payload occupy disjoint byte ranges without a length prefix.

Domain separation MUST be applied. A bare Ed25519 signature over the canonical
bytes *without* the domain prefix MUST be rejected (this prevents transplanting
a signature minted for another payload shape — receipts, fingerprints, etc.).

### §3.3 Algorithm tag

`alg` MUST equal `heso-plat/v1+ed25519` for v1. A verifier encountering any
other tag MUST refuse the envelope rather than silently assume Ed25519. Future
algorithms (e.g. post-quantum hybrids) are introduced under new tags.

### §3.4 Verification order (normative)

A verifier MUST perform, in order:

1. `alg` == `heso-plat/v1+ed25519`, else **WrongAlgorithm**.
2. `content.plat_hash` == recomputed BLAKE3 of `content` (§1.6), else
   **HashMismatch** (the content was mutated; the signature is not checked —
   `HashMismatch` is the clearer diagnostic).
3. Ed25519 `verify_strict` of `signature` over
   `SIGNING_DOMAIN ++ canonical_bytes(content)`, else **InvalidSignature**.

All three passing = **Valid**.

#### §3.4.1 Ed25519 strictness

Implementations MUST verify the signature scalar `s` is canonically reduced
mod ℓ (RFC 8032 §5.1.7); reject `s ≥ ℓ` as **InvalidSignature**.
Implementations SHOULD additionally reject small-order / torsion public keys.

> Correct description: ed25519-dalek `verify_strict` performs COFACTORLESS
> verification, `S·B = R + k·A`, AND rejects non-canonical or small-order R/A —
> this is strict mode. The cofactorED equation `[8]S·B = [8]R + [8]k·A` is the
> LOOSER check that permits malleability and is NOT what "strict" means.

The torsion rejection is SHOULD at Grade 0 because the signer presents their own
key — a torsion-key attack needs an attacker-CHOSEN public key, outside the
Grade 0 threat model — and becomes MUST at Grade 1+ where keys come from third
parties. Reference verifiers MUST document which level they implement.

### §3.5 Receipt signing (legacy compatibility)

A Receipt is signed over its canonical JSON with `signature` (and, in
pre-anchor scope, `tsa_anchor`) set to null before canonicalization; in
post-anchor scope only `signature` is nulled and `tsa_anchor` is covered. No
domain-separation prefix is currently prepended (see §3.5.1). Canonicalization
uses the same RFC 8785 rules as plats. Algorithm: Ed25519, same scalar-range
requirement as §3.4.1.

> The canonical, normative home of the agent-action Receipt format is the
> sibling [action-receipt.md](./action-receipt.md) module, which is also the
> authoritative source for the ActionReceipt signing domains. This sub-section
> is retained here only to specify the web-observation runtime's interaction
> with a co-signed receipt. The web-observation Receipt prefix
> (`heso-receipt/v1\0`, §3.5.1) is a distinct, still-deferred forward-compat
> concern and is *not* resolved by [action-receipt.md](./action-receipt.md).

#### §3.5.1 Receipt domain separation (forward-compat)

Web-observation Receipt signing currently relies on schema divergence (distinct
`trace_hash`/`seed`/`cost` fields) rather than a domain prefix to prevent
cross-type signature transplant — assessed LOW risk at Grade 0. A future
revision SHOULD add prefix `heso-receipt/v1\0` signalled via a versioned `alg`
field, backward-compatibly. This prefix is not yet implemented by the kernel and
is not required for Grade 0 conformance; it remains a genuine forward-compat
deferral. (This is a separate concern from the ActionReceipt signing domains,
which *are* resolved normatively in [action-receipt.md](./action-receipt.md).)

---

## §4 Determinism contract

Given the same cassette, a conformant implementation MUST produce the same plat
and therefore the same `plat_hash`. Sources of nondeterminism (wall-clock time,
RNG, network) MUST be seeded or recorded so replay is byte-identical. Replays
consult only the cassette; a cassette miss (§2.5) is an error, never a live
fetch.

---

## §5 Trust grades (informative)

This module as specified yields a **Grade 0** artifact: self-signed,
tamper-evident, replayable. The signing key is the operator's, so the signature
attests "this operator produced and signed exactly these bytes," not that the
content reflects reality (§0.1).

Higher grades layer **above** the §3 envelope — via additional signatures or
new `alg` tags — and are specified by the agent-action modules and HESO
Enterprise, not this module:

- **Grade 1** — independent notary co-signs (witness the operator can't forge).
- **Grade 2** — customer / independent co-signer.
- **Grade 3** — threshold notary mesh + transparency-log anchoring.
- **Grade 4** — origin-signed content (the source vouches for itself).

The §0.1 consistency-vs-truth boundary is the reason grades exist: each grade
adds a trust anchor outside the operator. This module deliberately stops at the
boundary so the open web-observation format leaks no part of the assurance
trust layer.

The agent-action half of HESO/1 restates these grades as trust *levels* (L0–L3)
for an **agent-compliance** layer over agent *actions* (not web observations):
L0 is the operator-signed action, L1 adds an authorized human approver's
co-signature, and L2/L3 mirror the threshold / external-co-sign grades above —
see [action-receipt.md](./action-receipt.md), [quorum.md](./quorum.md), and
[transparency.md](./transparency.md). This is an informative pointer only; it
changes no normative rule or §1.7 vector in this module.

---

## §6 Conformance

An implementation conforms to the HESO/1 web-observation module iff it:

1. canonicalizes per §1.5 (RFC 8785, no Unicode normalization);
2. computes `plat_hash` per §1.6 and reproduces the §1.7 vectors;
3. encodes/decodes cassettes per §2 and enforces the §2.4 content-addressing
   invariant and §2.5 cassette-miss semantics;
4. produces and verifies sealed envelopes per §3, with the §3.4 verification
   order and §3.2 domain separation.

The §1.7 vectors are the minimum conformance suite. Per-module conformance is
the HESO/1 norm: an implementation MAY claim the web-observation module without
claiming any sibling module (action-receipt, chain, transparency, time-anchor,
quorum, envelope), and vice versa.
