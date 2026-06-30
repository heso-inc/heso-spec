# HESO/1 — Observed Facts Module

**Status: Normative.** Module: `observed-facts` · HESO/1

Observed facts are the normalized, signed evidence fields that describe what an
agent action touched. They are the input to [`taxonomy.md`](./taxonomy.md). The
taxonomy decides risk from these facts; it does not parse every provider API
itself.

This separation is load-bearing:

- Provider adapters MAY know that `api.stripe.com` is a payment rail or that an
  AWS Secrets Manager host is a secret store.
- The taxonomy only sees structural facts such as `host`, `path`, `method`,
  `is_payment`, `is_secret`, `row_count_estimate`, or `row_count_unknown`.
- Verifiers replay the same facts against the pinned taxonomy bundle hash. They
  do not fetch provider knowledge from the network during verification.

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY are to be
interpreted as in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

---

## 1. Fact Contract

An observed-facts object is a JSON object. Field names are lower snake case.
Unknown fields MAY be preserved for audit, but a taxonomy predicate MUST ignore
unknown fields unless the predicate vocabulary explicitly names them.

Core facts used by HESO/1:

| Fact | Type | Meaning |
|---|---:|---|
| `host` | string | Resolved destination host, lower-cased by the producer. |
| `path` | string | Request path, filesystem path, object key, or equivalent target path. |
| `method` | string | HTTP method or equivalent request method. |
| `argv_tokens` | array[string] | Whole command / SQL / shell tokens, already tokenized. |
| `row_count_estimate` | integer | Observed row or record count when known. |
| `row_count_unknown` | boolean | A row-count-bearing operation was observed, but the count could not be determined. |
| `is_payment` | boolean | The body or operation shape indicates value movement. |
| `is_identity_change` | boolean | The operation changes identity, access, credentials, or authority. |
| `is_secret` | boolean | The operation reads or exports secret material. |
| `is_model_call` | boolean | The operation is an inference/model-provider call. |
| `effect_destructive` | boolean | The parsed operation irreversibly removes or mutates state. |
| `is_local_compute` | boolean | The operation is local compute/filesystem work with no network reach. |

Facts MUST be captured before classification and signed inside the receipt when
the receipt carries an ERT. A verifier that re-derives classification MUST use the
facts in the receipt, not ambient network lookups.

---

## 2. Absent vs Unknown

Absent and unknown are different:

- An absent fact means "not observed or not applicable." For example, no
  `row_count_estimate` means the `row_threshold` predicate does not match.
- An unknown-but-relevant fact MUST be represented explicitly. For row counts,
  producers set `row_count_unknown = true`; the taxonomy then fails safe into the
  disclosure lane.

This rule prevents every event without a count from becoming `bulk_data`, while
still requiring a data operation with indeterminate size to classify strictly.

---

## 3. Provider Manifests

Provider knowledge belongs in registry-governed manifests, not the taxonomy
spine. A manifest can say "these hosts are payment providers" or "these hosts are
secret stores" by adding predicate rows to a core class. It MUST NOT invent new
primitives or weaken a core class.

The default first-party manifests live under
[`../taxonomy/extensions/heso/`](../taxonomy/extensions/heso/) and are discovered
through [`../registry.toml`](../registry.toml). Third-party manifests use the
same registry path and conformance-vector rules.

---

## 4. Offline Verification

Receipts pin the taxonomy bundle hash. A verifier can accept a classification
only when it has the exact core taxonomy and extension manifests that produced
that hash. If the bundle is unavailable, the verifier MUST fail closed with
taxonomy-unavailable semantics; it MUST NOT verify against "latest."
