# Changelog

All notable changes to the Royalty Flow Interface Protocol are documented in this file.

---

## [0.5.0] - 2026-08-10

### Status

**Core Draft Complete**

v0.5 marks the planned completion boundary of the current RFIP Core Draft series.

Future advanced trust mechanisms should normally be implemented as optional profiles or companion protocols rather than automatically extending the RFIP base.

### Added

* `ObservationReceipt`
* Temporal Evidence Profile
* complete signed-record digest binding
* SHA-256 target digest
* RFC 8785 canonical target representation
* independent Observer semantics
* Observer identity binding
* Observer signature verification
* observation chronology checks
* pre-expiration observation checks
* pre-revocation observation checks
* external temporal-evidence validation

### Added invariants

* `FI-020` — Temporal Evidence requires a valid ObservationReceipt.
* `FI-021` — Observation digest MUST match the complete signed target record.
* `FI-022` — Observation time MUST NOT precede target signature time.
* `FI-023` — Observer MUST be independent from the target signer.
* `FI-024` — Pre-cutoff existence requires observation before expiration or revocation.
* `FI-025` — ObservationReceipt signature MUST itself be valid and temporally eligible.

### Changed

* Core schema version advanced to `0.5.0`.
* Observation digest intentionally includes the target record's `signature.value`.
* Temporal evidence is separated from signer-declared `signed_at`.
* Conformance is explicitly divided into:

  * RFIP Core
  * RFIP Temporal Evidence

### Security improvement

v0.4 could establish that a signature's declared `signed_at` was compatible with a key's lifecycle.

However, `signed_at` remained a timestamp asserted by the signer.

v0.5 adds an independent ObservationReceipt so a verifier can distinguish:

```text
"the signer claims this existed before revocation"
```

from:

```text
"an independent observer possessed this exact signed artifact
before revocation"
```

### Scope boundary

v0.5 deliberately does not introduce:

* multi-observer quorum,
* transparency logs,
* trusted timestamp authorities,
* blockchain anchoring,
* consensus,
* payment execution,
* global allocation policy.

These belong in optional future profiles.

---

## [0.4.0] - 2026-08-10

### Added

* verification-key lifecycle semantics
* `valid_from`
* `valid_until`
* `revoked_at`
* `revocation_reason`
* `superseded_by`
* `supersedes`
* key-rotation consistency checks
* record/signature chronology checks

### Added invariants

* `FI-015` — Signature MUST NOT precede `key.valid_from`.
* `FI-016` — Signature MUST precede `key.valid_until`.
* `FI-017` — Signature MUST precede `key.revoked_at`.
* `FI-018` — Key lifecycle and rotation metadata MUST be internally consistent.
* `FI-019` — Signature MUST NOT precede the event time of the record.

### Security improvement

v0.3 proved:

```text
the signature is cryptographically valid
```

v0.4 additionally asks:

```text
was that key eligible to sign at the declared time?
```

This allows RFIP to reject otherwise valid signatures made using:

* not-yet-valid keys,
* expired keys,
* revoked keys,
* superseded keys outside their validity interval.

### Limitation identified

v0.4 explicitly recognizes that `signature.signed_at` is not an independent trusted timestamp.

This limitation became the design basis for v0.5.

---

## [0.3.0] - 2026-08-10

### Added

* cryptographic verification profile
* Ed25519 signature verification
* verification-key registry
* public-key resolution by `key_id`
* JWK-style Ed25519 public-key representation
* RFC 8785 canonical signature payload generation
* base64url signature decoding
* signer/controller consistency checks
* algorithm consistency checks

### Added schemas

* `verification-key-registry.schema.json`

### Added registry

* `registry/verification-keys.yaml`

### Added invariants

* `FI-011` — Signature key MUST resolve.
* `FI-012` — Signer, controller, and algorithm MUST be compatible.
* `FI-013` — Signature payload MUST use RFC 8785 canonicalization.
* `FI-014` — Ed25519 signature MUST cryptographically verify.

### Changed

Signature scope changed from:

```text
record-without-signature
```

to:

```text
record-without-signature-value
```

This ensures that signature metadata itself is protected.

Only:

```text
signature.value
```

is excluded from the signature input.

### Security improvement

v0.2 could describe a signature.

v0.3 can verify one.

---

## [0.2.0] - 2026-08-10

### Added

* namespaced Value vocabulary
* reusable `Value` schema
* reusable `SignatureEnvelope`
* signed FlowReceipt
* signed TraceRecord
* signed AuditRecord
* signed SettlementReceipt
* canonicalization metadata
* signature algorithm metadata
* signer identity metadata
* key identifier metadata
* settlement distribution-total validation
* source/settlement Value consistency checks

### Added value types

```text
currency
credit
point
token
usage_unit
compute_unit
custom
```

### Added invariants

* `FI-006` — Provenance records require SignatureEnvelope.
* `FI-007` — FlowRequest signer MUST equal Actor.
* `FI-008` — Value MUST use standardized type and namespaced unit.
* `FI-009` — Distribution total MUST equal settled amount.
* `FI-010` — Settlement Value semantics MUST remain compatible with source Flow.

### Changed

The v0.1 opaque signature string was replaced by a structured SignatureEnvelope.

Value changed from a loosely interpreted amount into:

```text
type
unit_namespace
unit
amount
```

### Design decision

RFIP remained policy-neutral.

No universal royalty percentage or allocation formula was introduced.

---

## [0.1.0] - 2026-08-10

### Added

Initial Royalty Flow Interface Protocol draft.

### Added core records

* `FlowRequest`
* `FlowReceipt`
* `TraceRecord`
* `AuditRecord`
* `SettlementReceipt`

### Added logical API

```text
POST /flow/in
GET  /flow/out/{flow_id}
GET  /trace/{trace_id}
GET  /audit/{audit_id}
```

### Added core invariants

* `FI-001` — Every Flow MUST reference an Origin.
* `FI-002` — Every accepted Flow MUST reference a resolvable Trace.
* `FI-003` — Trace MUST resolve to the declared Origin.
* `FI-004` — Settlement MUST NOT complete before Audit succeeds.
* `FI-005` — Completed Settlement MUST produce a verifiable receipt.

### Added

* JSON Schema Draft 2020-12 schemas
* pass examples
* fail examples
* semantic validation
* GitHub Actions validation workflow
* OpenAPI draft
* policy-neutral settlement model

### Initial design principle

RFIP was established around the principle:

> **A Flow MUST preserve the traceable relationship between value, origin, and settlement.**

### Initial scope boundary

RFIP deliberately did not define:

* royalty percentage,
* allocation algorithm,
* payment rail,
* blockchain requirement,
* custody model,
* taxation,
* identity infrastructure.

The protocol began as a minimal value-routing waterway rather than a centralized economic authority.

---

## Core Draft Summary

The v0.1 → v0.5 progression can be summarized as:

```text
v0.1
Route the value.

v0.2
Identify and sign the records.

v0.3
Verify the signatures.

v0.4
Verify that the keys were temporally eligible.

v0.5
Verify that an independent party observed
the exact signed artifact in time.
```

RFIP v0.5 therefore closes the current Core Draft around five questions:

```text
Where did the value originate?

Which route did it follow?

Was the route valid?

Were the records authentically signed?

Can their existence be independently evidenced in time?
```

Further sophistication should preferentially remain outside the minimal RFIP core.
