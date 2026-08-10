# Royalty Flow Interface Protocol

**RFIP — Royalty Flow Interface Protocol**

> A minimal, policy-neutral protocol for routing traceable value from actors through origin, trace, audit, settlement, and temporal evidence.

**Version:** `v0.5.0`
**Status:** Core Draft Complete

---

## 1. Overview

Royalty Flow Interface Protocol (RFIP) defines a minimal interface for routing value while preserving the relationship between:

* who caused the value flow,
* where the value originated,
* which trace connects the flow to that origin,
* whether the route was audited,
* how the value was settled,
* and when the signed records were independently observed.

RFIP does **not** define a universal royalty percentage.

RFIP does **not** decide how much value an implementation must return.

RFIP standardizes the **meaning and verifiability of the route**, while leaving allocation policy to each economic system.

The central principle is:

> **A Flow MUST preserve the traceable relationship between value, origin, and settlement.**

日本語では、

> **Flowは、価値・起源・清算の追跡可能な関係を失ってはならない。**

---

## 2. Design Philosophy

RFIP is designed as a **waterway standard, not a central dam**.

Different systems may choose different allocation policies.

For example:

```text
Platform A
  └─ returns 1% of revenue

API Provider B
  └─ returns 10 API credits

Agent Network C
  └─ distributes points

Marketplace D
  └─ uses its own token or accounting unit
```

RFIP does not attempt to make these policies identical.

Instead, RFIP provides a common structure for answering:

```text
What value moved?

Who moved it?

Which Origin is it linked to?

Which Trace proves that relationship?

Was the route valid?

How was it settled?

Can the signed records be independently verified?

Was the record externally observed before a relevant key cutoff?
```

---

## 3. Core Flow

```text
[Actor]
   |
   | FlowRequest
   v
[Flow Port]
   |
   | FlowReceipt
   v
[Trace Resolution]
   |
   | TraceRecord
   v
[Audit]
   |
   | AuditRecord
   v
[Settlement]
   |
   | SettlementReceipt
   v
[Origin / Derivative / Trace-valid recipients]
```

RFIP v0.5 additionally supports independent temporal evidence:

```text
Signed Core Record
       |
       | SHA-256(JCS(full signed record))
       v
   Record Digest
       |
       | observed by independent party
       v
ObservationReceipt
       |
       | independently signed
       v
Temporal Evidence
```

---

## 4. Core Record Types

RFIP v0.5 defines six principal records:

```text
FlowRequest
FlowReceipt
TraceRecord
AuditRecord
SettlementReceipt
ObservationReceipt
```

Supporting infrastructure includes:

```text
VerificationKeyRegistry
SignatureEnvelope
Value
```

The first five records describe the value-flow lifecycle.

`ObservationReceipt` provides external evidence that a specific signed record existed no later than an independently declared observation time.

---

## 5. Version Evolution

RFIP intentionally evolved in small layers.

```text
v0.1
Flow Routing
  |
  | Defines the waterway
  v
Origin → Trace → Audit → Settlement


v0.2
Signature Envelope
  |
  | Defines who claims authorship
  v
Signed Records


v0.3
Cryptographic Verification
  |
  | Resolves keys and verifies Ed25519
  v
Verifiable Signed Records


v0.4
Key Lifecycle
  |
  | Checks validity, expiration and revocation
  v
Time-bounded Verification


v0.5
Temporal Evidence
  |
  | Adds independent ObservationReceipt
  v
Externally Observed Value-Flow Evidence
```

v0.5 is the planned completion boundary for the current RFIP Core Draft.

More advanced mechanisms such as multi-observer quorum, transparency logs, external timestamp authorities, payment adapters, or blockchain anchors should normally be implemented as optional profiles or companion protocols rather than expanding the RFIP core indefinitely.

---

## 6. Core Invariants

RFIP defines normative Flow Invariants.

### Flow and Origin

```text
FI-001
Every Flow MUST reference an Origin.

FI-002
Every accepted Flow MUST reference a resolvable Trace.

FI-003
The referenced Trace MUST resolve to the declared Origin.

FI-004
Settlement MUST NOT complete before Audit succeeds.

FI-005
Every completed Settlement MUST produce a signed,
verifiable SettlementReceipt.
```

### Value and Signature Semantics

```text
FI-006
Core RFIP records that require provenance MUST carry
a SignatureEnvelope.

FI-007
A FlowRequest signature signer_id MUST equal actor_id.

FI-008
Every Value MUST use a standardized value type
and a namespaced unit.

FI-009
The sum of Settlement distribution amounts
MUST equal settled_value.amount.

FI-010
Settlement value semantics MUST remain compatible
with the originating FlowRequest.
```

### Cryptographic Verification

```text
FI-011
Every signature key_id MUST resolve to a registered
verification key.

FI-012
signature.signer_id MUST match the verification-key
controller and the algorithms MUST be compatible.

FI-013
The signed payload MUST be the RFC 8785 canonical
representation of the complete record excluding only
signature.value.

FI-014
The Ed25519 signature MUST cryptographically verify.
```

### Key Lifecycle

```text
FI-015
signature.signed_at MUST NOT precede key.valid_from.

FI-016
If key.valid_until exists, signature.signed_at MUST
be earlier than valid_until.

FI-017
If key.revoked_at exists, signature.signed_at MUST
be earlier than revoked_at.

FI-018
Verification-key lifecycle and rotation metadata
MUST be internally consistent.

FI-019
signature.signed_at MUST NOT precede the event time
of the record being signed.
```

### Temporal Evidence

```text
FI-020
A record conforming to the Temporal Evidence Profile
MUST have at least one valid ObservationReceipt.

FI-021
ObservationReceipt.target_digest MUST equal
SHA-256(JCS(the complete signed target record)).

FI-022
ObservationReceipt.observed_at MUST NOT precede
the target signature.signed_at.

FI-023
The observer MUST be independent from the target signer,
and the ObservationReceipt signer MUST represent observer_id.

FI-024
To establish pre-cutoff existence, the target MUST be
observed before the signing key's valid_until or revoked_at.

FI-025
The ObservationReceipt itself MUST carry a cryptographically
valid signature from a key valid at observation time.
```

---

## 7. Value Representation

RFIP is not limited to fiat currency.

A value is represented using:

```yaml
value:
  type: "currency"
  unit_namespace: "iso4217"
  unit: "JPY"
  amount: 1000
```

RFIP v0.5 recognizes:

```text
currency
credit
point
token
usage_unit
compute_unit
custom
```

Examples:

```yaml
type: "currency"
unit_namespace: "iso4217"
unit: "JPY"
```

```yaml
type: "credit"
unit_namespace: "example.api"
unit: "API_CREDIT"
```

```yaml
type: "compute_unit"
unit_namespace: "example.compute"
unit: "GPU_SECOND"
```

RFIP does not define exchange rates between different units.

---

## 8. Policy Neutrality

RFIP deliberately separates:

```text
Routing Semantics
        |
        | standardized
        v
RFIP

from

Allocation Policy
        |
        | implementation-defined
        v
1% / 10% / points / credits / custom policy
```

RFIP therefore does not define:

* royalty percentages,
* tax rates,
* beneficiary policy,
* revenue-sharing formulas,
* payment processor selection,
* blockchain requirements,
* custody arrangements,
* exchange-rate rules.

An implementation decides **how much** to flow.

RFIP defines **how the flow remains traceable and verifiable**.

---

## 9. Signature Model

RFIP v0.5 uses a SignatureEnvelope.

Example:

```yaml
signature:
  algorithm: "Ed25519"
  key_id: "did:example:actor-alpha#key-1"
  signer_id: "actor-alpha"
  canonicalization: "JCS-RFC8785"
  scope: "record-without-signature-value"
  encoding: "base64url"
  signed_at: "2026-08-10T00:00:00Z"
  value: "..."
```

The signature protects the entire record except:

```text
signature.value
```

This means the following remain protected by the signature:

```text
schema_version
record identifiers
Origin and Trace references
Value
timestamps
key_id
signer_id
algorithm
canonicalization
scope
encoding
signed_at
```

---

## 10. Key Lifecycle

A cryptographically valid signature is not automatically an authorized historical signature.

RFIP therefore models verification-key lifetime.

```text
valid_from
    |
    | usable interval
    v
valid_until

or

valid_from
    |
    v
revoked_at
```

The validity interval is interpreted as:

```text
[valid_from, valid_until)
```

A signature at or after `valid_until` is rejected.

A signature at or after `revoked_at` is rejected.

RFIP also supports key rotation using:

```text
superseded_by
supersedes
```

---

## 11. Temporal Evidence

Cryptographic signatures prove that someone controlling a private key signed a payload.

They do not independently prove when that payload first existed.

RFIP v0.5 therefore introduces `ObservationReceipt`.

Example concept:

```text
Actor signs record at:
00:00:04

Key revoked at:
00:00:05

Independent observer sees exact record at:
00:00:04.5

=> evidence exists that the exact signed record
   existed before revocation
```

By contrast:

```text
Actor claims:
signed_at = 00:00:04

Key revoked:
00:00:05

First independent observation:
00:00:06
```

does not establish that the record existed before revocation.

This distinction reduces reliance on signer-declared timestamps alone.

---

## 12. Observation Digest

An ObservationReceipt binds to the **complete signed target record**.

The digest is calculated as:

```text
SHA-256(
  JCS(
    complete signed target record
  )
)
```

Unlike the signature input, the Observation digest includes:

```text
signature.value
```

This means the observation proves possession of the exact signed artifact, not merely a record with the same identifier.

---

## 13. Minimal API Surface

The original RFIP Flow Interface remains intentionally small:

```text
POST /flow/in
GET  /flow/out/{flow_id}
GET  /trace/{trace_id}
GET  /audit/{audit_id}
```

`POST /flow/in`

Submits a `FlowRequest`.

`GET /flow/out/{flow_id}`

Returns the completed `SettlementReceipt`.

It does not itself perform settlement.

`GET /trace/{trace_id}`

Returns the referenced `TraceRecord`.

`GET /audit/{audit_id}`

Returns the referenced `AuditRecord`.

RFIP v0.5 defines the **ObservationReceipt data model and validation semantics**, but deliberately does not require a specific network endpoint for distributing ObservationReceipts.

Transport remains implementation-defined.

---

## 14. Conformance Profiles

RFIP v0.5 distinguishes two useful conformance levels.

### RFIP Core

An implementation validates:

```text
Flow
Value
Trace
Audit
Settlement
Signatures
Cryptographic verification
Key lifecycle
```

and satisfies the relevant invariants through FI-019.

### RFIP Temporal Evidence

An implementation additionally validates:

```text
ObservationReceipt
Target digest
Observer independence
Observation chronology
Pre-cutoff observation
Observer signature
```

and satisfies FI-020 through FI-025.

The reference v0.5 validation examples exercise the Temporal Evidence Profile.

---

## 15. Repository Structure

```text
royalty-flow-interface-protocol/
├── .github/
│   └── workflows/
│       └── validate.yml
├── examples/
│   ├── pass/
│   ├── fail/
│   └── support/
├── openapi/
│   └── flow-interface.openapi.yaml
├── registry/
│   └── verification-keys.yaml
├── schemas/
│   ├── value.schema.json
│   ├── signature-envelope.schema.json
│   ├── verification-key-registry.schema.json
│   ├── flow-request.schema.json
│   ├── flow-receipt.schema.json
│   ├── trace-record.schema.json
│   ├── audit-record.schema.json
│   ├── settlement-receipt.schema.json
│   └── observation-receipt.schema.json
├── scripts/
│   └── validate_examples.py
├── CHANGELOG.md
├── README.md
├── SPEC.md
└── requirements.txt
```

---

## 16. Validation

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run:

```bash
python scripts/validate_examples.py
```

The validation suite checks:

* JSON Schema conformance,
* Origin/Trace consistency,
* settlement ordering,
* value consistency,
* distribution totals,
* verification-key resolution,
* Ed25519 signatures,
* JCS signature payloads,
* key validity,
* expiration,
* revocation,
* chronology,
* ObservationReceipt target resolution,
* full-record digest binding,
* observer independence,
* temporal cutoff evidence.

Files under:

```text
examples/pass/
```

are expected to pass.

Files under:

```text
examples/fail/
```

are expected to fail for a deliberate reason.

---

## 17. Security Boundary

RFIP improves verifiability but does not claim perfect trust.

RFIP v0.5 does not by itself guarantee:

* that an Observer is honest,
* that a VerificationKeyRegistry is globally trustworthy,
* that clocks are perfectly synchronized,
* that a single Observer cannot collude with another party,
* that external payment actually occurred,
* that a legal royalty obligation exists,
* that an Origin claim is legally valid intellectual-property ownership.

RFIP verifies relationships between protocol records.

It does not replace legal systems, payment systems, identity systems, or external trust infrastructure.

---

## 18. Core Completion Boundary

RFIP v0.5 intentionally stops before introducing:

* multi-observer quorum,
* transparency logs,
* trusted timestamp authorities,
* blockchain anchors,
* consensus systems,
* external payment adapters,
* dispute courts,
* global allocation policy.

These mechanisms may be valuable, but they are not necessary to define the minimal RFIP core.

Future work should prefer optional profiles or companion protocols rather than continually enlarging the base specification.

---

## 19. Final Structural View

```text
                    ┌──────────────┐
                    │    Origin    │
                    └──────▲───────┘
                           │
                       Settlement
                           │
                    ┌──────┴───────┐
                    │    Audit     │
                    └──────▲───────┘
                           │
                        Trace
                           │
                    ┌──────┴───────┐
                    │     Flow     │
                    └──────▲───────┘
                           │
                         Actor


Every major record
        │
        ├── Signature
        │
        ├── Key Verification
        │
        ├── Key Lifecycle
        │
        └── Optional Temporal Evidence
                │
                ▼
        ObservationReceipt
```

RFIP is therefore not a protocol for deciding who deserves value.

It is a protocol for ensuring that:

> **Value can move without forgetting where it came from.**
