# Royalty Flow Interface Protocol Specification

**RFIP v0.5.0**

**Status:** Core Draft Complete

---

## 1. Scope

Royalty Flow Interface Protocol (RFIP) defines a minimal, policy-neutral protocol for traceable value routing.

RFIP standardizes the verifiable relationships among:

```text
Actor
Origin
Trace
Value
Audit
Settlement
Signature
Verification Key
Observation
```

RFIP does not standardize allocation percentages, taxation, legal ownership, payment rails, exchange rates, or economic policy.

---

## 2. Normative Language

The keywords:

```text
MUST
MUST NOT
REQUIRED
SHOULD
SHOULD NOT
MAY
```

are normative when written in uppercase.

---

## 3. Core Principle

An RFIP Flow MUST preserve the traceable relationship between:

```text
Value
Origin
Trace
Audit
Settlement
```

A completed Settlement MUST remain verifiably linked to the declared Origin.

---

## 4. Record Types

RFIP v0.5 defines:

```text
FlowRequest
FlowReceipt
TraceRecord
AuditRecord
SettlementReceipt
ObservationReceipt
```

Supporting types are:

```text
Value
SignatureEnvelope
VerificationKeyRegistry
```

---

## 5. FlowRequest

A `FlowRequest` declares an Actor's intent to route Value.

A FlowRequest MUST contain:

```text
schema_version
flow_request_id
actor_id
origin_id
trace_id
value
occurred_at
signature
```

The FlowRequest signer MUST be the declared Actor.

Therefore:

```text
signature.signer_id == actor_id
```

MUST hold.

---

## 6. FlowReceipt

A `FlowReceipt` acknowledges receipt of a FlowRequest.

Its status is:

```text
accepted
rejected
```

`accepted` MUST NOT be interpreted as `settled`.

A rejected FlowReceipt MUST contain a reason.

---

## 7. TraceRecord

A `TraceRecord` binds a routing structure to an Origin.

A TraceRecord MUST contain its declared Origin within its route.

A Flow referencing a TraceRecord MUST satisfy:

```text
FlowRequest.origin_id
==
TraceRecord.origin_id
```

A Trace that cannot be resolved MUST NOT be used for an accepted Flow.

---

## 8. AuditRecord

An `AuditRecord` records verification of the Flow and Trace relationship.

Its decision is:

```text
passed
failed
held
```

A Settlement MUST NOT complete unless the referenced AuditRecord has:

```text
decision: passed
```

---

## 9. SettlementReceipt

A `SettlementReceipt` records the completed routing result.

A completed SettlementReceipt MUST contain:

```text
settlement_id
flow_id
origin_id
trace_id
audit_id
settled_value
route
distribution
settled_at
signature
```

The identifiers:

```text
flow_id
origin_id
trace_id
```

MUST remain consistent with the referenced AuditRecord.

---

## 10. Distribution Consistency

For a completed Settlement:

```text
sum(distribution[].amount)
==
settled_value.amount
```

MUST hold.

Recipients using standard RFIP recipient types SHOULD appear in the referenced Trace.

Implementation-defined custom recipients MAY be handled by an external allocation policy.

---

## 11. Value Model

A Value MUST contain:

```text
type
unit_namespace
unit
amount
```

`amount` MUST be positive for routed Value.

Recognized RFIP v0.5 types are:

```text
currency
credit
point
token
usage_unit
compute_unit
custom
```

For:

```text
type: currency
```

the namespace MUST be:

```text
iso4217
```

and the unit SHOULD represent an ISO 4217 currency identifier.

Custom units MUST use an implementation-controlled namespace.

---

## 12. Value Preservation

Settlement Value semantics MUST remain compatible with the originating FlowRequest.

The following descriptors MUST remain consistent unless an external conversion profile explicitly defines otherwise:

```text
type
unit_namespace
unit
```

In the RFIP Core Draft, a Settlement MUST NOT claim an amount greater than the originating FlowRequest amount.

RFIP does not define currency conversion or value transformation.

---

## 13. SignatureEnvelope

RFIP v0.5 uses:

```text
algorithm: Ed25519
canonicalization: JCS-RFC8785
scope: record-without-signature-value
encoding: base64url
```

A SignatureEnvelope contains:

```text
algorithm
key_id
signer_id
canonicalization
scope
encoding
signed_at
value
```

---

## 14. Signature Payload

The signature input MUST be derived from the complete record after removing only:

```text
signature.value
```

The remaining object MUST be canonicalized using RFC 8785 JSON Canonicalization Scheme.

Conceptually:

```text
payload =
JCS(
  record
  minus signature.value
)
```

The following signature metadata therefore remains protected:

```text
algorithm
key_id
signer_id
canonicalization
scope
encoding
signed_at
```

---

## 15. Cryptographic Verification

The verifier MUST:

1. resolve `signature.key_id`,
2. obtain the referenced verification key,
3. confirm key-controller compatibility,
4. confirm algorithm compatibility,
5. construct the canonical signature payload,
6. decode the signature,
7. perform Ed25519 verification.

A cryptographically invalid signature MUST be rejected.

---

## 16. VerificationKeyRegistry

A VerificationKeyRegistry maps:

```text
key_id
```

to:

```text
controller_id
algorithm
public_key_jwk
valid_from
valid_until
revoked_at
rotation metadata
```

A `key_id` MUST be unique within the registry used for validation.

---

## 17. Key Validity

A verification key becomes usable at:

```text
valid_from
```

If:

```text
valid_until
```

exists, the validity interval is:

```text
[valid_from, valid_until)
```

Therefore:

```text
signed_at < valid_from
```

MUST be rejected.

And:

```text
signed_at >= valid_until
```

MUST be rejected.

---

## 18. Key Revocation

If a key contains:

```text
revoked_at
```

then:

```text
signed_at >= revoked_at
```

MUST be rejected.

A revoked key SHOULD provide a revocation reason.

Possible reasons include:

```text
compromised
suspected_compromise
administrative
superseded
other
```

---

## 19. Key Rotation

A key MAY identify its successor using:

```text
superseded_by
```

The successor MAY identify its predecessor using:

```text
supersedes
```

Rotation links SHOULD be reciprocal.

Rotated keys SHOULD retain the same logical controller.

A superseded key MUST define an appropriate validity cutoff if the implementation relies on temporal key eligibility.

---

## 20. Record Chronology

A record MUST NOT claim a signature time earlier than its own event time.

The following relations apply:

```text
FlowRequest:
occurred_at <= signature.signed_at

FlowReceipt:
received_at <= signature.signed_at

TraceRecord:
created_at <= signature.signed_at

AuditRecord:
audited_at <= signature.signed_at

SettlementReceipt:
settled_at <= signature.signed_at

ObservationReceipt:
observed_at <= signature.signed_at
```

---

## 21. Limitation of signed_at

`signature.signed_at` is protected by the signature.

However, it remains a time asserted by the signer.

Cryptographic validity alone does not prove that a signed record truly existed at the declared historical time.

For this reason RFIP v0.5 defines independent ObservationReceipts.

---

## 22. ObservationReceipt

An `ObservationReceipt` states that an independent Observer possessed a specific signed RFIP record no later than `observed_at`.

It MUST contain:

```text
schema_version
observation_id
observer_id
target_record_type
target_record_id
target_digest
digest_algorithm
canonicalization
observed_at
signature
```

---

## 23. Observation Target

The ObservationReceipt MUST identify both:

```text
target_record_type
target_record_id
```

The target MUST resolve to a concrete RFIP record.

An unresolved target MUST be rejected.

---

## 24. Observation Digest

The target digest MUST be calculated from the **complete signed target record**.

The digest input therefore includes:

```text
signature.value
```

The calculation is:

```text
canonical_target =
JCS(
  complete signed target record
)

target_digest =
base64url-no-padding(
  SHA-256(canonical_target)
)
```

This differs intentionally from the signature payload.

The signature excludes its own signature value.

The Observation digest includes the target signature value.

---

## 25. Observation Chronology

For a valid ObservationReceipt:

```text
target.signature.signed_at
<=
ObservationReceipt.observed_at
```

MUST hold.

The Observer cannot validly claim to have observed a signed artifact before that artifact's declared signature existed.

---

## 26. Observer Independence

An Observer MUST be independent from the signer of the target record for RFIP Temporal Evidence conformance.

Therefore:

```text
ObservationReceipt.observer_id
!=
target.signature.signer_id
```

MUST hold.

The ObservationReceipt's own signature MUST also satisfy:

```text
ObservationReceipt.signature.signer_id
==
ObservationReceipt.observer_id
```

---

## 27. Observation Signature

The ObservationReceipt MUST itself be signed.

Its signature MUST satisfy the same cryptographic and key-lifecycle requirements as other signed RFIP records.

The Observer's verification key MUST therefore:

* resolve,
* match the Observer,
* be valid at the ObservationReceipt signature time,
* not be expired,
* not be revoked,
* and successfully verify the Ed25519 signature.

---

## 28. Pre-cutoff Evidence

ObservationReceipts may be used to determine whether a record was externally observed before a signing-key cutoff.

If the target signing key has:

```text
valid_until
```

then Temporal Evidence for pre-expiration existence requires:

```text
observed_at < valid_until
```

If the target signing key has:

```text
revoked_at
```

then Temporal Evidence for pre-revocation existence requires:

```text
observed_at < revoked_at
```

An observation made at or after the cutoff does not prove that the target existed before that cutoff.

---

## 29. Example Temporal Sequence

Valid:

```text
record event
00:00:03

signed_at
00:00:04

independent observed_at
00:00:04.5

key revoked_at
00:00:05
```

Relationship:

```text
event
<= signed_at
<= observed_at
< revoked_at
```

This provides evidence that the exact signed record was observed before revocation.

Invalid for pre-revocation evidence:

```text
signed_at
00:00:04

revoked_at
00:00:05

observed_at
00:00:06
```

Even if the signature is cryptographically valid, the observation occurred too late to establish pre-revocation existence.

---

## 30. Conformance Classes

### 30.1 RFIP Core Conformance

RFIP Core Conformance covers:

```text
FlowRequest
FlowReceipt
TraceRecord
AuditRecord
SettlementReceipt
Value
SignatureEnvelope
VerificationKeyRegistry
```

and the applicable invariants through FI-019.

### 30.2 RFIP Temporal Evidence Conformance

RFIP Temporal Evidence Conformance additionally requires:

```text
ObservationReceipt
target digest validation
observer independence
observation chronology
pre-cutoff observation validation
observer signature validation
```

and the applicable invariants FI-020 through FI-025.

---

## 31. Normative Invariants

### FI-001

Every Flow MUST reference an Origin.

### FI-002

Every accepted Flow MUST reference a resolvable Trace.

### FI-003

The referenced Trace MUST resolve to the declared Origin.

### FI-004

Settlement MUST NOT complete before Audit succeeds.

### FI-005

Every completed Settlement MUST produce a signed, verifiable SettlementReceipt.

### FI-006

RFIP provenance records requiring authentication MUST carry a SignatureEnvelope.

### FI-007

A FlowRequest signature signer MUST equal its Actor.

### FI-008

Every Value MUST use a recognized value type and namespaced unit.

### FI-009

Settlement distribution totals MUST equal the settled amount.

### FI-010

Settlement Value semantics MUST remain compatible with the originating FlowRequest.

### FI-011

Every signature key identifier MUST resolve.

### FI-012

The signer, key controller, and signature algorithm MUST be compatible.

### FI-013

The signature payload MUST be derived from the RFC 8785 canonical representation of the record excluding only `signature.value`.

### FI-014

The Ed25519 signature MUST cryptographically verify.

### FI-015

A signature MUST NOT precede the referenced key's `valid_from`.

### FI-016

A signature MUST precede `valid_until` when that field exists.

### FI-017

A signature MUST precede `revoked_at` when that field exists.

### FI-018

Verification-key lifecycle and rotation metadata MUST be internally consistent.

### FI-019

A signature MUST NOT precede the event time of its own record.

### FI-020

A target requiring Temporal Evidence MUST have at least one valid ObservationReceipt.

### FI-021

An ObservationReceipt digest MUST match the complete signed target artifact.

### FI-022

Observation time MUST NOT precede target signature time.

### FI-023

The Observer MUST be independent from the target signer and MUST sign its own ObservationReceipt.

### FI-024

Pre-cutoff existence requires observation before the relevant expiration or revocation boundary.

### FI-025

The ObservationReceipt signature MUST itself be cryptographically valid and temporally eligible.

---

## 32. Allocation Policy

RFIP MUST NOT require a universal allocation percentage.

Implementations MAY independently determine:

```text
royalty percentage
revenue share
point distribution
credit allocation
token distribution
custom economic policy
```

The policy MAY differ between RFIP implementations.

Traceability semantics remain the shared layer.

---

## 33. Minimal Interface

The RFIP Core Draft defines the logical Flow Interface:

```text
POST /flow/in

GET /flow/out/{flow_id}

GET /trace/{trace_id}

GET /audit/{audit_id}
```

ObservationReceipt transport is not standardized by v0.5.

Implementations MAY distribute ObservationReceipts through:

```text
HTTP APIs
message buses
registries
object storage
distributed storage
transparency systems
other implementation-defined transports
```

provided the Receipt itself conforms to RFIP.

---

## 34. Trust Boundary

RFIP verifies protocol relationships.

RFIP does not prove all external facts.

In particular, RFIP does not inherently prove:

* legal intellectual-property ownership,
* legal entitlement to royalty,
* actual bank settlement,
* honesty of an Observer,
* honesty of a key registry operator,
* globally synchronized clocks,
* absence of collusion,
* correctness of off-protocol allocation policy.

These require external trust or companion protocols.

---

## 35. Single-Observer Limitation

An ObservationReceipt provides stronger temporal evidence than signer-declared time alone.

However, one Observer is still one trust point.

A malicious or colluding Observer may issue misleading evidence.

Possible stronger profiles include:

```text
multiple independent observers
observer quorum
append-only transparency logs
trusted timestamp authorities
distributed anchoring
blockchain anchoring
Merkle transparency structures
```

These are outside the RFIP v0.5 Core Draft.

---

## 36. Completion Boundary

RFIP v0.5 marks the planned completion boundary of the current Core Draft series.

The base protocol SHOULD remain small.

Future functionality SHOULD preferentially be defined as:

```text
optional profile
adapter
companion protocol
conformance extension
```

rather than being automatically added to the RFIP base.

Potential future profiles include:

```text
Multi-Observer Profile
Transparency Log Profile
Trusted Timestamp Profile
Payment Adapter Profile
Privacy Proof Profile
Dispute Profile
```

None are required for RFIP v0.5 Core Conformance.

---

## 37. Final Model

RFIP v0.5 can be summarized as:

```text
Actor
  |
  v
FlowRequest
  |
  v
Trace
  |
  v
Audit
  |
  v
Settlement
  |
  v
Origin / Derivative recipients
```

with a verification plane:

```text
Every signed record
   |
   ├─ JCS canonicalization
   ├─ Ed25519 verification
   ├─ key resolution
   ├─ key lifecycle validation
   └─ optional Temporal Evidence
          |
          v
   ObservationReceipt
```

The protocol's purpose is not to centrally determine value.

Its purpose is to make value flow without losing its verifiable relationship to origin.
