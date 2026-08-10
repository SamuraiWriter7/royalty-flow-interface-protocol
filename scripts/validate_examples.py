#!/usr/bin/env python3
"""Validate RFIP v0.5 including Temporal Evidence / Observation Receipts."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import math
import sys

from datetime import datetime
from pathlib import Path
from typing import Any

import rfc8785
import yaml

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from jsonschema import (
    Draft202012Validator,
    FormatChecker,
)

from referencing import (
    Registry,
    Resource,
)


ROOT = Path(__file__).resolve().parents[1]

SCHEMAS = ROOT / "schemas"

PASS_DIR = ROOT / "examples" / "pass"
FAIL_DIR = ROOT / "examples" / "fail"
SUPPORT_DIR = ROOT / "examples" / "support"

KEY_REGISTRY_PATH = (
    ROOT
    / "registry"
    / "verification-keys.yaml"
)


SCHEMA_FILES = {
    "value":
        SCHEMAS / "value.schema.json",

    "signature-envelope":
        SCHEMAS / "signature-envelope.schema.json",

    "verification-key-registry":
        SCHEMAS / "verification-key-registry.schema.json",

    "flow-request":
        SCHEMAS / "flow-request.schema.json",

    "flow-receipt":
        SCHEMAS / "flow-receipt.schema.json",

    "trace-record":
        SCHEMAS / "trace-record.schema.json",

    "audit-record":
        SCHEMAS / "audit-record.schema.json",

    "settlement-receipt":
        SCHEMAS / "settlement-receipt.schema.json",

    "observation-receipt":
        SCHEMAS / "observation-receipt.schema.json",
}


RECORD_TIME_FIELDS = {
    "flow-request": "occurred_at",
    "flow-receipt": "received_at",
    "trace-record": "created_at",
    "audit-record": "audited_at",
    "settlement-receipt": "settled_at",
    "observation-receipt": "observed_at",
}


RECORD_ID_FIELDS = {
    "flow-request": "flow_request_id",
    "flow-receipt": "flow_id",
    "trace-record": "trace_id",
    "audit-record": "audit_id",
    "settlement-receipt": "settlement_id",
}


FAIL_TYPE_HINTS = {
    "distribution-total-mismatch.example.yaml":
        "settlement-receipt",

    "settlement-without-audit.example.yaml":
        "settlement-receipt",

    "settlement-after-failed-audit.example.yaml":
        "settlement-receipt",

    "unsigned-trace.example.yaml":
        "trace-record",

    "rotated-key-after-cutover.example.yaml":
        "trace-record",
}


def load_json(
    path: Path,
) -> dict[str, Any]:

    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def load_yaml(
    path: Path,
) -> dict[str, Any]:

    data = yaml.safe_load(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        data,
        dict,
    ):

        raise ValueError(
            f"{path}: top-level YAML "
            "value must be an object"
        )

    return data


def parse_datetime(
    value: str,
) -> datetime:

    return datetime.fromisoformat(
        value.replace(
            "Z",
            "+00:00",
        )
    )


def build_schema_registry() -> Registry:

    registry = Registry()

    for path in SCHEMAS.glob(
        "*.json"
    ):

        schema = load_json(
            path
        )

        registry = registry.with_resource(
            schema["$id"],
            Resource.from_contents(
                schema
            ),
        )

    return registry


SCHEMA_REGISTRY = (
    build_schema_registry()
)


def record_type_for(
    path: Path,
    record: dict[str, Any],
) -> str:

    if "observation_id" in record:
        return "observation-receipt"

    if path.name in FAIL_TYPE_HINTS:
        return FAIL_TYPE_HINTS[
            path.name
        ]

    name = path.name.lower()

    if "flow-request" in name:
        return "flow-request"

    if "flow-receipt" in name:
        return "flow-receipt"

    if "trace-record" in name:
        return "trace-record"

    if "audit-record" in name:
        return "audit-record"

    if "settlement-receipt" in name:
        return "settlement-receipt"

    if "settlement_id" in record:
        return "settlement-receipt"

    if (
        "audit_id" in record
        and "decision" in record
    ):
        return "audit-record"

    if (
        "trace_id" in record
        and "route" in record
        and "flow_id" not in record
    ):
        return "trace-record"

    if (
        "flow_id" in record
        and "flow_request_id" in record
    ):
        return "flow-receipt"

    if (
        "flow_request_id" in record
        or "actor_id" in record
    ):
        return "flow-request"

    raise ValueError(
        f"Cannot infer record type "
        f"for {path}"
    )


def schema_errors(
    record_type: str,
    record: dict[str, Any],
) -> list[str]:

    validator = (
        Draft202012Validator(
            load_json(
                SCHEMA_FILES[
                    record_type
                ]
            ),
            registry=SCHEMA_REGISTRY,
            format_checker=FormatChecker(),
        )
    )

    errors = sorted(
        validator.iter_errors(
            record
        ),
        key=lambda error:
            list(error.path),
    )

    rendered: list[str] = []

    for error in errors:

        where = ".".join(
            str(part)
            for part
            in error.path
        ) or "<root>"

        rendered.append(
            f"{where}: "
            f"{error.message}"
        )

    return rendered


def b64url_decode(
    value: str,
) -> bytes:

    padding = (
        "="
        * (
            (
                4
                - len(value) % 4
            )
            % 4
        )
    )

    return base64.urlsafe_b64decode(
        value + padding
    )


def signature_payload(
    record: dict[str, Any],
) -> bytes:

    payload = copy.deepcopy(
        record
    )

    del payload[
        "signature"
    ][
        "value"
    ]

    return rfc8785.dumps(
        payload
    )


def record_digest(
    record: dict[str, Any],
) -> str:

    digest = hashlib.sha256(
        rfc8785.dumps(
            record
        )
    ).digest()

    return (
        base64.urlsafe_b64encode(
            digest
        )
        .rstrip(b"=")
        .decode("ascii")
    )


def load_verification_keys() -> tuple[
    dict[str, dict[str, Any]],
    list[str],
]:

    document = load_yaml(
        KEY_REGISTRY_PATH
    )

    errors = schema_errors(
        "verification-key-registry",
        document,
    )

    keys: dict[
        str,
        dict[str, Any],
    ] = {}

    if errors:

        return (
            keys,
            [
                "verification-key-registry "
                + error
                for error in errors
            ],
        )

    for item in document[
        "keys"
    ]:

        key_id = item[
            "key_id"
        ]

        if key_id in keys:

            errors.append(
                "FI-018: duplicate "
                "verification key_id: "
                f"{key_id}"
            )

        else:

            keys[
                key_id
            ] = item

    for key_id, item in (
        keys.items()
    ):

        valid_from = parse_datetime(
            item[
                "valid_from"
            ]
        )

        if "valid_until" in item:

            if (
                parse_datetime(
                    item[
                        "valid_until"
                    ]
                )
                <= valid_from
            ):

                errors.append(
                    "FI-018: valid_until "
                    "MUST be later than "
                    "valid_from: "
                    f"{key_id}"
                )

        if "revoked_at" in item:

            if (
                parse_datetime(
                    item[
                        "revoked_at"
                    ]
                )
                <= valid_from
            ):

                errors.append(
                    "FI-018: revoked_at "
                    "MUST be later than "
                    "valid_from: "
                    f"{key_id}"
                )

        successor_id = item.get(
            "superseded_by"
        )

        if successor_id:

            successor = keys.get(
                successor_id
            )

            if successor is None:

                errors.append(
                    "FI-018: superseded_by "
                    "does not resolve: "
                    f"{key_id} -> "
                    f"{successor_id}"
                )

            elif (
                successor[
                    "controller_id"
                ]
                != item[
                    "controller_id"
                ]
            ):

                errors.append(
                    "FI-018: rotated keys "
                    "MUST share controller_id: "
                    f"{key_id}"
                )

            if "valid_until" not in item:

                errors.append(
                    "FI-018: superseded key "
                    "MUST declare valid_until: "
                    f"{key_id}"
                )

    return (
        keys,
        errors,
    )


def signature_errors(
    record: dict[str, Any],
    verification_keys:
        dict[str, dict[str, Any]],
) -> list[str]:

    errors: list[str] = []

    signature = record[
        "signature"
    ]

    key_id = signature[
        "key_id"
    ]

    key_record = (
        verification_keys.get(
            key_id
        )
    )

    if key_record is None:

        return [
            "FI-011: signature "
            "key_id does not resolve: "
            f"{key_id}"
        ]

    if (
        key_record[
            "controller_id"
        ]
        != signature[
            "signer_id"
        ]
    ):

        errors.append(
            "FI-012: signature signer_id "
            "MUST equal verification "
            "key controller_id"
        )

    if (
        key_record[
            "algorithm"
        ]
        != signature[
            "algorithm"
        ]
    ):

        errors.append(
            "FI-012: signature algorithm "
            "MUST match verification "
            "key algorithm"
        )

    signed_at = parse_datetime(
        signature[
            "signed_at"
        ]
    )

    valid_from = parse_datetime(
        key_record[
            "valid_from"
        ]
    )

    if signed_at < valid_from:

        errors.append(
            "FI-015: signature.signed_at "
            "precedes key.valid_from"
        )

    if "valid_until" in key_record:

        if (
            signed_at
            >= parse_datetime(
                key_record[
                    "valid_until"
                ]
            )
        ):

            errors.append(
                "FI-016: key was no longer "
                "valid at signature.signed_at"
            )

    if "revoked_at" in key_record:

        if (
            signed_at
            >= parse_datetime(
                key_record[
                    "revoked_at"
                ]
            )
        ):

            errors.append(
                "FI-017: key was revoked "
                "at or before "
                "signature.signed_at"
            )

    try:

        public_bytes = (
            b64url_decode(
                key_record[
                    "public_key_jwk"
                ][
                    "x"
                ]
            )
        )

        signature_bytes = (
            b64url_decode(
                signature[
                    "value"
                ]
            )
        )

        public_key = (
            Ed25519PublicKey
            .from_public_bytes(
                public_bytes
            )
        )

        public_key.verify(
            signature_bytes,
            signature_payload(
                record
            ),
        )

    except (
        ValueError,
        InvalidSignature,
        binascii.Error,
    ):

        errors.append(
            "FI-014: Ed25519 "
            "signature verification failed"
        )

    return errors


def record_time_errors(
    record_type: str,
    record: dict[str, Any],
) -> list[str]:

    field = (
        RECORD_TIME_FIELDS[
            record_type
        ]
    )

    record_time = parse_datetime(
        record[
            field
        ]
    )

    signed_at = parse_datetime(
        record[
            "signature"
        ][
            "signed_at"
        ]
    )

    if signed_at < record_time:

        return [
            "FI-019: signature.signed_at "
            f"MUST NOT precede {field}"
        ]

    return []


def core_semantic_errors(
    record_type: str,
    record: dict[str, Any],
    *,
    traces:
        dict[str, dict[str, Any]],
    audits:
        dict[str, dict[str, Any]],
    flow_requests:
        dict[str, dict[str, Any]],
    flow_receipts:
        dict[str, dict[str, Any]],
    verification_keys:
        dict[str, dict[str, Any]],
) -> list[str]:

    errors = signature_errors(
        record,
        verification_keys,
    )

    errors.extend(
        record_time_errors(
            record_type,
            record,
        )
    )

    if record_type == "flow-request":

        trace = traces.get(
            record[
                "trace_id"
            ]
        )

        if trace is None:

            errors.append(
                "FI-002: referenced "
                "trace_id does not resolve"
            )

        elif (
            trace[
                "origin_id"
            ]
            != record[
                "origin_id"
            ]
        ):

            errors.append(
                "FI-003: trace origin_id "
                "does not match flow origin_id"
            )

        if (
            record[
                "signature"
            ][
                "signer_id"
            ]
            != record[
                "actor_id"
            ]
        ):

            errors.append(
                "FI-007: FlowRequest "
                "signer_id MUST equal actor_id"
            )

    elif record_type == "flow-receipt":

        if (
            record[
                "flow_request_id"
            ]
            not in flow_requests
        ):

            errors.append(
                "FlowReceipt references "
                "an unknown flow_request_id"
            )

    elif record_type == "trace-record":

        contains_origin = any(
            node[
                "node_type"
            ] == "origin"
            and node[
                "node_id"
            ] == record[
                "origin_id"
            ]
            for node
            in record[
                "route"
            ]
        )

        if not contains_origin:

            errors.append(
                "TraceRecord route "
                "MUST contain its "
                "declared origin"
            )

    elif record_type == "audit-record":

        trace = traces.get(
            record[
                "trace_id"
            ]
        )

        if trace is None:

            errors.append(
                "AuditRecord references "
                "an unknown trace_id"
            )

        elif (
            trace[
                "origin_id"
            ]
            != record[
                "origin_id"
            ]
        ):

            errors.append(
                "AuditRecord origin_id "
                "does not match "
                "TraceRecord origin_id"
            )

        receipt = (
            flow_receipts.get(
                record[
                    "flow_id"
                ]
            )
        )

        if receipt is None:

            errors.append(
                "AuditRecord references "
                "an unknown flow_id"
            )

        elif (
            receipt[
                "status"
            ] != "accepted"
            and record[
                "decision"
            ] == "passed"
        ):

            errors.append(
                "AuditRecord MUST NOT pass "
                "a rejected FlowReceipt"
            )

    elif (
        record_type
        == "settlement-receipt"
    ):

        audit = audits.get(
            record[
                "audit_id"
            ]
        )

        if audit is None:

            errors.append(
                "FI-004: settlement "
                "references an "
                "unknown audit_id"
            )

        else:

            if (
                audit[
                    "decision"
                ]
                != "passed"
            ):

                errors.append(
                    "FI-004: settlement "
                    "MUST NOT complete "
                    "unless audit decision "
                    "is passed"
                )

            for key in (
                "flow_id",
                "origin_id",
                "trace_id",
            ):

                if (
                    audit[
                        key
                    ]
                    != record[
                        key
                    ]
                ):

                    errors.append(
                        "SettlementReceipt "
                        f"{key} does not match "
                        "referenced AuditRecord"
                    )

        trace = traces.get(
            record[
                "trace_id"
            ]
        )

        if trace is None:

            errors.append(
                "SettlementReceipt "
                "references an "
                "unknown trace_id"
            )

        else:

            if (
                trace[
                    "origin_id"
                ]
                != record[
                    "origin_id"
                ]
            ):

                errors.append(
                    "SettlementReceipt "
                    "origin_id does not match "
                    "TraceRecord origin_id"
                )

            trace_nodes = {
                (
                    node[
                        "node_type"
                    ],
                    node[
                        "node_id"
                    ],
                )
                for node
                in trace[
                    "route"
                ]
            }

            for item in record[
                "distribution"
            ]:

                if (
                    item[
                        "recipient_type"
                    ]
                    == "custom"
                ):

                    continue

                candidate = (
                    item[
                        "recipient_type"
                    ],
                    item[
                        "recipient_id"
                    ],
                )

                if (
                    candidate
                    not in trace_nodes
                ):

                    errors.append(
                        "Distribution recipient "
                        "is not present in the "
                        "referenced TraceRecord: "
                        f"{item['recipient_type']}:"
                        f"{item['recipient_id']}"
                    )

        distributed = sum(
            item[
                "amount"
            ]
            for item
            in record[
                "distribution"
            ]
        )

        if not math.isclose(
            distributed,
            record[
                "settled_value"
            ][
                "amount"
            ],
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):

            errors.append(
                "FI-009: distribution total "
                "MUST equal "
                "settled_value.amount"
            )

        receipt = (
            flow_receipts.get(
                record[
                    "flow_id"
                ]
            )
        )

        if receipt is None:

            errors.append(
                "SettlementReceipt "
                "references an "
                "unknown flow_id"
            )

        else:

            request = (
                flow_requests.get(
                    receipt[
                        "flow_request_id"
                    ]
                )
            )

            if request is not None:

                source = request[
                    "value"
                ]

                settled = record[
                    "settled_value"
                ]

                for key in (
                    "type",
                    "unit_namespace",
                    "unit",
                ):

                    if (
                        source[
                            key
                        ]
                        != settled[
                            key
                        ]
                    ):

                        errors.append(
                            "FI-010: settled "
                            "value descriptor "
                            "MUST match "
                            "FlowRequest value "
                            f"descriptor ({key})"
                        )

                if (
                    settled[
                        "amount"
                    ]
                    > source[
                        "amount"
                    ]
                ):

                    errors.append(
                        "FI-010: "
                        "settled_value.amount "
                        "MUST NOT exceed "
                        "FlowRequest value.amount"
                    )

    return errors


def observation_semantic_errors(
    observation: dict[str, Any],
    *,
    targets:
        dict[
            tuple[str, str],
            dict[str, Any],
        ],
    verification_keys:
        dict[str, dict[str, Any]],
) -> list[str]:

    errors = signature_errors(
        observation,
        verification_keys,
    )

    errors.extend(
        record_time_errors(
            "observation-receipt",
            observation,
        )
    )

    if (
        observation[
            "signature"
        ][
            "signer_id"
        ]
        != observation[
            "observer_id"
        ]
    ):

        errors.append(
            "FI-023: ObservationReceipt "
            "signer_id MUST equal observer_id"
        )

    target_key = (
        observation[
            "target_record_type"
        ],
        observation[
            "target_record_id"
        ],
    )

    target = targets.get(
        target_key
    )

    if target is None:

        errors.append(
            "FI-020: ObservationReceipt "
            "target does not resolve"
        )

        return errors

    if (
        observation[
            "observer_id"
        ]
        == target[
            "signature"
        ][
            "signer_id"
        ]
    ):

        errors.append(
            "FI-023: observer_id "
            "MUST be independent "
            "from target signer_id"
        )

    expected_digest = (
        record_digest(
            target
        )
    )

    if (
        observation[
            "target_digest"
        ]
        != expected_digest
    ):

        errors.append(
            "FI-021: target_digest "
            "does not match the "
            "canonical signed target record"
        )

    observed_at = parse_datetime(
        observation[
            "observed_at"
        ]
    )

    target_signed_at = parse_datetime(
        target[
            "signature"
        ][
            "signed_at"
        ]
    )

    if (
        observed_at
        < target_signed_at
    ):

        errors.append(
            "FI-022: observed_at "
            "MUST NOT precede target "
            "signature.signed_at"
        )

    target_key_record = (
        verification_keys.get(
            target[
                "signature"
            ][
                "key_id"
            ]
        )
    )

    if target_key_record is not None:

        if (
            "valid_until"
            in target_key_record
        ):

            if (
                observed_at
                >= parse_datetime(
                    target_key_record[
                        "valid_until"
                    ]
                )
            ):

                errors.append(
                    "FI-024: target was not "
                    "observed before "
                    "key.valid_until"
                )

        if (
            "revoked_at"
            in target_key_record
        ):

            if (
                observed_at
                >= parse_datetime(
                    target_key_record[
                        "revoked_at"
                    ]
                )
            ):

                errors.append(
                    "FI-024: target was not "
                    "observed before "
                    "key.revoked_at"
                )

    return errors


def build_context():

    traces: dict[
        str,
        dict[str, Any],
    ] = {}

    audits: dict[
        str,
        dict[str, Any],
    ] = {}

    flow_requests: dict[
        str,
        dict[str, Any],
    ] = {}

    flow_receipts: dict[
        str,
        dict[str, Any],
    ] = {}

    targets: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    for directory in (
        PASS_DIR,
        SUPPORT_DIR,
    ):

        for path in sorted(
            directory.glob(
                "*.yaml"
            )
        ):

            record = load_yaml(
                path
            )

            kind = record_type_for(
                path,
                record,
            )

            if (
                kind
                == "observation-receipt"
            ):

                continue

            if kind in RECORD_ID_FIELDS:

                targets[
                    (
                        kind,
                        record[
                            RECORD_ID_FIELDS[
                                kind
                            ]
                        ],
                    )
                ] = record

            if kind == "trace-record":

                traces[
                    record[
                        "trace_id"
                    ]
                ] = record

            elif kind == "audit-record":

                audits[
                    record[
                        "audit_id"
                    ]
                ] = record

            elif kind == "flow-request":

                flow_requests[
                    record[
                        "flow_request_id"
                    ]
                ] = record

            elif kind == "flow-receipt":

                flow_receipts[
                    record[
                        "flow_id"
                    ]
                ] = record

    return (
        traces,
        audits,
        flow_requests,
        flow_receipts,
        targets,
    )


def load_support_observations() -> list[
    tuple[
        Path,
        dict[str, Any],
    ]
]:

    result = []

    for path in sorted(
        SUPPORT_DIR.glob(
            "observation-*.yaml"
        )
    ):

        result.append(
            (
                path,
                load_yaml(
                    path
                ),
            )
        )

    return result


def validate_pass_core(
    *,
    context,
    verification_keys:
        dict[str, dict[str, Any]],
) -> bool:

    (
        traces,
        audits,
        flow_requests,
        flow_receipts,
        _,
    ) = context

    ok = True

    print(
        "\n[pass examples]"
    )

    for path in sorted(
        PASS_DIR.glob(
            "*.yaml"
        )
    ):

        record = load_yaml(
            path
        )

        kind = record_type_for(
            path,
            record,
        )

        print(
            f"- {path.relative_to(ROOT)} "
            f"[{kind}]"
        )

        s_errors = schema_errors(
            kind,
            record,
        )

        if s_errors:

            ok = False

            for error in s_errors:

                print(
                    f"  [schema-error] "
                    f"{error}"
                )

            continue

        print(
            "  [schema-ok]"
        )

        m_errors = (
            core_semantic_errors(
                kind,
                record,
                traces=traces,
                audits=audits,
                flow_requests=
                    flow_requests,
                flow_receipts=
                    flow_receipts,
                verification_keys=
                    verification_keys,
            )
        )

        if m_errors:

            ok = False

            for error in m_errors:

                print(
                    "  "
                    f"[semantic-error] "
                    f"{error}"
                )

        else:

            print(
                "  [semantic-ok]"
            )

    return ok


def validate_temporal_evidence(
    *,
    context,
    verification_keys:
        dict[str, dict[str, Any]],
) -> bool:

    (
        _,
        _,
        _,
        _,
        targets,
    ) = context

    observations = (
        load_support_observations()
    )

    valid_targets: set[
        tuple[str, str]
    ] = set()

    ok = True

    print(
        "\n[temporal evidence]"
    )

    for (
        path,
        observation,
    ) in observations:

        print(
            f"- {path.relative_to(ROOT)} "
            "[observation-receipt]"
        )

        s_errors = schema_errors(
            "observation-receipt",
            observation,
        )

        if s_errors:

            ok = False

            for error in s_errors:

                print(
                    f"  [schema-error] "
                    f"{error}"
                )

            continue

        print(
            "  [schema-ok]"
        )

        m_errors = (
            observation_semantic_errors(
                observation,
                targets=targets,
                verification_keys=
                    verification_keys,
            )
        )

        if m_errors:

            ok = False

            for error in m_errors:

                print(
                    "  "
                    f"[semantic-error] "
                    f"{error}"
                )

        else:

            print(
                "  [semantic-ok]"
            )

            valid_targets.add(
                (
                    observation[
                        "target_record_type"
                    ],
                    observation[
                        "target_record_id"
                    ],
                )
            )

    for path in sorted(
        PASS_DIR.glob(
            "*.yaml"
        )
    ):

        record = load_yaml(
            path
        )

        kind = record_type_for(
            path,
            record,
        )

        target_key = (
            kind,
            record[
                RECORD_ID_FIELDS[
                    kind
                ]
            ],
        )

        if (
            target_key
            not in valid_targets
        ):

            ok = False

            print(
                "  "
                "[temporal-evidence-error] "
                "FI-020: no valid "
                "ObservationReceipt for "
                f"{kind}:"
                f"{target_key[1]}"
            )

    if ok:

        print(
            "  "
            "[temporal-evidence-complete]"
        )

    return ok


def validate_fail_examples(
    *,
    context,
    verification_keys:
        dict[str, dict[str, Any]],
) -> bool:

    (
        traces,
        audits,
        flow_requests,
        flow_receipts,
        targets,
    ) = context

    ok = True

    print(
        "\n[fail examples: "
        "failure expected]"
    )

    for path in sorted(
        FAIL_DIR.glob(
            "*.yaml"
        )
    ):

        record = load_yaml(
            path
        )

        kind = record_type_for(
            path,
            record,
        )

        print(
            f"- {path.relative_to(ROOT)} "
            f"[{kind}]"
        )

        s_errors = schema_errors(
            kind,
            record,
        )

        if s_errors:

            print(
                "  "
                "[expected-schema-failure]"
            )

            for error in s_errors:

                print(
                    f"    - {error}"
                )

            continue

        print(
            "  [schema-ok]"
        )

        if (
            kind
            == "observation-receipt"
        ):

            m_errors = (
                observation_semantic_errors(
                    record,
                    targets=targets,
                    verification_keys=
                        verification_keys,
                )
            )

        else:

            m_errors = (
                core_semantic_errors(
                    kind,
                    record,
                    traces=traces,
                    audits=audits,
                    flow_requests=
                        flow_requests,
                    flow_receipts=
                        flow_receipts,
                    verification_keys=
                        verification_keys,
                )
            )

        if m_errors:

            print(
                "  "
                "[expected-semantic-failure]"
            )

            for error in m_errors:

                print(
                    f"    - {error}"
                )

        else:

            ok = False

            print(
                "  "
                "[unexpected-pass] "
                "fail fixture did not fail"
            )

    return ok


def main() -> int:

    print(
        "=== Royalty Flow Interface "
        "Protocol v0.5 Validation ==="
    )

    for name, path in (
        SCHEMA_FILES.items()
    ):

        print(
            f"schema [{name}]: "
            f"{path.relative_to(ROOT)}"
        )

        Draft202012Validator.check_schema(
            load_json(
                path
            )
        )

    print(
        "[schema-definitions-ok]"
    )

    (
        verification_keys,
        key_errors,
    ) = load_verification_keys()

    if key_errors:

        for error in key_errors:

            print(
                "[key-registry-error] "
                f"{error}"
            )

        return 1

    print(
        "[verification-key-registry-ok] "
        f"keys={len(verification_keys)}"
    )

    context = build_context()

    pass_ok = validate_pass_core(
        context=context,
        verification_keys=
            verification_keys,
    )

    temporal_ok = (
        validate_temporal_evidence(
            context=context,
            verification_keys=
                verification_keys,
        )
    )

    fail_ok = validate_fail_examples(
        context=context,
        verification_keys=
            verification_keys,
    )

    if (
        pass_ok
        and temporal_ok
        and fail_ok
    ):

        print(
            "\nValidation passed."
        )

        return 0

    print(
        "\nValidation failed."
    )

    return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )
