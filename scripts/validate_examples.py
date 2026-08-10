#!/usr/bin/env python3
"""Validate RFIP v0.3 schemas, invariants, and Ed25519 signatures."""

from __future__ import annotations

import base64
import binascii
import copy
import json
import math
import sys

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
        SCHEMAS
        / "verification-key-registry.schema.json",

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


def build_schema_registry() -> Registry:

    registry = Registry()

    for path in SCHEMAS.glob(
        "*.json"
    ):

        schema = load_json(
            path
        )

        registry = (
            registry.with_resource(
                schema["$id"],
                Resource.from_contents(
                    schema
                ),
            )
        )

    return registry


SCHEMA_REGISTRY = (
    build_schema_registry()
)


def record_type_for(
    path: Path,
    record: dict[str, Any],
) -> str:
    """
    Infer the intended record type.

    Fail fixtures may intentionally omit
    required fields, so filename hints are
    checked before field inference.
    """

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

    if path.parent == FAIL_DIR:
        return "flow-request"

    raise ValueError(
        f"Cannot infer record type "
        f"for {path}"
    )


def schema_errors(
    record_type: str,
    record: dict[str, Any],
) -> list[str]:

    schema = load_json(
        SCHEMA_FILES[
            record_type
        ]
    )

    validator = (
        Draft202012Validator(
            schema,
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

    return (
        base64.urlsafe_b64decode(
            value + padding
        )
    )


def signature_payload(
    record: dict[str, Any],
) -> bytes:
    """
    RFIP v0.3 signature input.

    Protect the entire record except
    signature.value.
    """

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


def load_verification_keys() -> tuple[
    dict[str, Any],
    list[str],
]:

    registry_doc = load_yaml(
        KEY_REGISTRY_PATH
    )

    errors: list[str] = []

    schema = load_json(
        SCHEMA_FILES[
            "verification-key-registry"
        ]
    )

    validator = (
        Draft202012Validator(
            schema,
            registry=SCHEMA_REGISTRY,
            format_checker=FormatChecker(),
        )
    )

    schema_errors_found = sorted(
        validator.iter_errors(
            registry_doc
        ),
        key=lambda error:
            list(error.path),
    )

    for error in schema_errors_found:

        where = ".".join(
            str(part)
            for part
            in error.path
        ) or "<root>"

        errors.append(
            "verification-key-registry "
            f"{where}: "
            f"{error.message}"
        )

    keys: dict[str, Any] = {}

    if not errors:

        for item in registry_doc[
            "keys"
        ]:

            key_id = item[
                "key_id"
            ]

            if key_id in keys:

                errors.append(
                    "duplicate verification "
                    f"key_id: {key_id}"
                )

            else:

                keys[
                    key_id
                ] = item

    return (
        keys,
        errors,
    )


def signature_errors(
    record: dict[str, Any],
    verification_keys:
        dict[str, Any],
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

        public_key = (
            Ed25519PublicKey
            .from_public_bytes(
                public_bytes
            )
        )

        signature_bytes = (
            b64url_decode(
                signature[
                    "value"
                ]
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


def semantic_errors(
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
        dict[str, Any],
) -> list[str]:

    errors = signature_errors(
        record,
        verification_keys,
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
                "does not match "
                "flow origin_id"
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
    )


def validate_directory(
    directory: Path,
    *,
    expect_failure: bool,
    context,
    verification_keys:
        dict[str, Any],
) -> bool:

    (
        traces,
        audits,
        flow_requests,
        flow_receipts,
    ) = context

    ok = True

    label = (
        "fail examples: failure expected"
        if expect_failure
        else "pass examples"
    )

    print(
        f"\n[{label}]"
    )

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

        print(
            f"- {path.relative_to(ROOT)} "
            f"[{kind}]"
        )

        s_errors = schema_errors(
            kind,
            record,
        )

        if s_errors:

            if expect_failure:

                print(
                    "  "
                    "[expected-schema-failure]"
                )

                for error in s_errors:

                    print(
                        f"    - {error}"
                    )

                continue

            ok = False

            for error in s_errors:

                print(
                    "  "
                    f"[schema-error] {error}"
                )

            continue

        print(
            "  [schema-ok]"
        )

        m_errors = semantic_errors(
            kind,
            record,
            traces=traces,
            audits=audits,
            flow_requests=flow_requests,
            flow_receipts=flow_receipts,
            verification_keys=
                verification_keys,
        )

        if m_errors:

            if expect_failure:

                print(
                    "  "
                    "[expected-semantic-failure]"
                )

                for error in m_errors:

                    print(
                        f"    - {error}"
                    )

                continue

            ok = False

            for error in m_errors:

                print(
                    "  "
                    f"[semantic-error] {error}"
                )

            continue

        if expect_failure:

            ok = False

            print(
                "  [unexpected-pass] "
                "fail fixture did not fail"
            )

        else:

            print(
                "  [semantic-ok]"
            )

    return ok


def main() -> int:

    print(
        "=== Royalty Flow Interface "
        "Protocol v0.3 Validation ==="
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

    pass_ok = validate_directory(
        PASS_DIR,
        expect_failure=False,
        context=context,
        verification_keys=
            verification_keys,
    )

    fail_ok = validate_directory(
        FAIL_DIR,
        expect_failure=True,
        context=context,
        verification_keys=
            verification_keys,
    )

    if (
        pass_ok
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
