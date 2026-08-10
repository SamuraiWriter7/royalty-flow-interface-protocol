#!/usr/bin/env python3
"""Validate RFIP v0.1 schemas and semantic invariants."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
PASS_DIR = ROOT / "examples" / "pass"
FAIL_DIR = ROOT / "examples" / "fail"
SUPPORT_DIR = ROOT / "examples" / "support"

SCHEMA_FILES = {
    "flow-request": SCHEMAS / "flow-request.schema.json",
    "flow-receipt": SCHEMAS / "flow-receipt.schema.json",
    "trace-record": SCHEMAS / "trace-record.schema.json",
    "audit-record": SCHEMAS / "audit-record.schema.json",
    "settlement-receipt": SCHEMAS / "settlement-receipt.schema.json",
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level YAML value must be an object")
    return data


def record_type_for(path: Path) -> str:
    name = path.name
    if (
        "flow-request" in name
        or "unsigned-flow" in name
        or "mismatched-origin-trace" in name
        or "unknown-trace" in name
        or "missing-origin" in name
    ):
        return "flow-request"

    if "flow-receipt" in name:
        return "flow-receipt"

    if "trace-record" in name:
        return "trace-record"

    if "audit-record" in name:
        return "audit-record"

    if "settlement" in name:
        return "settlement-receipt"

    raise ValueError(f"Cannot infer record type from filename: {path.name}")


def schema_errors(
    record_type: str,
    record: dict[str, Any],
) -> list[str]:
    schema = load_json(SCHEMA_FILES[record_type])

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    errors = sorted(
        validator.iter_errors(record),
        key=lambda e: list(e.path),
    )

    rendered: list[str] = []

    for error in errors:
        where = ".".join(str(p) for p in error.path) or "<root>"
        rendered.append(f"{where}: {error.message}")

    return rendered


def semantic_errors(
    record_type: str,
    record: dict[str, Any],
    *,
    traces: dict[str, dict[str, Any]],
    audits: dict[str, dict[str, Any]],
    flow_requests: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []

    if record_type == "flow-request":
        trace = traces.get(record["trace_id"])

        if trace is None:
            errors.append(
                "FI-002: referenced trace_id does not resolve"
            )

        elif trace["origin_id"] != record["origin_id"]:
            errors.append(
                "FI-003: trace origin_id does not match flow origin_id"
            )

    elif record_type == "flow-receipt":
        if record["flow_request_id"] not in flow_requests:
            errors.append(
                "flow_receipt references an unknown flow_request_id"
            )

    elif record_type == "trace-record":
        route = record["route"]

        origin_matches = [
            node
            for node in route
            if node["node_type"] == "origin"
            and node["node_id"] == record["origin_id"]
        ]

        if not origin_matches:
            errors.append(
                "trace route MUST contain its declared origin"
            )

    elif record_type == "audit-record":
        trace = traces.get(record["trace_id"])

        if trace is None:
            errors.append(
                "audit references an unknown trace_id"
            )

        elif trace["origin_id"] != record["origin_id"]:
            errors.append(
                "audit origin_id does not match trace origin_id"
            )

    elif record_type == "settlement-receipt":
        audit = audits.get(record["audit_id"])

        if audit is None:
            errors.append(
                "FI-004: settlement references an unknown audit_id"
            )

        else:
            if audit["decision"] != "passed":
                errors.append(
                    "FI-004: settlement MUST NOT complete "
                    "unless audit decision is passed"
                )

            for key in ("flow_id", "origin_id", "trace_id"):
                if audit[key] != record[key]:
                    errors.append(
                        f"settlement {key} does not match referenced audit"
                    )

        trace = traces.get(record["trace_id"])

        if trace is None:
            errors.append(
                "settlement references an unknown trace_id"
            )

        else:
            if trace["origin_id"] != record["origin_id"]:
                errors.append(
                    "settlement origin_id does not match trace origin_id"
                )

            trace_nodes = {
                (n["node_type"], n["node_id"])
                for n in trace["route"]
            }

            for item in record["distribution"]:
                if item["recipient_type"] == "custom":
                    continue

                key = (
                    item["recipient_type"],
                    item["recipient_id"],
                )

                if key not in trace_nodes:
                    errors.append(
                        "distribution recipient is not present "
                        "in the referenced trace: "
                        f"{item['recipient_type']}:"
                        f"{item['recipient_id']}"
                    )

        if (
            record["status"] == "settled"
            and not record.get("final_signature")
        ):
            errors.append(
                "FI-005: completed settlement "
                "MUST contain final_signature"
            )

    return errors


def build_context() -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    traces: dict[str, dict[str, Any]] = {}
    audits: dict[str, dict[str, Any]] = {}
    flow_requests: dict[str, dict[str, Any]] = {}

    for path in sorted(PASS_DIR.glob("*.yaml")):
        record = load_yaml(path)
        kind = record_type_for(path)

        if kind == "trace-record":
            traces[record["trace_id"]] = record

        elif kind == "audit-record":
            audits[record["audit_id"]] = record

        elif kind == "flow-request":
            flow_requests[record["flow_request_id"]] = record

    for path in sorted(SUPPORT_DIR.glob("*.yaml")):
        record = load_yaml(path)
        kind = record_type_for(path)

        if kind == "trace-record":
            traces[record["trace_id"]] = record

        elif kind == "audit-record":
            audits[record["audit_id"]] = record

        elif kind == "flow-request":
            flow_requests[record["flow_request_id"]] = record

    return traces, audits, flow_requests


def validate_pass_examples(
    traces: dict[str, dict[str, Any]],
    audits: dict[str, dict[str, Any]],
    flow_requests: dict[str, dict[str, Any]],
) -> bool:
    ok = True

    print("\n[pass examples]")

    for path in sorted(PASS_DIR.glob("*.yaml")):
        kind = record_type_for(path)
        record = load_yaml(path)

        print(
            f"- {path.relative_to(ROOT)} [{kind}]"
        )

        s_errors = schema_errors(kind, record)

        if s_errors:
            ok = False

            for err in s_errors:
                print(f"  [schema-error] {err}")

            continue

        print("  [schema-ok]")

        m_errors = semantic_errors(
            kind,
            record,
            traces=traces,
            audits=audits,
            flow_requests=flow_requests,
        )

        if m_errors:
            ok = False

            for err in m_errors:
                print(f"  [semantic-error] {err}")

        else:
            print("  [semantic-ok]")

    return ok


def validate_fail_examples(
    traces: dict[str, dict[str, Any]],
    audits: dict[str, dict[str, Any]],
    flow_requests: dict[str, dict[str, Any]],
) -> bool:
    ok = True

    print("\n[fail examples: failure expected]")

    for path in sorted(FAIL_DIR.glob("*.yaml")):
        kind = record_type_for(path)
        record = load_yaml(path)

        print(
            f"- {path.relative_to(ROOT)} [{kind}]"
        )

        s_errors = schema_errors(kind, record)

        if s_errors:
            print("  [expected-schema-failure]")

            for err in s_errors:
                print(f"    - {err}")

            continue

        m_errors = semantic_errors(
            kind,
            record,
            traces=traces,
            audits=audits,
            flow_requests=flow_requests,
        )

        if m_errors:
            print("  [expected-semantic-failure]")

            for err in m_errors:
                print(f"    - {err}")

            continue

        ok = False
        print(
            "  [unexpected-pass] fail fixture did not fail"
        )

    return ok


def main() -> int:
    print(
        "=== Royalty Flow Interface Protocol "
        "v0.1 Validation ==="
    )

    for name, path in SCHEMA_FILES.items():
        print(
            f"schema [{name}]: "
            f"{path.relative_to(ROOT)}"
        )

        Draft202012Validator.check_schema(
            load_json(path)
        )

    print("[schema-definitions-ok]")

    traces, audits, flow_requests = build_context()

    pass_ok = validate_pass_examples(
        traces,
        audits,
        flow_requests,
    )

    fail_ok = validate_fail_examples(
        traces,
        audits,
        flow_requests,
    )

    if pass_ok and fail_ok:
        print("\nValidation passed.")
        return 0

    print("\nValidation failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
