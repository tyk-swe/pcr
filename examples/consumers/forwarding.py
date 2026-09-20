#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded reference consumer for the v6 forwarding contract.

This validates the protocol and forwarding invariants it uses, not the complete
JSON Schema. Additive fields are accepted; unknown semantic enums are rejected.
An error envelope is an execution failure, not a forwarding verdict.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import BinaryIO, Any

SCHEMA = "packetcraftr.output/v6"
MAX_RECORD = 16 * 1024 * 1024
MAX_STREAM = 64 * 1024 * 1024
STATES = {"observed", "absent", "truncated", "decode_incomplete", "field_budget"}


class ContractError(ValueError):
    """The output cannot safely be interpreted by this consumer."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def integer(value: Any, name: str) -> int:
    require(type(value) is int and 0 <= value <= 2**64 - 1, f"invalid counter: {name}")
    return value


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ContractError(f"non-JSON numeric constant: {value}")


def decode(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ContractError(f"invalid JSON: {error}") from error
    require(isinstance(value, dict), "an envelope must be an object")
    require(value.get("schema") == SCHEMA, "unsupported schema; explicit migration required")
    require(value.get("command") == "verify-forwarding", "unexpected command")
    return value


def validate_check(check: dict[str, Any]) -> None:
    kind = check["check"]["kind"]
    outcome = check["outcome"]
    actual = check["actual_state"]
    expected = check["expected_state"]
    require(kind in {"preserve", "preserve_presence", "expect", "expect_absent"}, "unknown check kind")
    require(outcome in {"satisfied", "violated", "unevaluable"}, "unknown check outcome")
    require(actual in STATES and (expected is None or expected in STATES), "unknown evidence state")
    if outcome == "unevaluable":
        return
    if kind == "preserve":
        require(actual == expected == "observed", "value check without readable evidence")
        require(check.get("actual") is not None and check.get("expected") is not None,
                "value check with missing values")
        require((check["actual"] == check["expected"]) == (outcome == "satisfied"),
                "preservation outcome contradicts values")
    elif kind == "preserve_presence":
        require(actual in {"observed", "absent"} and expected in {"observed", "absent"},
                "presence check without complete decoder-view evidence")
        require((actual == expected) == (outcome == "satisfied"), "presence outcome contradicts states")
    elif kind == "expect":
        require(actual == "observed" and check.get("actual") is not None,
                "expectation without readable evidence")
    else:
        require(actual in {"observed", "absent"}, "absence check without complete decoder-view evidence")
        require((actual == "absent") == (outcome == "satisfied"), "absence outcome contradicts state")


def validate_report(report: dict[str, Any]) -> str:
    verdict = report["verdict"]
    require(verdict in {"pass", "fail", "inconclusive"}, "unknown verdict")
    rules = report["rules"]
    for name in ("identity", "preserve", "preserve_presence", "expect", "expect_absent", "warnings"):
        require(isinstance(rules[name], list), f"rules.{name} must be a list")
    require(bool(rules["identity"]), "empty identity")
    has_checks = any(rules[name] for name in ("preserve", "preserve_presence", "expect", "expect_absent"))
    require(rules["comparison"] == ("property_checks" if has_checks else "correspondence_only"),
            "comparison label does not describe the requested checks")
    summary = report["summary"]
    for name in ("unique_matches", "reordered_pairs", "ingress_only", "egress_only",
                 "ambiguous_groups", "ambiguous_observations", "checks_evaluated",
                 "checks_satisfied", "checks_violated", "checks_unevaluable"):
        integer(summary[name], name)
    require(summary["checks_evaluated"] == summary["checks_satisfied"] + summary["checks_violated"],
            "check counters do not sum")
    require(summary["reordered_pairs"] <= summary["unique_matches"], "invalid reorder count")
    incomplete = False
    ambiguous_by_side = []
    for side in ("ingress", "egress"):
        capture = report["captures"][side]
        for name in ("read", "selected", "keyed", "unkeyed", "incomplete"):
            integer(capture[name], f"{side}.{name}")
        require(capture["keyed"] + capture["unkeyed"] == capture["selected"] <= capture["read"],
                "capture counters do not sum")
        require(capture["incomplete"] <= capture["selected"], "invalid incomplete count")
        accounted = summary["unique_matches"] + summary[side + "_only"]
        require(accounted <= capture["keyed"], f"{side} matches and unmatched exceed capture census")
        ambiguous_by_side.append(capture["keyed"] - accounted)
        incomplete |= bool(capture["incomplete"] or capture["unkeyed"])
    require(sum(ambiguous_by_side) == summary["ambiguous_observations"],
            "ambiguous observations disagree with capture census")
    groups = summary["ambiguous_groups"]
    require((groups == 0) == (summary["ambiguous_observations"] == 0)
            and all(count >= groups for count in ambiguous_by_side)
            and summary["ambiguous_observations"] >= 3 * groups,
            "ambiguous group counts disagree with capture census")
    requested_checks = (
        summary["unique_matches"] * (len(rules["preserve"]) + len(rules["preserve_presence"]))
        + report["captures"]["egress"]["selected"] * (len(rules["expect"]) + len(rules["expect_absent"]))
    )
    require(summary["checks_evaluated"] + summary["checks_unevaluable"] == requested_checks,
            "requested checks were not all evaluated or classified")
    expected_verdict = (
        "fail" if summary["checks_violated"] else
        "pass" if summary["unique_matches"] and not incomplete and not any(
            summary[name] for name in ("ingress_only", "egress_only", "ambiguous_groups", "checks_unevaluable")
        ) else "inconclusive"
    )
    require(verdict == expected_verdict, "verdict contradicts summary")
    for name, total in (("matches", "unique_matches"), ("violations", "checks_violated"),
                        ("ambiguous", "ambiguous_groups")):
        omitted_name = "ambiguous_groups" if name == "ambiguous" else name
        omitted = integer(report["omitted"][omitted_name], omitted_name)
        require(len(report[name]) + omitted == summary[total], f"{name} omission count does not sum")
    retained_outcomes = {"satisfied": 0, "violated": 0, "unevaluable": 0}
    for pair in report["matches"]:
        for check in pair["checks"]:
            validate_check(check)
            retained_outcomes[check["outcome"]] += 1
    for outcome, count in retained_outcomes.items():
        require(count <= summary["checks_" + outcome], "retained checks exceed summary")
    return verdict


def consume(source: BinaryIO, output_format: str, exit_code: int) -> dict[str, Any]:
    """Return execution/domain status, or reject an incomplete/contradictory stream."""
    try:
        if output_format == "json":
            data = source.read(MAX_RECORD + 1)
            require(len(data) <= MAX_RECORD, "aggregate output too large")
            terminal = decode(data)
            require(terminal.get("mode") == "aggregate", "expected aggregate envelope")
        elif output_format == "ndjson":
            terminal = None
            sequence = 0
            total = 0
            while True:
                line = source.readline(MAX_RECORD + 1)
                if not line:
                    break
                total += len(line)
                require(total <= MAX_STREAM and len(line) <= MAX_RECORD, "stream limit exceeded")
                require(line.endswith(b"\n"), "truncated NDJSON record")
                require(terminal is None, "record after terminal event")
                record = decode(line)
                require(record.get("mode") == "stream", "expected stream envelope")
                require(type(record.get("sequence")) is int and record["sequence"] == sequence,
                        "non-contiguous stream sequence")
                sequence += 1
                event = record.get("event")
                require(event in {"event", "complete", "error"}, "unknown stream event")
                if event in {"complete", "error"}:
                    terminal = record
            require(terminal is not None, "missing terminal event")
        else:
            raise ContractError("format must be json or ndjson")
        status = terminal["status"]
        require(status in {"success", "error"}, "unknown execution status")
        if output_format == "ndjson":
            require(terminal["event"] == ("complete" if status == "success" else "error"),
                    "terminal event and status disagree")
        if status == "error":
            require(exit_code != 0, "error envelope with successful process exit")
            require(isinstance(terminal.get("error"), dict), "missing error object")
            return {"execution": "error", "error": terminal["error"], "verdict": None}
        verdict = validate_report(terminal["result"])
        require(exit_code == (0 if verdict == "pass" else 1), "exit code disagrees with domain verdict")
        return {"execution": "complete", "verdict": verdict, "report": terminal["result"]}
    except (KeyError, TypeError, AttributeError) as error:
        raise ContractError(f"missing or malformed contract member: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("json", "ndjson"), default="ndjson")
    parser.add_argument("--exit-code", type=int, required=True, help="exit code of PacketcraftR, not the pipe")
    args = parser.parse_args()
    try:
        result = consume(sys.stdin.buffer, args.format, args.exit_code)
    except ContractError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["execution"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
