# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Structured CLI invocation and independent output-schema validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from .context import CaseContext

_VALIDATORS: dict[Path, Any] = {}


def invoke_json(
    context: CaseContext,
    command: str,
    arguments: Sequence[str],
    *,
    expected_exit: int = 0,
    expected_status: str = "success",
    timeout: float = 10.0,
) -> dict[str, Any]:
    completed = context.run_packetcraftr(
        ("--output", "json", command, *arguments),
        timeout=timeout,
    )
    if completed.returncode != expected_exit:
        raise AssertionError(
            f"{command} exited {completed.returncode}, expected {expected_exit}\n"
            f"{context.invocations[-1].render()}"
        )
    if completed.stderr:
        raise AssertionError(
            f"{command} emitted stderr for JSON output\n"
            f"{context.invocations[-1].render()}"
        )
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"{command} emitted invalid JSON: {error}\n"
            f"{context.invocations[-1].render()}"
        ) from error
    if not isinstance(document, dict):
        raise AssertionError(f"{command} JSON output was not an object: {document!r}")
    validate_output_schema(context.native_e2e_root, document)
    expected = {
        "schema": "packetcraftr.output/v1",
        "command": command,
        "mode": "aggregate",
        "status": expected_status,
    }
    actual = {key: document.get(key) for key in expected}
    if actual != expected:
        raise AssertionError(
            f"{command} envelope {actual!r} did not equal {expected!r}"
        )
    return document


def validate_output_schema(
    native_e2e_root: Path,
    document: dict[str, Any],
) -> None:
    schema_path = (
        native_e2e_root.parent.parent
        / "schemas"
        / "packetcraftr.output.v1.schema.json"
    ).resolve()
    validator = _VALIDATORS.get(schema_path)
    if validator is None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError as error:
            raise RuntimeError(
                "Python jsonschema with Draft 2020-12 support is required"
            ) from error
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        _VALIDATORS[schema_path] = validator
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        details = "\n".join(
            f"- {list(error.absolute_path)!r}: {error.message}" for error in errors
        )
        raise AssertionError(
            f"output did not validate against {schema_path.name}:\n{details}"
        )


def packet_field(
    decoded_frame: dict[str, Any],
    protocol: str,
    field: str,
) -> Any:
    packet = decoded_frame.get("packet")
    if not isinstance(packet, dict):
        raise AssertionError(f"decoded frame omitted packet document: {decoded_frame!r}")
    layers = packet.get("layers")
    if not isinstance(layers, list):
        raise AssertionError(f"decoded packet omitted layers: {packet!r}")
    for layer in layers:
        if not isinstance(layer, dict) or layer.get("protocol") != protocol:
            continue
        fields = layer.get("fields")
        if not isinstance(fields, dict) or field not in fields:
            raise AssertionError(f"{protocol} layer omitted {field}: {layer!r}")
        value = fields[field]
        if not isinstance(value, dict) or "value" not in value:
            raise AssertionError(
                f"{protocol}.{field} was not a typed field value: {value!r}"
            )
        return value["value"]
    raise AssertionError(f"decoded packet omitted protocol {protocol!r}")
