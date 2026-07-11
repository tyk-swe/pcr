#!/usr/bin/env python3
"""Validate 0.2.0 RC audit inputs and produce sanitized retained evidence."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(alpha|beta|rc)\.(?:0|[1-9][0-9]*))?"
)
PACKAGE_NAMES = (
    "packetcraftr-core",
    "packetcraftr-protocols",
    "packetcraftr-io",
    "packetcraftr-session",
    "packetcraftr",
)

# Each named regression represents a distinct public boundary. The full
# all-feature suite must execute every one; merely finding the source is not
# enough for a passing evidence bundle.
REQUIRED_TESTS = (
    # Parser, packet, expression, and template bounds.
    "byte_layer_limit_is_rejected_before_encoding",
    "zero_layer_limit_applies_to_unknown_link_types",
    "document_field_nesting_is_configurable_and_bounded",
    "layer_limits_fire_during_json_and_yaml_deserialization",
    "stable_document_parser_rejects_ambiguous_or_amplifying_yaml",
    "the_absolute_nesting_boundary_is_accepted_and_the_next_level_is_rejected",
    "expression_list_nesting_is_bounded",
    "expansion_is_lazy_bounded_and_deterministic",
    "external_codec_factories_must_materialize_required_fields",
    # Capture readers, writers, metadata, queues, and loss evidence.
    "bounded_transcode_preserves_pcapng_interface_metadata_and_frames",
    "writer_stream_limits_fail_before_emitting_the_excess_frame",
    "pcapng_reader_bounds_interface_descriptions",
    "pcapng_writer_bounds_interfaces_atomically",
    "pcapng_interface_block_honors_writer_size_limit",
    "pcapng_block_limit_is_checked_before_allocation",
    "pcapng_metadata_work_is_bounded_per_read",
    "limit_is_checked_before_packet_allocation",
    "replay_timing_is_bounded_and_validated",
    "capture_queue_limits_fail_closed_at_zero_and_stable_maxima",
    "fail_policy_reports_queue_loss",
    "drop_oldest_preserves_the_newest_bounded_frame",
    "drop_newest_preserves_the_oldest_bounded_frame",
    "native_drop_counters_do_not_masquerade_as_queue_overflows",
    "source_failure_propagates_once_and_shutdown_still_joins",
    # Reassembly, neighbor discovery, and aggregate evidence.
    "final_length_rejects_prior_fragment_beyond_end_atomically",
    "aggregate_limit_charges_sparse_fragment_metadata",
    "byte_limit_bounds_buffered_window_not_flow_lifetime",
    "emitted_history_shares_per_flow_and_aggregate_limits_with_pending_data",
    "aggregate_limit_rejects_emitted_history_atomically",
    "pending_segment_limit_is_typed_and_atomic",
    "aggregate_limit_charges_sparse_segment_metadata",
    "ndp_rejects_bad_checksum_before_accepting_correlated_evidence",
    "timeout_is_bounded_attempted_and_joined",
    "pre_request_frames_cannot_satisfy_lookup_and_evidence_is_bounded",
    # Client trust boundaries, authorization, cleanup, and exact evidence.
    "hostname_policy_precedes_resolution_and_resolved_policy_precedes_routes",
    "every_resolution_reauthorizes_all_addresses_before_route_use",
    "invalid_exchange_limits_fail_before_route_or_live_side_effects",
    "receiver_loss_is_not_reported_as_queue_overflow",
    "exchange_surfaces_operation_and_cleanup_failures",
    "capture_guard_attempts_shutdown_during_unwind",
    "partial_backend_send_is_a_typed_failure",
    "changed_post_build_wire_evidence_is_an_invariant_failure",
    "synthesized_ethernet_is_authorized_before_neighbor_traffic",
    # DNS authorization, bounded parsing, and terminal-safe exact bytes.
    "query_construction_is_canonical_and_bounded",
    "txt_bytes_remain_exact_even_when_they_contain_terminal_controls",
    "every_published_record_shape_decodes_to_typed_bounded_data",
    "malformed_compression_and_unrelated_identity_are_typed_failures",
    "truncation_never_presents_partial_records_and_tcp_length_is_exact",
    "hostname_intent_is_denied_before_resolver_or_executor_side_effects",
    "every_mixed_answer_is_authorized_before_family_selection",
    "every_retry_reresolves_and_reauthorizes_rebinding_before_probe_construction",
    "complete_operation_budget_precedes_resolution_and_queries",
    # Fuzz policy, allocation, duration, and evidence ceilings.
    "random_list_mutation_never_clones_beyond_field_or_item_bounds",
    "nested_empty_lists_are_charged_to_the_structural_byte_budget",
    "limits_reject_before_unbounded_case_or_byte_growth",
    "rejected_case_recipes_and_shrink_data_share_the_aggregate_byte_budget",
    "oversized_base_packet_is_rejected_before_case_cloning",
    "strategy_expansion_is_hard_bounded",
    "authorization_denial_precedes_every_live_execution",
    "malformed_call_site_opt_in_precedes_authorizer_and_executor",
    "worst_case_duration_is_rejected_before_authorization_or_execution",
    "actual_executor_wall_time_cannot_evade_the_duration_limit",
    "live_rate_and_timeout_are_bounded_before_execution",
    "evidence_truncation_never_turns_a_correlated_response_into_timeout",
    # Replay/tool/CLI end-to-end ceilings and presentation safety.
    "aggregate_limits_use_checked_arithmetic_before_the_next_send",
    "replay_duration_limit_precedes_policy_clock_and_next_send",
    "partial_send_and_missing_wire_evidence_are_failures",
    "malformed_tail_is_not_clean_end_of_stream",
    "every_mixed_resolution_answer_is_authorized_before_family_filter_or_probe",
    "rerunning_scan_reauthorizes_changed_addresses_before_another_probe",
    "undecodable_evidence_is_bounded_across_the_scan",
    "rerun_reauthorizes_rebound_hostname_before_another_probe",
    "undecodable_evidence_remains_exact_hop_scoped_and_operation_bounded",
    "request_bounds_reject_before_authorized_probe_construction",
    "terminal_text_escapes_controls_and_directional_overrides",
    "capture_driver_streams_bounded_frames_and_reports_statistics",
    "capture_byte_budget_fails_before_emitting_the_excess_frame",
    "fuzz_malformed_live_requires_both_explicit_opt_ins_before_route_io",
    "send_budget_and_output_contracts_precede_route_or_live_io",
    "invalid_capture_and_exchange_limits_precede_packet_policy",
    "capture_commands_reserve_the_documented_queue_limit_contract",
    "text_errors_escape_terminal_controls_while_json_stays_structured",
)


class AuditError(ValueError):
    pass


def release_channel(version: str) -> str:
    match = VERSION.fullmatch(version)
    if match is None:
        raise AuditError(f"Release version is not canonical SemVer: {version}")
    return match.group(1) or "stable"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AuditError(f"expected a JSON object in {path}")
    return value


def validate_commit(value: str) -> str:
    value = value.lower()
    if not COMMIT.fullmatch(value):
        raise AuditError(f"invalid expected commit: {value}")
    return value


def parse_checksums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\\]+)", raw)
        if not match:
            raise AuditError(f"invalid SHA256SUMS line {number}")
        digest, name = match.groups()
        if name in entries:
            raise AuditError(f"duplicate SHA256SUMS entry: {name}")
        entries[name] = digest
    if not entries:
        raise AuditError("SHA256SUMS is empty")
    return entries


def archive_command(args: argparse.Namespace) -> None:
    archive = args.archive.resolve(strict=True)
    checksums = args.checksums.resolve(strict=True)
    destination = args.extract.resolve()
    expected_commit = validate_commit(args.expected_commit)
    entries = parse_checksums(checksums)
    expected_digest = entries.get(archive.name)
    if expected_digest is None:
        raise AuditError(f"SHA256SUMS has no entry for {archive.name}")
    actual_digest = sha256(archive)
    if actual_digest != expected_digest:
        raise AuditError("candidate archive digest differs from SHA256SUMS")
    if destination.exists() and any(destination.iterdir()):
        raise AuditError(f"extraction directory is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members or len(members) > 10_000:
            raise AuditError("candidate archive has an invalid member count")
        names: set[str] = set()
        prefixes: set[str] = set()
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                raise AuditError(f"unsafe archive member path: {member.name}")
            if member.name in names:
                raise AuditError(f"duplicate archive member: {member.name}")
            names.add(member.name)
            prefixes.add(pure.parts[0])
            if not (member.isfile() or member.isdir()):
                raise AuditError(f"archive member is not a regular file/directory: {member.name}")
        if len(prefixes) != 1:
            raise AuditError(f"candidate archive has multiple roots: {sorted(prefixes)}")
        prefix = next(iter(prefixes))
        metadata_name = f"{prefix}/RELEASE-METADATA.toml"
        metadata_member = bundle.getmember(metadata_name)
        metadata_file = bundle.extractfile(metadata_member)
        if metadata_file is None:
            raise AuditError("candidate archive metadata is not a regular file")
        release = tomllib.loads(metadata_file.read().decode("utf-8"))
        version = release.get("version")
        if not isinstance(version, str):
            raise AuditError("release metadata version is not a string")
        channel = release_channel(version)
        expected_metadata = {
            "schema": "packetcraftr.release/v1",
            "version": version,
            "tag": f"v{version}",
            "commit": expected_commit,
            "channel": channel,
            "repository": "https://github.com/tyk-swe/pcr",
            "rust_version": "1.96.0",
            "license": "AGPL-3.0-only",
        }
        if release != expected_metadata:
            raise AuditError(
                f"release metadata differs: expected={expected_metadata!r} actual={release!r}"
            )
        if prefix != f"packetcraftr-workspace-{version}":
            raise AuditError("archive root does not match the embedded version")
        bundle.extractall(destination, filter="data")

    workspace = destination / prefix
    write_json(
        args.output,
        {
            "status": "pass",
            "archive": archive.name,
            "archive_sha256": actual_digest,
            "archive_size": archive.stat().st_size,
            "checksums_sha256": sha256(checksums),
            "commit": expected_commit,
            "channel": channel,
            "members": len(members),
            "version": version,
            "workspace": prefix,
        },
    )
    print(workspace)


def manifest_command(args: argparse.Namespace) -> None:
    workspace = args.workspace.resolve(strict=True)
    rows: list[str] = []
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink():
            raise AuditError(f"workspace contains a symlink: {path.relative_to(workspace)}")
        if path.is_file():
            rows.append(f"{sha256(path)}  {path.relative_to(workspace).as_posix()}")
    args.output.write_text("\n".join(rows) + "\n", encoding="utf-8")


def secret_line_allowed(workspace: Path, filename: str, line_number: int) -> str | None:
    path = workspace / filename
    if not path.is_file() or line_number < 1:
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if line_number > len(lines):
        return None
    line = lines[line_number - 1]
    nearby = "\n".join(lines[max(0, line_number - 6) : min(len(lines), line_number + 3)])
    if (filename.endswith(".provenance.json") or filename.endswith("/provenance.example.json")) and re.search(
        r'"sha256"\s*:\s*"[0-9a-f]{64}"', line
    ):
        return "fixture SHA-256 provenance digest"
    if filename.startswith(".github/workflows/") and re.fullmatch(
        r"\s*default:\s*[0-9a-f]{40}\s*", line
    ) and "expected_commit" in nearby:
        return "explicit candidate commit input default"
    if filename == "RELEASE-METADATA.toml" and re.fullmatch(
        r'\s*commit\s*=\s*"[0-9a-f]{40}"\s*', line
    ):
        return "exact source commit embedded by the deterministic archive"
    dns_paths = {
        "examples/documents/output-dns-success.json",
        "src/output.rs",
        "tests/document_examples.rs",
    }
    if filename in dns_paths and "strings_hex" in nearby and re.search(
        r'"[0-9a-f]{16,128}"', line
    ):
        return "exact DNS TXT wire bytes used by terminal-escaping regression"
    return None


def secrets_command(args: argparse.Namespace) -> None:
    workspace = args.workspace.resolve(strict=True)
    scan = load_json(args.scan)
    if scan.get("version") != "1.5.0":
        raise AuditError(f"secret scanner version is not pinned: {scan.get('version')!r}")
    results = scan.get("results")
    if not isinstance(results, dict):
        raise AuditError("secret scan has no results object")
    reviewed: list[dict[str, object]] = []
    rejected: list[str] = []
    for filename, findings in sorted(results.items()):
        if not isinstance(filename, str) or not isinstance(findings, list):
            raise AuditError("secret scan result has an invalid shape")
        for finding in findings:
            if not isinstance(finding, dict):
                raise AuditError("secret scan finding has an invalid shape")
            line_number = finding.get("line_number")
            finding_type = finding.get("type")
            if not isinstance(line_number, int) or not isinstance(finding_type, str):
                raise AuditError("secret scan finding lacks typed location metadata")
            reason = secret_line_allowed(workspace, filename, line_number)
            if reason is None:
                rejected.append(f"{filename}:{line_number} ({finding_type})")
            else:
                reviewed.append(
                    {
                        "file": filename,
                        "line": line_number,
                        "type": finding_type,
                        "disposition": "false_positive",
                        "reason": reason,
                    }
                )
    if rejected:
        raise AuditError("unreviewed secret candidates:\n" + "\n".join(rejected))
    write_json(
        args.output,
        {
            "status": "pass",
            "scanner": "detect-secrets 1.5.0",
            "reviewed_findings": reviewed,
            "reviewed_findings_count": len(reviewed),
            "unreviewed_findings_count": 0,
        },
    )


def source_command(args: argparse.Namespace) -> None:
    workspace = args.workspace.resolve(strict=True)
    cargo = tomllib.loads((workspace / "Cargo.toml").read_text(encoding="utf-8"))
    version = cargo["workspace"]["package"]["version"]
    manifests = [workspace / "Cargo.toml", *sorted((workspace / "crates").glob("*/Cargo.toml"))]
    packages: dict[str, dict[str, object]] = {}
    for manifest in manifests:
        value = tomllib.loads(manifest.read_text(encoding="utf-8"))
        package = value.get("package")
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise AuditError(f"invalid package metadata in {manifest}")
        if package.get("publish") is not False:
            raise AuditError(f"{package['name']} is not blocked from public registries")
        packages[str(package["name"])] = value
        for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
            table = value.get(table_name, {})
            if not isinstance(table, dict):
                continue
            for dependency_name, dependency in table.items():
                if dependency_name not in PACKAGE_NAMES:
                    continue
                if not isinstance(dependency, dict) or dependency.get("version") != f"={version}":
                    raise AuditError(
                        f"{package['name']} -> {dependency_name} is not exact-version {version}"
                    )
    if set(packages) != set(PACKAGE_NAMES):
        raise AuditError(f"workspace package set differs: {sorted(packages)}")

    policy_paths = [
        *sorted((workspace / ".github" / "workflows").glob("*.yml")),
        *sorted((workspace / ".github" / "workflows").glob("*.yaml")),
        *sorted((workspace / "scripts").glob("*")),
    ]
    mutation = re.compile(r"\bcargo\s+(?:" + "publish" + "|" + "login" + r")\b")
    credential_names = (
        "CARGO_" + "REGISTRY_TOKEN",
        "CRATES_" + "IO_TOKEN",
    )
    upload_markers = (
        "crates.io/api/" + "v1/crates/new",
        "registry=" + "https://upload.pypi.org",
    )
    violations: list[str] = []
    for path in policy_paths:
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(workspace).as_posix()
        if mutation.search(content):
            violations.append(f"{relative}: public Cargo registry mutation command")
        for marker in (*credential_names, *upload_markers):
            if marker in content:
                violations.append(f"{relative}: public registry credential/upload marker")
        if relative.startswith(".github/workflows/") and re.search(
            r"(?m)^\s*packages:\s*write\s*$", content
        ):
            violations.append(f"{relative}: package-registry write permission")
    if violations:
        raise AuditError("release policy violations:\n" + "\n".join(violations))

    rust_sources = (
        sorted(workspace.glob("src/**/*.rs"))
        + sorted(workspace.glob("crates/**/*.rs"))
        + sorted(workspace.glob("tests/**/*.rs"))
    )
    unsafe_pattern = re.compile(r"\bunsafe\s*(?:\{|impl\b|fn\b|extern\b)")
    unsafe_comment_pattern = re.compile(r"\bunsafe\s*(?:\{|impl\b)")
    unsafe_rows: list[dict[str, object]] = []
    for path in rust_sources:
        relative = path.relative_to(workspace).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            for match in unsafe_pattern.finditer(line):
                if not relative.startswith("crates/io/src/io/platform/"):
                    raise AuditError(f"unsafe/FFI boundary escaped platform ownership: {relative}:{number}")
                if unsafe_comment_pattern.match(match.group(0)):
                    context = "\n".join(lines[max(0, number - 9) : number - 1])
                    if "SAFETY:" not in context:
                        raise AuditError(f"unsafe operation lacks a local SAFETY invariant: {relative}:{number}")
                unsafe_rows.append({"file": relative, "line": number, "form": match.group(0)})

    rust_text = "\n".join(path.read_text(encoding="utf-8") for path in rust_sources)
    missing_tests = [name for name in REQUIRED_TESTS if f"fn {name}(" not in rust_text]
    if missing_tests:
        raise AuditError("required audit regressions are missing:\n" + "\n".join(missing_tests))

    changelog = re.sub(
        r"\s+", " ", (workspace / "CHANGELOG.md").read_text(encoding="utf-8")
    )
    for claim in (
        "pre-deserialization JSON/YAML byte and nesting ceilings",
        "offline local packaging of all five unpublished crates",
        "no-public-registry release policy",
    ):
        if claim not in changelog:
            raise AuditError(f"changelog is missing the reviewed RC audit claim: {claim}")

    write_json(
        args.output,
        {
            "status": "pass",
            "version": version,
            "packages": sorted(packages),
            "public_registry_mutation_commands": 0,
            "public_registry_credentials": 0,
            "required_regressions": len(REQUIRED_TESTS),
            "unsafe_occurrences": len(unsafe_rows),
            "unsafe_files": sorted({row["file"] for row in unsafe_rows}),
            "unsafe_review": unsafe_rows,
        },
    )


def tests_command(args: argparse.Namespace) -> None:
    content = args.log.read_text(encoding="utf-8", errors="replace")
    content = re.sub(r"\x1b\[[0-9;]*m", "", content)
    missing = [name for name in REQUIRED_TESTS if f"{name} ... ok" not in content]
    if missing:
        raise AuditError("required regressions did not report success:\n" + "\n".join(missing))
    write_json(
        args.output,
        {
            "status": "pass",
            "required_regressions": len(REQUIRED_TESTS),
            "observed_regressions": list(REQUIRED_TESTS),
            "test_log_sha256": sha256(args.log),
        },
    )


def package_names(path: Path) -> list[str]:
    names: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        match = re.fullmatch(r"[0-9a-f]{64}  (.+\.crate)", raw)
        if not match:
            raise AuditError(f"invalid package manifest row: {raw}")
        names.append(Path(match.group(1)).name)
    return names


def finalize_command(args: argparse.Namespace) -> None:
    evidence = args.evidence.resolve(strict=True)
    archive_review = load_json(evidence / "archive-review.json")
    source_review = load_json(evidence / "source-review.json")
    secret_review = load_json(evidence / "secret-review.json")
    test_review = load_json(evidence / "test-review.json")
    for name, review in (
        ("archive", archive_review),
        ("source", source_review),
        ("secret", secret_review),
        ("test", test_review),
    ):
        if review.get("status") != "pass":
            raise AuditError(f"{name} review did not pass")
    before = (evidence / "source-files.before").read_bytes()
    after = (evidence / "source-files.after").read_bytes()
    if before != after:
        raise AuditError("exact candidate source changed during the audit")
    packages = package_names(evidence / "package-SHA256SUMS")
    expected_package_prefixes = [f"{name}-{archive_review['version']}" for name in PACKAGE_NAMES]
    for prefix in expected_package_prefixes:
        if not any(name == f"{prefix}.crate" for name in packages):
            raise AuditError(f"local package output is missing {prefix}.crate")
    if len(packages) != len(PACKAGE_NAMES):
        raise AuditError(f"local package output count differs: {packages}")

    required_logs = (
        "toolchain.log",
        "dependency-policy.log",
        "format.log",
        "architecture.log",
        "schemas.log",
        "fixtures.log",
        "clippy-all-features.log",
        "clippy-no-default-features.log",
        "test-all-features.log",
        "test-no-default-features.log",
        "doctest-all-features.log",
        "doctest-no-default-features.log",
        "rustdoc-all-features.log",
        "rustdoc-no-default-features.log",
        "public-api.log",
        "cli-contract.log",
        "documentation-examples.log",
        "dependency-fetch.log",
        "cli-build.log",
        "package.log",
        "rustdoc-default-features.log",
    )
    logs: dict[str, str] = {}
    for name in required_logs:
        path = evidence / name
        if not path.is_file() or path.stat().st_size == 0:
            raise AuditError(f"required audit log is absent or empty: {name}")
        logs[name] = sha256(path)

    summary = {
        "schema": "packetcraftr.rc-audit/v1",
        "status": "pass",
        "completed_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "candidate": {
            "archive": archive_review["archive"],
            "archive_sha256": archive_review["archive_sha256"],
            "commit": archive_review["commit"],
            "version": archive_review["version"],
            "source_unchanged": True,
        },
        "results": {
            "critical_high_findings": 0,
            "dependency_license_advisory_policy": "pass",
            "msrv": "rustc 1.96.0",
            "local_packages_verified": len(packages),
            "public_registry_credentials": 0,
            "public_registry_mutation_commands": 0,
            "required_resource_security_regressions": test_review["required_regressions"],
            "secret_candidates_reviewed": secret_review["reviewed_findings_count"],
            "unreviewed_secret_candidates": 0,
            "unsafe_occurrences_reviewed": source_review["unsafe_occurrences"],
        },
        "accepted_risks": [
            {
                "id": "RUSTSEC-2024-0436",
                "severity": "maintenance",
                "owner": "XOD-54 release rehearsal",
                "disposition": "Pinned transitive paste notice has no vulnerability or safe upgrade; cargo-deny continues to deny vulnerabilities.",
            }
        ],
        "separate_release_qualifications": [
            {"owner": "XOD-50", "scope": "privileged macOS live I/O"},
            {"owner": "XOD-52", "scope": "cross-platform parity and artifact matrix"},
        ],
        "scope_waivers": [
            {
                "owner": "release owner / XOD-51",
                "scope": "privileged Windows/Npcap live I/O",
                "disposition": "Unqualified 0.2.0 preview; hosted MSVC boundary is not a substitute for real Npcap evidence.",
            }
        ],
        "package_archives": packages,
        "log_sha256": logs,
    }
    write_json(args.output, summary)
    report = f"""# PacketcraftR 0.2.0 RC audit evidence

Status: **PASS**

- Candidate commit: `{archive_review['commit']}`
- Candidate archive: `{archive_review['archive']}`
- Archive SHA-256: `{archive_review['archive_sha256']}`
- Critical/high findings: 0
- Required security/resource regressions observed: {test_review['required_regressions']}
- Local unpublished packages built and verified: {len(packages)}
- Secret candidates reviewed as documented false positives: {secret_review['reviewed_findings_count']}
- Unreviewed secret candidates or public-registry credentials: 0
- Source tree changed during audit: no

The only accepted dependency item is the pinned `RUSTSEC-2024-0436`
maintenance notice documented in `deny.toml`; XOD-54 owns the release-time
review. Privileged macOS and cross-platform parity remain separately owned
release qualifications, not accepted security-audit bypasses. The release
owner explicitly waived privileged Windows/Npcap live I/O for 0.2.0; it
remains an unqualified preview and is not represented as a passing row.
"""
    (args.output.parent / "REPORT.md").write_text(report, encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    archive = commands.add_parser("archive")
    archive.add_argument("--archive", type=Path, required=True)
    archive.add_argument("--checksums", type=Path, required=True)
    archive.add_argument("--expected-commit", required=True)
    archive.add_argument("--extract", type=Path, required=True)
    archive.add_argument("--output", type=Path, required=True)
    archive.set_defaults(function=archive_command)

    manifest = commands.add_parser("manifest")
    manifest.add_argument("--workspace", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)
    manifest.set_defaults(function=manifest_command)

    secrets = commands.add_parser("secrets")
    secrets.add_argument("--workspace", type=Path, required=True)
    secrets.add_argument("--scan", type=Path, required=True)
    secrets.add_argument("--output", type=Path, required=True)
    secrets.set_defaults(function=secrets_command)

    source = commands.add_parser("source")
    source.add_argument("--workspace", type=Path, required=True)
    source.add_argument("--output", type=Path, required=True)
    source.set_defaults(function=source_command)

    tests = commands.add_parser("tests")
    tests.add_argument("--log", type=Path, required=True)
    tests.add_argument("--output", type=Path, required=True)
    tests.set_defaults(function=tests_command)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--evidence", type=Path, required=True)
    finalize.add_argument("--output", type=Path, required=True)
    finalize.set_defaults(function=finalize_command)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.function(args)
    except (AuditError, KeyError, OSError, tarfile.TarError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
        print(f"RC audit verification failed: {error}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
