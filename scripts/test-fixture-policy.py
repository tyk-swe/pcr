#!/usr/bin/env python3
"""Regression tests for the fixture provenance and Git range policy."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1]
ZERO_SHA = "0" * 40


def run(
    arguments: list[str],
    cwd: Path,
    *,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"{' '.join(arguments)} failed:\n{result.stdout}")
    return result


def write(path: Path, content: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def provenance(relative: str, content: bytes, *, sha256: str | None = None) -> dict:
    return {
        "schema": "packetcraftr.fixture-provenance/v1",
        "fixture": relative,
        "sha256": sha256 or hashlib.sha256(content).hexdigest(),
        "kind": "document",
        "authority": "derived",
        "created_utc": "2026-07-10T00:00:00Z",
        "protocols": ["raw"],
        "capture": None,
        "source": {
            "type": "derived",
            "description": "Temporary policy regression fixture",
            "reference": "https://example.invalid/fixture-policy",
            "generator": {
                "name": "test-fixture-policy.py",
                "version": "1",
                "invocation": "create temporary fixture",
            },
            "oracle": None,
        },
        "license": {
            "spdx": "CC0-1.0",
            "evidence": "Created in an ephemeral policy-test repository",
        },
        "expected": {
            "link_type": None,
            "layers": ["raw"],
            "diagnostic_codes": [],
            "exact_rebuild": None,
            "valid": True,
            "notes": "Only the provenance policy is under test",
        },
        "review": {
            "reviewer": "fixture-policy regression",
            "reviewed_utc": "2026-07-10T00:00:00Z",
            "evidence": "https://linear.app/xodud/issue/XOD-60",
        },
    }


def write_fixture(repo: Path, relative: str, content: bytes, *, sidecar: bool = True) -> None:
    fixture = repo / "tests/fixtures" / relative
    write(fixture, content)
    if sidecar:
        document = provenance(relative, content)
        write(
            Path(f"{fixture}.provenance.json"),
            json.dumps(document, indent=2, sort_keys=True) + "\n",
        )


def commit(repo: Path, message: str) -> str:
    run(["git", "add", "."], repo)
    run(["git", "commit", "-m", message], repo)
    return run(["git", "rev-parse", "HEAD"], repo).stdout.strip()


def repository() -> tuple[tempfile.TemporaryDirectory[str], Path, str]:
    temporary = tempfile.TemporaryDirectory(prefix="packetcraftr-fixture-policy-")
    repo = Path(temporary.name)
    (repo / "scripts").mkdir()
    shutil.copy2(SOURCE_ROOT / "scripts/check-fixture-changes.sh", repo / "scripts")
    shutil.copy2(SOURCE_ROOT / "scripts/validate-fixture-corpus.py", repo / "scripts")
    write(repo / "tests/fixtures/README.md", "temporary fixture policy repository\n")
    run(["git", "init", "--initial-branch=main"], repo)
    run(["git", "config", "user.name", "Fixture Policy"], repo)
    run(["git", "config", "user.email", "fixture-policy@example.invalid"], repo)
    base = commit(repo, "initial policy")
    return temporary, repo, base


def policy(repo: Path, base: str, *, before: str | None = None) -> subprocess.CompletedProcess[str]:
    head = run(["git", "rev-parse", "HEAD"], repo).stdout.strip()
    environment = os.environ.copy()
    environment.update(
        {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_BEFORE_SHA": before if before is not None else base,
            "GITHUB_BASE_SHA": "",
            "GITHUB_SHA": head,
            "GITHUB_DEFAULT_BRANCH": "main",
        }
    )
    return run(["bash", "scripts/check-fixture-changes.sh"], repo, env=environment, check=False)


def require_failure(result: subprocess.CompletedProcess[str], phrase: str) -> None:
    if result.returncode == 0 or phrase not in result.stdout:
        raise AssertionError(
            f"expected failure containing {phrase!r}, got {result.returncode}:\n{result.stdout}"
        )


def valid_sidecar_passes() -> None:
    temporary, repo, base = repository()
    with temporary:
        write_fixture(repo, "documents/valid.json", b'{"value":1}\n')
        commit(repo, "add valid fixture")
        result = policy(repo, base)
        if result.returncode != 0:
            raise AssertionError(result.stdout)


def missing_sidecar_fails() -> None:
    temporary, repo, base = repository()
    with temporary:
        write_fixture(repo, "documents/missing.json", b"{}\n", sidecar=False)
        commit(repo, "add unsidecarred fixture")
        require_failure(policy(repo, base), "missing provenance sidecar")


def malformed_sidecar_fails() -> None:
    temporary, repo, base = repository()
    with temporary:
        fixture = repo / "tests/fixtures/documents/malformed.json"
        write(fixture, "{}\n")
        write(Path(f"{fixture}.provenance.json"), "{not json}\n")
        commit(repo, "add malformed provenance")
        require_failure(policy(repo, base), "invalid provenance JSON")


def schema_invalid_type_fails_cleanly() -> None:
    temporary, repo, base = repository()
    with temporary:
        content = b"{}\n"
        fixture = repo / "tests/fixtures/documents/type.json"
        write(fixture, content)
        document = provenance("documents/type.json", content)
        document["kind"] = []
        write(Path(f"{fixture}.provenance.json"), json.dumps(document) + "\n")
        commit(repo, "add schema-invalid provenance type")
        result = policy(repo, base)
        require_failure(result, "kind must be one of")
        if "Traceback" in result.stdout:
            raise AssertionError(f"validator raised an uncontrolled exception:\n{result.stdout}")


def hash_mismatch_fails() -> None:
    temporary, repo, base = repository()
    with temporary:
        content = b"{}\n"
        fixture = repo / "tests/fixtures/documents/hash.json"
        write(fixture, content)
        document = provenance("documents/hash.json", content, sha256="0" * 64)
        write(Path(f"{fixture}.provenance.json"), json.dumps(document) + "\n")
        commit(repo, "add mismatched hash")
        require_failure(policy(repo, base), "sha256 mismatch")


def declared_path_mismatch_fails() -> None:
    temporary, repo, base = repository()
    with temporary:
        content = b"{}\n"
        fixture = repo / "tests/fixtures/documents/path.json"
        write(fixture, content)
        document = provenance("documents/other.json", content)
        write(Path(f"{fixture}.provenance.json"), json.dumps(document) + "\n")
        commit(repo, "add mismatched fixture path")
        require_failure(policy(repo, base), "does not match sidecar path")


def required_review_metadata_fails() -> None:
    temporary, repo, base = repository()
    with temporary:
        content = b"{}\n"
        fixture = repo / "tests/fixtures/documents/review.json"
        write(fixture, content)
        document = provenance("documents/review.json", content)
        del document["review"]["evidence"]
        write(Path(f"{fixture}.provenance.json"), json.dumps(document) + "\n")
        commit(repo, "omit required review evidence")
        require_failure(policy(repo, base), "review is missing fields")


def stale_sidecar_fails() -> None:
    temporary, repo, _ = repository()
    with temporary:
        write_fixture(repo, "documents/stale.json", b'{"value":1}\n')
        base = commit(repo, "add fixture")
        write(repo / "tests/fixtures/documents/stale.json", '{"value":2}\n')
        commit(repo, "mutate fixture only")
        require_failure(policy(repo, base), "sha256 mismatch")


def fixture_deletion_requires_sidecar_deletion() -> None:
    temporary, repo, _ = repository()
    with temporary:
        write_fixture(repo, "documents/deleted.json", b"{}\n")
        base = commit(repo, "add fixture")
        (repo / "tests/fixtures/documents/deleted.json").unlink()
        commit(repo, "delete fixture only")
        require_failure(policy(repo, base), "referenced fixture does not exist")


def yaml_is_not_exempt() -> None:
    temporary, repo, base = repository()
    with temporary:
        write_fixture(repo, "documents/missing.yaml", b"schema: test\n", sidecar=False)
        commit(repo, "add unsidecarred YAML")
        require_failure(policy(repo, base), "missing provenance sidecar")


def full_push_range_is_used() -> None:
    temporary, repo, base = repository()
    with temporary:
        write_fixture(repo, "documents/range.json", b"{}\n")
        commit(repo, "first commit changes fixture")
        write(repo / "tests/fixtures/README.md", "second commit in the same push\n")
        head = commit(repo, "second commit changes documentation")
        result = policy(repo, base)
        if result.returncode != 0 or f"{base}..{head}" not in result.stdout:
            raise AssertionError(f"full range was not used:\n{result.stdout}")


def unavailable_push_base_fails_closed() -> None:
    temporary, repo, _ = repository()
    with temporary:
        result = policy(repo, ZERO_SHA, before="1" * 40)
        require_failure(result, "push before")


def main() -> int:
    cases = [
        valid_sidecar_passes,
        missing_sidecar_fails,
        malformed_sidecar_fails,
        schema_invalid_type_fails_cleanly,
        hash_mismatch_fails,
        declared_path_mismatch_fails,
        required_review_metadata_fails,
        stale_sidecar_fails,
        fixture_deletion_requires_sidecar_deletion,
        yaml_is_not_exempt,
        full_push_range_is_used,
        unavailable_push_base_fails_closed,
    ]
    for case in cases:
        case()
        print(f"ok: {case.__name__}")
    print(f"fixture policy regressions passed ({len(cases)}/{len(cases)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
