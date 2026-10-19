#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Require independent validation artifacts from successful CI for the exact release commit."""
import argparse
import pathlib
import re
import subprocess
import tempfile

from script_support import read_json, strict_json, write_json_atomic
from validation_evidence import EVIDENCE_VERSION, valid_digest, validate_decoder, validate_native

REQUIRED = {
    'decode-oracle-evidence': 'decode-oracle.json',
    'native-isolated-evidence': 'native-isolated.json',
}
GH_API_TIMEOUT = 60
GH_DOWNLOAD_TIMEOUT = 300


def validate(report, commit, kind):
    if kind not in REQUIRED:
        raise ValueError(f'unknown evidence kind: {kind}')
    if not isinstance(report, dict):
        raise ValueError(f'{kind}: report must be an object')
    if type(report.get('schema_version')) is not int or report['schema_version'] != EVIDENCE_VERSION:
        raise ValueError(f'{kind}: unsupported evidence schema version')
    if report.get('status') != 'passed' or report.get('commit') != commit or report.get('dirty') is not False:
        raise ValueError(f'{kind}: missing successful clean exact-commit evidence')
    if report.get('error'):
        raise ValueError(f'{kind}: success report contains an execution error')
    version = report.get('binary_version')
    if (not isinstance(version, str) or not version.startswith('packetcraftr ')
            or not version[len('packetcraftr '):].strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in version)):
        raise ValueError(f'{kind}: missing unambiguous PacketcraftR version')
    if not valid_digest(report.get('binary_sha256')):
        raise ValueError(f'{kind}: missing binary digest')
    if kind == 'native-isolated-evidence':
        validate_native(report)
    else:
        validate_decoder(report)


def select_run(document, repository, commit):
    """Do not treat server-side query filters as release evidence themselves."""
    if not isinstance(document, dict) or not isinstance(document.get('workflow_runs'), list):
        raise ValueError('workflow lookup did not return an inventory')
    eligible = []
    seen = set()
    for run in document['workflow_runs']:
        if not isinstance(run, dict) or type(run.get('id')) is not int or run['id'] <= 0:
            raise ValueError('workflow lookup contains an invalid run identifier')
        if run['id'] in seen:
            raise ValueError('workflow lookup contains duplicate run identifiers')
        seen.add(run['id'])
        if (run.get('head_sha') != commit or run.get('event') != 'push'
                or run.get('status') != 'completed' or run.get('conclusion') != 'success'):
            continue
        url = f"https://github.com/{repository}/actions/runs/{run['id']}"
        if not isinstance(run.get('html_url'), str) or run['html_url'].lower() != url.lower():
            raise ValueError('workflow run URL disagrees with requested repository and run')
        eligible.append(run)
    if not eligible:
        raise ValueError('no successful push CI run for release commit')
    return max(eligible, key=lambda run: run['id'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True,
                        help='retain downloads from each attempt and publish VALIDATION-EVIDENCE.json on success')
    args = parser.parse_args(argv)
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository)
            or not re.fullmatch(r'[0-9a-f]{40}', args.commit)
            or any(part in ('.', '..') for part in args.repository.split('/'))):
        parser.error('expected owner/repository and a full commit SHA')
    aggregate = args.output / 'VALIDATION-EVIDENCE.json'
    try:
        # A failed retry must not leave a previous attempt's success marker behind.
        aggregate.unlink(missing_ok=True)
        document = strict_json(subprocess.check_output(
            ['gh', 'api', '--method', 'GET',
             f'repos/{args.repository}/actions/workflows/ci.yml/runs', '-f', f'head_sha={args.commit}',
             '-f', 'status=success', '-f', 'event=push', '-f', 'per_page=100'],
            timeout=GH_API_TIMEOUT))
        run = select_run(document, args.repository, args.commit)
        args.output.mkdir(parents=True, exist_ok=True)
        # A separate directory prevents falling back to stale downloaded reports.
        attempt = pathlib.Path(tempfile.mkdtemp(prefix=f'run-{run["id"]}-', dir=args.output))
        evidence = dict(commit=args.commit, ci_run=run['html_url'], reports={})
        for artifact, filename in REQUIRED.items():
            directory = attempt / artifact
            subprocess.run(['gh', 'run', 'download', str(run['id']), '--repo', args.repository,
                            '--name', artifact, '--dir', str(directory)],
                           check=True, timeout=GH_DOWNLOAD_TIMEOUT)
            report = read_json(directory / filename)
            validate(report, args.commit, artifact)
            evidence['reports'][artifact] = report
        write_json_atomic(aggregate, evidence)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'release evidence: {error}\n')
    print(evidence['ci_run'])


if __name__ == '__main__':
    main()
