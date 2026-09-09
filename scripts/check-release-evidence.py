#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Require independent validation artifacts from successful CI for the exact release commit."""
import argparse
import json
import pathlib
import re
import subprocess

REQUIRED = {
    'decode-oracle-evidence': 'decode-oracle.json',
    'native-isolated-evidence': 'native-isolated.json',
}
NATIVE = {'loopback_exchange', 'readiness_and_repeated_cleanup', 'idle_deadline_and_cancellation',
          'bounded_queue_reports_real_capture_loss', 'native_filter_error_preserves_diagnostic_and_releases_admission',
          'interface_disappearance_reports_driver_failure_and_cleans_up'}


def validate(report, commit, kind):
    if report.get('status') != 'passed' or report.get('commit') != commit or report.get('dirty') is not False:
        raise ValueError(f'{kind}: missing successful clean exact-commit evidence')
    if not re.fullmatch(r'[0-9a-f]{64}', report.get('binary_sha256', '')):
        raise ValueError(f'{kind}: missing binary digest')
    if kind == 'native-isolated-evidence':
        scenarios = report.get('scenarios', [])
        if {item['name'] for item in scenarios} != NATIVE or any(item['status'] != 'passed' for item in scenarios):
            raise ValueError('native evidence omits or skips required scenarios')
        if report.get('namespace') == report.get('parent_namespace') or not report.get('namespace'):
            raise ValueError('native evidence lacks namespace isolation')
    if kind == 'decode-oracle-evidence':
        if report.get('expected_tshark') != '4.6.4' or not report.get('captures') or report.get('mismatches'):
            raise ValueError('decoder evidence is incomplete')
        if any(item.get('status') != 'passed' for item in report['captures']):
            raise ValueError('decoder capture failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', args.repository) or not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        parser.error('expected owner/repository and a full commit SHA')
    runs = json.loads(subprocess.check_output(['gh', 'api', '--method', 'GET',
        f'repos/{args.repository}/actions/workflows/ci.yml/runs', '-f', f'head_sha={args.commit}',
        '-f', 'status=success', '-f', 'event=push', '-f', 'per_page=100']))['workflow_runs']
    if not runs:
        raise SystemExit('no successful push CI run for release commit')
    run = max(runs, key=lambda row: row['id'])
    args.output.mkdir(parents=True, exist_ok=True)
    evidence = dict(commit=args.commit, ci_run=run['html_url'], reports={})
    for artifact, filename in REQUIRED.items():
        directory = args.output / artifact
        subprocess.run(['gh', 'run', 'download', str(run['id']), '--repo', args.repository,
                        '--name', artifact, '--dir', str(directory)], check=True)
        report = json.loads((directory / filename).read_text())
        validate(report, args.commit, artifact)
        evidence['reports'][artifact] = report
    (args.output / 'VALIDATION-EVIDENCE.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(evidence['ci_run'])


if __name__ == '__main__':
    main()
