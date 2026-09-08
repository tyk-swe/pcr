#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Write or verify packaged binary identity using release-supplied metadata."""
import argparse
import hashlib
import json
import pathlib
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=pathlib.Path, required=True)
parser.add_argument('--output', type=pathlib.Path)
parser.add_argument('--verify', type=pathlib.Path)
parser.add_argument('--commit')
parser.add_argument('--target')
parser.add_argument('--variant')
args = parser.parse_args()
digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
if args.verify:
    document = json.loads(args.verify.read_text())
    for field, expected in (('commit', args.commit), ('target', args.target),
                            ('feature_variant', args.variant)):
        if expected is not None and document.get(field) != expected:
            raise SystemExit(f'packaged {field} does not match release metadata')
    if document['binary_sha256'] != digest or document['binary'] != args.binary.name:
        raise SystemExit('packaged binary does not match BUILD-METADATA.json')
    if document['version'] != subprocess.check_output([args.binary, '--version'], text=True, timeout=30).strip():
        raise SystemExit('packaged version does not match BUILD-METADATA.json')
else:
    if not all([args.output, args.commit, args.target, args.variant]):
        parser.error('writing requires --output, --commit, --target and --variant')
    document = dict(commit=args.commit, target=args.target, feature_variant=args.variant,
                    rustc=subprocess.check_output(['rustc', '--version', '--verbose'], text=True, timeout=30).strip(),
                    version=subprocess.check_output([args.binary, '--version'], text=True, timeout=30).strip(),
                    binary=args.binary.name, binary_sha256=digest)
    args.output.write_text(json.dumps(document, indent=2) + '\n')
