#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Write or verify packaged binary identity using release-supplied metadata."""
import argparse
import json
import pathlib
import subprocess

from validation_evidence import digest

COMMAND_TIMEOUT = 30
REQUIRED_FIELDS = ('binary', 'binary_sha256', 'version')


def load_manifest(path):
    """Decode a BUILD-METADATA.json document or exit with a useful diagnostic."""
    try:
        text = path.read_text(encoding='utf-8')
    except OSError as error:
        raise SystemExit(f'cannot read {path}: {error}')
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise SystemExit(f'{path} is not valid JSON: {error}')
    if not isinstance(document, dict):
        raise SystemExit(f'{path} must contain a JSON object')
    for field in REQUIRED_FIELDS:
        if field not in document:
            raise SystemExit(f'{path} is missing required field {field}')
        if not isinstance(document[field], str):
            raise SystemExit(f'{path} field {field} must be a string')
    return document


def write_manifest(args, binary_digest):
    document = dict(commit=args.commit, target=args.target, feature_variant=args.variant,
                    rustc=subprocess.check_output(['rustc', '--version', '--verbose'], text=True,
                                                  timeout=COMMAND_TIMEOUT).strip(),
                    version=subprocess.check_output([args.binary, '--version'], text=True,
                                                    timeout=COMMAND_TIMEOUT).strip(),
                    binary=args.binary.name, binary_sha256=binary_digest)
    args.output.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')


def verify_manifest(args, binary_digest):
    document = load_manifest(args.verify)
    for field, expected in (('commit', args.commit), ('target', args.target),
                            ('feature_variant', args.variant)):
        if expected is not None and document.get(field) != expected:
            raise SystemExit(f'packaged {field} does not match release metadata')
    if document['binary_sha256'] != binary_digest or document['binary'] != args.binary.name:
        raise SystemExit('packaged binary does not match BUILD-METADATA.json')
    version = subprocess.check_output([args.binary, '--version'], text=True,
                                      timeout=COMMAND_TIMEOUT).strip()
    if document['version'] != version:
        raise SystemExit('packaged version does not match BUILD-METADATA.json')


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--output', type=pathlib.Path)
    modes.add_argument('--verify', type=pathlib.Path)
    parser.add_argument('--commit')
    parser.add_argument('--target')
    parser.add_argument('--variant')
    return parser


def main(argv=None):
    parser = arguments()
    args = parser.parse_args(argv)
    try:
        binary_digest = digest(args.binary)
    except OSError as error:
        raise SystemExit(f'cannot read binary {args.binary}: {error}')
    if args.verify is not None:
        verify_manifest(args, binary_digest)
        return
    if not all([args.output, args.commit, args.target, args.variant]):
        parser.error('writing requires --output, --commit, --target and --variant')
    write_manifest(args, binary_digest)


if __name__ == '__main__':
    main()
