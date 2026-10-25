#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Write or verify packaged binary identity using release-supplied metadata."""
import argparse
from collections.abc import Sequence
import pathlib
import re
import subprocess
from subprocess import SubprocessError

from script_support import digest, portable_basename, prepare_report, read_json, valid_digest, write_json_atomic

COMMAND_TIMEOUT = 30
REQUIRED_FIELDS = ('binary', 'binary_sha256', 'version', 'commit', 'target',
                   'feature_variant', 'rustc')
MAX_MANIFEST_BYTES = 64 * 1024


def validate_identity(document):
    """Reject missing provenance instead of treating a digest alone as identity."""
    if not isinstance(document, dict):
        raise ValueError('manifest must contain a JSON object')
    for field in REQUIRED_FIELDS:
        if not isinstance(document.get(field), str) or not document[field].strip():
            raise ValueError(f'manifest field {field} must be a nonempty string')
    if not valid_digest(document['binary_sha256']):
        raise ValueError('manifest binary_sha256 must be a lowercase SHA-256 digest')
    if not valid_digest(document['commit'], 40):
        raise ValueError('manifest commit must be a full lowercase Git SHA')
    for field in ('target', 'feature_variant'):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', document[field]):
            raise ValueError(f'manifest {field} must be a portable identifier')
    if not portable_basename(document['binary']):
        raise ValueError('manifest binary must be a portable basename')
    if (not document['version'].startswith('packetcraftr ')
            or not document['version'][len('packetcraftr '):].strip()
            or len(document['version'].splitlines()) != 1
            or any(ord(character) < 32 or ord(character) == 127 for character in document['version'])):
        raise ValueError('manifest version must be one PacketcraftR version line')
    if not document['rustc'].startswith('rustc ') or not document['rustc'][len('rustc '):].strip():
        raise ValueError('manifest lacks Rust compiler identity')
    if any((ord(character) < 32 and character not in '\t\r\n')
           or 127 <= ord(character) <= 159 for character in document['rustc']):
        raise ValueError('manifest Rust compiler identity contains control characters')


def load_manifest(path):
    """Decode and validate a bounded BUILD-METADATA.json document."""
    try:
        document = read_json(path, max_bytes=MAX_MANIFEST_BYTES)
        validate_identity(document)
        return document
    except (OSError, ValueError) as error:
        raise SystemExit(f'cannot load build metadata {path}: {error}') from error


def binary_version(binary: pathlib.Path, binary_digest: str) -> str:
    version = subprocess.check_output([str(binary), '-V'], text=True,
                                      encoding='utf-8', timeout=COMMAND_TIMEOUT).strip()
    if digest(binary) != binary_digest:
        raise ValueError('binary changed while reading its version')
    return version


def write_manifest(args, binary_digest):
    document = dict(commit=args.commit, target=args.target, feature_variant=args.variant,
                    rustc=subprocess.check_output(['rustc', '--version', '--verbose'], text=True,
                                                  encoding='utf-8', timeout=COMMAND_TIMEOUT).strip(),
                    version=binary_version(args.binary, binary_digest),
                    binary=args.binary.name, binary_sha256=binary_digest)
    validate_identity(document)
    write_json_atomic(args.output, document)


def verify_manifest(args, binary_digest):
    document = load_manifest(args.verify)
    for field, expected in (('commit', args.commit), ('target', args.target),
                            ('feature_variant', args.variant)):
        if expected is not None and document.get(field) != expected:
            raise SystemExit(f'packaged {field} does not match release metadata')
    if document['binary_sha256'] != binary_digest or document['binary'] != args.binary.name:
        raise SystemExit('packaged binary does not match BUILD-METADATA.json')
    if document['version'] != binary_version(args.binary, binary_digest):
        raise SystemExit('packaged version does not match BUILD-METADATA.json')


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--output', type=pathlib.Path)
    modes.add_argument('--verify', type=pathlib.Path)
    parser.add_argument('--commit')
    parser.add_argument('--target')
    parser.add_argument('--variant')
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = arguments()
    args = parser.parse_args(argv)
    # Preserve the supplied basename, but never search PATH for the hashed file.
    args.binary = args.binary.absolute()
    if args.output is not None and not all([args.commit, args.target, args.variant]):
        parser.error('writing requires --commit, --target and --variant')
    if args.commit is not None and not valid_digest(args.commit, 40):
        parser.error('--commit must be a full lowercase Git SHA')
    for name in ('target', 'variant'):
        value = getattr(args, name)
        if value is not None and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', value):
            parser.error(f'--{name} must be a portable identifier')
    try:
        if args.output is not None:
            prepare_report(args.output, args.binary)
        if not args.binary.is_file():
            raise ValueError(f'binary is not a regular file: {args.binary}')
        binary_digest = digest(args.binary)
        if args.verify is not None:
            verify_manifest(args, binary_digest)
        else:
            write_manifest(args, binary_digest)
    except (OSError, ValueError, SubprocessError) as error:
        parser.exit(1, f'build metadata failed: {error}\n')


if __name__ == '__main__':
    main()
