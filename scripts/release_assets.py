# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared release inventory for packaging and extracted-archive validation."""
import json
from pathlib import Path

MANIFEST = json.loads(Path(__file__).with_name('release-assets.json').read_text(encoding='utf-8'))
if MANIFEST['schema'] != 'packetcraftr.release-assets/v1':
    raise ValueError('unsupported release asset manifest')
SOURCE_ASSETS = tuple(MANIFEST['source_assets'])
GENERATED_ASSETS = tuple(MANIFEST['generated_assets'])
