#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Compile an independent, pcap-free public API consumer outside the workspace.

Run after the workspace has populated Cargo's dependency cache. This creates a
fresh lockfile offline; it does not claim the workspace lockfile governs consumers.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    cargo = shutil.which(args.cargo)
    if not cargo:
        parser.exit(2, "Cargo is required; external-consumer validation was not executed.\n")
    with tempfile.TemporaryDirectory(prefix="packetcraftr-external-") as directory:
        project = Path(directory)
        dependencies = "\n".join(
            f'{name} = {{ path = {json.dumps(str(ROOT / "crates" / name))}, default-features = false }}'
            for name in ("packetcraftr", "packetcraftr-core", "packetcraftr-netio")
        )
        (project / "Cargo.toml").write_text(
            '[package]\nname = "packetcraftr-external-consumer"\nversion = "0.0.0"\n'
            'edition = "2024"\npublish = false\n\n[workspace]\n\n[dependencies]\n'
            + dependencies + '\n\n[[test]]\nname = "composition"\npath = "composition.rs"\n'
        )
        shutil.copyfile(ROOT / "examples/consumers/rust/composition.rs", project / "composition.rs")
        env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target/external-consumer"))
        # The detached temporary project has no rust-toolchain.toml. Preserve the
        # repository's pinned toolchain rather than silently choosing the host default.
        import tomllib
        channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        env["RUSTUP_TOOLCHAIN"] = channel
        subprocess.run([cargo, "generate-lockfile", "--offline"], cwd=project, env=env, check=True, timeout=180)
        subprocess.run([cargo, "test", "--locked", "--offline"], cwd=project, env=env, check=True, timeout=600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
