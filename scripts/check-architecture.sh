#!/usr/bin/env bash
set -euo pipefail

if root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    :
else
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "${root}"

if command -v rg >/dev/null 2>&1; then
    have_rg=true
else
    have_rg=false
fi

contains_fixed() {
    local needle="$1"
    local path="$2"
    if ${have_rg}; then
        rg --fixed-strings --quiet "${needle}" "${path}"
    else
        grep --fixed-strings --quiet -- "${needle}" "${path}"
    fi
}

contains_regex() {
    local pattern="$1"
    local path="$2"
    if ${have_rg}; then
        rg --quiet "${pattern}" "${path}"
    else
        grep --extended-regexp --quiet -- "${pattern}" "${path}"
    fi
}

rust_files_matching() {
    local pattern="$1"
    if ${have_rg}; then
        rg --files-with-matches "${pattern}" src crates --glob '*.rs'
    else
        find src crates -type f -name '*.rs' -exec grep --extended-regexp --files-with-matches -- "${pattern}" {} +
    fi
}

filter_regex() {
    local pattern="$1"
    if ${have_rg}; then
        rg "${pattern}"
    else
        grep --extended-regexp -- "${pattern}"
    fi
}

portable_modules=(
    crates/core/src/lib.rs
    crates/core/src/core/mod.rs
    crates/core/src/error.rs
    crates/protocols/src/lib.rs
    crates/protocols/src/protocols/mod.rs
    crates/session/src/lib.rs
    crates/session/src/session/mod.rs
    src/lib.rs
    src/tools/mod.rs
    src/output.rs
    src/client.rs
    src/cli.rs
)

for module in "${portable_modules[@]}"; do
    if ! contains_fixed '#![forbid(unsafe_code)]' "${module}"; then
        echo "portable component ${module} must forbid unsafe code" >&2
        exit 1
    fi
done

mapfile -t unsafe_or_ffi_files < <(
    rust_files_matching \
        'allow\(unsafe_code\)|#\[unsafe\(|unsafe[[:space:]]+(extern|fn|impl|trait|static)|unsafe[[:space:]]*\{|extern[[:space:]]+"[^"]+"' || true
)
for path in "${unsafe_or_ffi_files[@]}"; do
    case "${path}" in
        crates/io/src/io/platform/*) ;;
        *)
            echo "unsafe/FFI policy violation outside packetcraftr-io::platform: ${path}" >&2
            exit 1
            ;;
    esac
done

mapfile -t native_reference_files < <(
    rust_files_matching \
        'futures_util::|libc::|libloading::|pnet::|rtnetlink::|socket2::|tokio::|windows::|pcap::(Capture|Device|Error|Linktype|Packet|Savefile)' || true
)
for path in "${native_reference_files[@]}"; do
    case "${path}" in
        crates/io/src/io/platform/*) ;;
        *)
            echo "native dependency reference outside packetcraftr-io::platform: ${path}" >&2
            exit 1
            ;;
    esac
done

io_module=crates/io/src/io/mod.rs
if ! contains_fixed 'mod platform;' "${io_module}"; then
    echo "the platform adapter module must remain crate-private" >&2
    exit 1
fi
if contains_regex 'pub([[:space:]]*\([^)]*\))?[[:space:]]+mod[[:space:]]+platform' "${io_module}"; then
    echo "packetcraftr-io::platform must not be exported through the public API" >&2
    exit 1
fi

for legacy in src/core src/protocols src/io src/session src/error.rs; do
    if [[ -e "${legacy}" ]]; then
        echo "legacy façade-owned component source remains after extraction: ${legacy}" >&2
        exit 1
    fi
done

for reexport in \
    'pub use packetcraftr_core::{core, error};' \
    'pub use packetcraftr_io::io;' \
    'pub use packetcraftr_protocols::protocols;' \
    'pub use packetcraftr_session::session;'; do
    if ! contains_fixed "${reexport}" src/lib.rs; then
        echo "the root façade is missing component reexport: ${reexport}" >&2
        exit 1
    fi
done

native_packages='^(futures-util[[:space:]]|libc[[:space:]]|libloading[[:space:]]|pnet([_ ]|$)|pcap([_ ]|$)|rtnetlink([_ ]|$)|netlink-|socket2[[:space:]]|tokio[[:space:]]|windows[[:space:]])'
portable_targets=(
    x86_64-unknown-linux-gnu
    aarch64-apple-darwin
    x86_64-pc-windows-msvc
)
for target in "${portable_targets[@]}"; do
    if matches="$(
        cargo tree \
            --color never \
            --locked \
            --no-default-features \
            --target "${target}" \
            --edges normal \
            --prefix none \
            --format '{p}' |
            filter_regex "${native_packages}" || true
    )" && [[ -n "${matches}" ]]; then
        echo "portable dependency graph for ${target} resolved native adapter packages:" >&2
        echo "${matches}" >&2
        exit 1
    fi
done

cargo metadata --locked --no-deps --format-version 1 | python3 -c '
import json
import sys
from pathlib import Path

native = {
    "futures-util",
    "libc",
    "libloading",
    "pcap",
    "pnet",
    "rtnetlink",
    "socket2",
    "tokio",
    "windows",
}
component_edges = {
    "packetcraftr-core": set(),
    "packetcraftr-protocols": {"packetcraftr-core"},
    "packetcraftr-io": {"packetcraftr-core", "packetcraftr-protocols"},
    "packetcraftr-session": set(),
    "packetcraftr": {
        "packetcraftr-core",
        "packetcraftr-protocols",
        "packetcraftr-io",
        "packetcraftr-session",
    },
}
data = json.load(sys.stdin)
packages = {package["name"]: package for package in data["packages"]}
violations = []
missing = set(component_edges) - set(packages)
if missing:
    violations.append(f"workspace is missing packages: {sorted(missing)}")

root = packages.get("packetcraftr")
version = root["version"] if root else None
workspace_root = Path(data["workspace_root"])
workspace_license = workspace_root / "LICENSE"

for name, expected_edges in component_edges.items():
    package = packages.get(name)
    if package is None:
        continue
    if package["version"] != version:
        violations.append(f"{name} must share root version {version}")
    if package.get("edition") != "2021":
        violations.append(f"{name} must share the 2021 edition")
    if package.get("rust_version") != "1.96":
        violations.append(f"{name} must share MSRV 1.96")
    if package.get("license") != "AGPL-3.0-only":
        violations.append(f"{name} must use AGPL-3.0-only metadata")
    if package.get("repository") != "https://github.com/tyk-swe/pcr":
        violations.append(f"{name} has inconsistent repository metadata")
    if package.get("publish") != []:
        violations.append(f"{name} must remain unavailable to public registries")
    readme = package.get("readme")
    if not readme or not Path(readme).is_file():
        violations.append(f"{name} must have a package-local README")
    manifest_dir = Path(package["manifest_path"]).parent
    license_file = manifest_dir / "LICENSE"
    if not license_file.is_file():
        violations.append(f"{name} archive is missing a package-local LICENSE")
    elif name != "packetcraftr" and license_file.read_bytes() != workspace_license.read_bytes():
        violations.append(f"{name} LICENSE differs from the workspace license")

    actual_edges = {
        dependency["name"]
        for dependency in package["dependencies"]
        if dependency["kind"] is None and dependency["name"] in component_edges
    }
    if actual_edges != expected_edges:
        violations.append(
            f"{name} component edges are {sorted(actual_edges)}, expected {sorted(expected_edges)}"
        )
    for dependency in package["dependencies"]:
        if dependency["name"] not in expected_edges:
            continue
        dependency_name = dependency["name"]
        if dependency["kind"] is not None:
            violations.append(f"{name} -> {dependency_name} must be a normal dependency")
        if dependency["req"] != f"={version}":
            violations.append(
                f"{name} -> {dependency_name} must require exact version ={version}"
            )
        if dependency.get("path") is None:
            violations.append(f"{name} -> {dependency_name} must retain a local path")
        else:
            expected_path = Path(packages[dependency_name]["manifest_path"]).parent
            if Path(dependency["path"]) != expected_path:
                violations.append(
                    f"{name} -> {dependency_name} resolves outside its workspace package"
                )

for package in packages.values():
    for dependency in package["dependencies"]:
        if dependency["name"] not in native:
            continue
        name = dependency["name"]
        if package["name"] != "packetcraftr-io":
            violations.append(f"{name} must be owned only by packetcraftr-io")
        if not dependency["optional"]:
            violations.append(f"{name} must be optional")
        if dependency["target"] is None:
            violations.append(f"{name} must be target-specific")
        if dependency["uses_default_features"]:
            violations.append(f"{name} must disable default features")
if violations:
    print("component and native dependency metadata policy failed:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)
'

for required in \
    'resolver = "2"' \
    'extracted-packages = ["packetcraftr-core", "packetcraftr-protocols", "packetcraftr-io", "packetcraftr-session"]' \
    'package-order = ["packetcraftr-core", "packetcraftr-protocols", "packetcraftr-io", "packetcraftr-session", "packetcraftr"]' \
    'native-dependency-owner = "packetcraftr-io::platform"' \
    'unsafe-owner = "packetcraftr-io::platform"'; do
    if ! contains_fixed "${required}" Cargo.toml; then
        echo "Cargo workspace architecture metadata is missing: ${required}" >&2
        exit 1
    fi
done

echo "component, native-dependency, and unsafe-code policies passed"
