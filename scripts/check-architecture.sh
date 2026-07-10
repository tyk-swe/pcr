#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "${root}"

portable_modules=(
    src/core/mod.rs
    src/protocols/mod.rs
    src/session/mod.rs
    src/tools/mod.rs
    src/client.rs
    src/v2_cli.rs
)

for module in "${portable_modules[@]}"; do
    if ! rg --fixed-strings --quiet '#![forbid(unsafe_code)]' "${module}"; then
        echo "portable component ${module} must forbid unsafe code" >&2
        exit 1
    fi
done

mapfile -t unsafe_or_ffi_files < <(
    rg --files-with-matches \
        'allow\(unsafe_code\)|#\[unsafe\(|unsafe[[:space:]]+(extern|fn|impl|trait|static)|unsafe[[:space:]]*\{|extern[[:space:]]+"[^"]+"' \
        src --glob '*.rs' || true
)
for path in "${unsafe_or_ffi_files[@]}"; do
    case "${path}" in
        src/io/platform/*) ;;
        *)
            echo "unsafe/FFI policy violation outside src/io/platform: ${path}" >&2
            exit 1
            ;;
    esac
done

mapfile -t native_reference_files < <(
    rg --files-with-matches \
        'pnet::|rtnetlink::|socket2::|windows::|pcap::(Capture|Device|Error|Linktype|Packet|Savefile)' \
        src --glob '*.rs' || true
)
for path in "${native_reference_files[@]}"; do
    case "${path}" in
        src/io/platform/*) ;;
        *)
            echo "native dependency reference outside src/io/platform: ${path}" >&2
            exit 1
            ;;
    esac
done

if ! rg --fixed-strings --quiet 'mod platform;' src/io/mod.rs; then
    echo "the platform adapter module must remain crate-private" >&2
    exit 1
fi
if rg --quiet 'pub([[:space:]]*\([^)]*\))?[[:space:]]+mod[[:space:]]+platform' src/io/mod.rs; then
    echo "src/io/platform must not be exported through the public API" >&2
    exit 1
fi

native_packages='^(pnet([_ ]|$)|pcap([_ ]|$)|rtnetlink([_ ]|$)|netlink-|socket2[[:space:]]|windows[[:space:]])'
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
            rg "${native_packages}" || true
    )" && [[ -n "${matches}" ]]; then
        echo "portable dependency graph for ${target} resolved native adapter packages:" >&2
        echo "${matches}" >&2
        exit 1
    fi
done

cargo metadata --locked --no-deps --format-version 1 | python3 -c '
import json
import sys

native = {"pcap", "pnet", "rtnetlink", "socket2", "windows"}
violations = []
for package in json.load(sys.stdin)["packages"]:
    for dependency in package["dependencies"]:
        if dependency["name"] not in native:
            continue
        name = dependency["name"]
        if not dependency["optional"]:
            violations.append(f"{name} must be optional")
        if dependency["target"] is None:
            violations.append(f"{name} must be target-specific")
        if dependency["uses_default_features"]:
            violations.append(f"{name} must disable default features")
if violations:
    print("native dependency declaration policy failed:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)
'

for required in \
    'resolver = "2"' \
    'native-dependency-owner = "packetcraftr-io::platform"' \
    'unsafe-owner = "packetcraftr-io::platform"'; do
    if ! rg --fixed-strings --quiet "${required}" Cargo.toml; then
        echo "Cargo workspace architecture metadata is missing: ${required}" >&2
        exit 1
    fi
done

echo "component, native-dependency, and unsafe-code policies passed"
