#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s [quick|matrix|full]\n' "${0##*/}" >&2
    exit 2
}

run() {
    printf '+ %s\n' "$*"
    "$@"
}

if [ "$#" -gt 1 ]; then
    usage
fi

mode="${1:-quick}"

case "$mode" in
    quick)
        run cargo fmt --check
        run cargo test
        ;;
    matrix)
        run cargo test --no-default-features
        run cargo test
        run cargo test --features daemon
        run cargo test --features experimental
        ;;
    full)
        run cargo clippy --all-targets --all-features -- -D warnings
        ;;
    *)
        usage
        ;;
esac
