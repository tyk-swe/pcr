#!/usr/bin/env bash
set -euo pipefail

base="${GITHUB_BASE_SHA:-}"
if [[ -z "${base}" || "${base}" == "0000000000000000000000000000000000000000" ]]; then
    if git rev-parse --verify HEAD^ >/dev/null 2>&1; then
        base="HEAD^"
    else
        base="HEAD"
    fi
fi

mapfile -t changed < <(git diff --name-only "${base}" HEAD -- tests/fixtures)
for path in "${changed[@]}"; do
    case "${path}" in
        *.md) continue ;;
        *.json)
            if [[ -f "${path}" ]]; then
                python -m json.tool "${path}" >/dev/null
            fi
            continue
            ;;
    esac

    provenance="${path}.json"
    if [[ -f "${path}" && ! -f "${provenance}" ]]; then
        echo "fixture ${path} has no provenance sidecar ${provenance}" >&2
        exit 1
    fi
    if ! printf '%s\n' "${changed[@]}" | grep -Fxq "${provenance}"; then
        echo "fixture ${path} changed without a reviewed provenance sidecar change" >&2
        exit 1
    fi
    if [[ -f "${provenance}" ]]; then
        python -m json.tool "${provenance}" >/dev/null
    fi
done
