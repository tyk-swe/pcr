#!/usr/bin/env bash
set -euo pipefail

zero_sha="0000000000000000000000000000000000000000"
head="${GITHUB_SHA:-HEAD}"
event="${GITHUB_EVENT_NAME:-local}"

require_commit() {
    local commit="$1"
    local label="$2"
    if ! git cat-file -e "${commit}^{commit}" 2>/dev/null; then
        echo "cannot establish fixture change range: ${label} commit ${commit} is unavailable" >&2
        exit 1
    fi
}

require_commit "${head}" "head"
head=$(git rev-parse "${head}^{commit}")

base=""
if [[ -n "${GITHUB_BASE_SHA:-}" && "${GITHUB_BASE_SHA}" != "${zero_sha}" ]]; then
    base="${GITHUB_BASE_SHA}"
    require_commit "${base}" "pull-request base"
elif [[ -n "${GITHUB_BEFORE_SHA:-}" && "${GITHUB_BEFORE_SHA}" != "${zero_sha}" ]]; then
    base="${GITHUB_BEFORE_SHA}"
    require_commit "${base}" "push before"
elif [[ "${event}" == "pull_request" ]]; then
    echo "cannot establish fixture change range: pull request base SHA is missing" >&2
    exit 1
elif [[ "${event}" == "push" ]]; then
    default_branch="${GITHUB_DEFAULT_BRANCH:-main}"
    for candidate in "refs/remotes/origin/${default_branch}" "origin/${default_branch}"; do
        if git rev-parse --verify "${candidate}^{commit}" >/dev/null 2>&1; then
            base=$(git merge-base "${candidate}" "${head}" || true)
            [[ -n "${base}" ]] && break
        fi
    done
    if [[ -z "${base}" ]]; then
        parents=$(git rev-list --parents -n 1 "${head}" | awk '{print NF - 1}')
        if [[ "${parents}" == "0" ]]; then
            base=$(git hash-object -t tree /dev/null)
        else
            echo "cannot establish fixture change range for a new-branch push" >&2
            exit 1
        fi
    fi
elif [[ -n "${1:-}" ]]; then
    base="$1"
    require_commit "${base}" "explicit base"
elif git rev-parse --verify HEAD^ >/dev/null 2>&1; then
    base=$(git rev-parse HEAD^)
else
    base=$(git hash-object -t tree /dev/null)
fi

python3 scripts/validate-fixture-corpus.py --quiet

mapfile -d '' -t changed < <(
    git diff --name-only -z --no-renames "${base}" "${head}" -- tests/fixtures
)

path_changed() {
    local requested="$1"
    local candidate
    for candidate in "${changed[@]}"; do
        [[ "${candidate}" == "${requested}" ]] && return 0
    done
    return 1
}

for path in "${changed[@]}"; do
    case "${path}" in
        tests/fixtures/README.md|*.example.json|*.provenance.json)
            continue
            ;;
    esac

    provenance="${path}.provenance.json"
    if [[ -f "${path}" ]]; then
        if [[ ! -f "${provenance}" ]]; then
            echo "fixture ${path} has no provenance sidecar ${provenance}" >&2
            exit 1
        fi
        if ! path_changed "${provenance}"; then
            echo "fixture ${path} changed without a reviewed provenance sidecar change" >&2
            exit 1
        fi
    else
        if [[ -f "${provenance}" ]]; then
            echo "fixture ${path} was deleted but provenance ${provenance} remains" >&2
            exit 1
        fi
        if ! path_changed "${provenance}"; then
            echo "fixture ${path} was deleted without deleting provenance ${provenance}" >&2
            exit 1
        fi
    fi
done

echo "fixture corpus and change range ${base}..${head} passed"
