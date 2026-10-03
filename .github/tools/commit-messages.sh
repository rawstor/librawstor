#!/bin/bash

# Fails if any commit names Claude as its author or committer, or
# mentions Claude anywhere in its message (e.g. a Co-Authored-By trailer).
# Checks every commit reachable from HEAD, or the commits of the
# revision range given as $1 (e.g. "origin/main..HEAD"). Needs the full
# history (actions/checkout with fetch-depth: 0).

set -o pipefail


PATTERN="claude"


function main() {
    local range="${1:-HEAD}"
    local -a issues=()
    local checked=0

    local commits
    if ! commits="$(git rev-list "${range}")"; then
        echo -e "Can't list commits of \"${range}\"." >&2
        exit 1
    fi

    for commit in ${commits}; do
        checked=$((checked + 1))
        local people
        people="$(git log -1 --format='%an <%ae>%n%cn <%ce>' "${commit}")"
        if echo "${people}" | grep -qi "${PATTERN}"; then
            issues+=("${commit}: author/committer: $(echo "${people}" | grep -i "${PATTERN}" | head -1)")
        fi
        local message
        message="$(git log -1 --format='%B' "${commit}")"
        if echo "${message}" | grep -qi "${PATTERN}"; then
            issues+=("${commit}: message: $(echo "${message}" | grep -i "${PATTERN}" | head -1)")
        fi
    done

    echo -e "Commits checked: ${checked}"

    if [ ${#issues[@]} -eq 0 ]; then
        echo -e "Success!!! No commit mentions Claude."
        exit 0
    fi

    echo -e "Commits must not name Claude as an author or committer, nor mention it in the message:" >&2
    for issue in "${issues[@]}"; do
        echo "  ${issue}" >&2
    done
    exit 1
}


main "$@"
