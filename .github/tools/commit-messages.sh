#!/bin/bash

# Fails if any commit names Claude as its author or committer, or
# mentions Claude anywhere in its message (e.g. a Co-Authored-By trailer).
# Checks every commit reachable from HEAD, or the commits of the
# revision range given as $1 (e.g. "origin/main..HEAD"). Needs the full
# history (actions/checkout with fetch-depth: 0).

PATTERN="claude"


# Prints the first line of $1 that contains PATTERN (case-insensitive);
# fails if there is none. The text reaches grep as a here-string rather
# than through a pipe: with `echo | grep -q`, grep exits on the first
# match while echo is still writing a long message, echo dies of SIGPIPE,
# and under pipefail the match would read as a miss.
function first_match() {
    grep -i -F -m 1 -- "${PATTERN}" <<<"$1"
}


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
        local people match
        people="$(git log -1 --format='%an <%ae>%n%cn <%ce>' "${commit}")"
        if match="$(first_match "${people}")"; then
            issues+=("${commit}: author/committer: ${match}")
        fi
        local message
        message="$(git log -1 --format='%B' "${commit}")"
        if match="$(first_match "${message}")"; then
            issues+=("${commit}: message: ${match}")
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
