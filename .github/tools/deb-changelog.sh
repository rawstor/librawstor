#!/bin/bash
#
# Converts ChangeLog.md (Keep a Changelog format) into a full Debian
# changelog: the top entry uses the given package name/version (the one
# actually being built) with the first ChangeLog.md section as its body,
# followed by every prior section as its own dated, versioned entry.
#
# Usage: deb-changelog.sh <package-name> <version> <ChangeLog.md>
#
# The maintainer line defaults to the last git committer but can be
# overridden via the MAINTAINER environment variable.

set -e

pkg=$1
version=$2
md=$3

declare -a versions dates items

section=-1
current_items=""

flush() {
    if [ $section -ge 0 ]; then
        items[$section]="$current_items"
    fi
}

read_sections() {
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" =~ ^##\ \[([^]]+)\]\ -\ (.*)$ ]]; then
            flush
            section=$((section + 1))
            versions[$section]="${BASH_REMATCH[1]}"
            dates[$section]="${BASH_REMATCH[2]}"
            current_items=""
        elif [ $section -ge 0 ] && [[ "$line" =~ ^-\ (.*)$ ]]; then
            current_items+="${BASH_REMATCH[1]}"$'\n'
        fi
    done < "$md"
    flush
}

to_rfc2822() {
    if [ "$1" = "Unreleased" ]; then
        date -R
    else
        date -R -d "$1" 2> /dev/null || date -R
    fi
}

print_body() {
    local idx=$1
    if [ -z "${items[$idx]}" ]; then
        echo "  * No notable changes yet."
    else
        while IFS= read -r item; do
            [ -n "$item" ] && echo "  * ${item}"
        done <<< "${items[$idx]}" || true
    fi
}

print_entry() {
    local idx=$1 entry_version=$2 distribution=$3
    echo "${pkg} (${entry_version}) ${distribution}; urgency=medium"
    echo
    print_body "$idx"
    echo
    echo " -- ${MAINTAINER:-$(git log -1 --format='%cn <%ce>' 2> /dev/null || echo "unknown <unknown@example.com>")}  $(to_rfc2822 "${dates[$idx]}")"
}

read_sections

# The current, in-progress entry: always the version actually being
# built, not whatever ChangeLog.md's own top section happens to say.
print_entry 0 "$version" UNRELEASED

# Everything else is a real past release.
for ((i = 1; i <= section; i++)); do
    echo
    print_entry "$i" "${versions[$i]}" unstable
done
