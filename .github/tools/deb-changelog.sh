#!/bin/bash
#
# Converts ChangeLog.md (Keep a Changelog format) into a full Debian
# changelog: the top entry uses the given package name/version (the one
# actually being built) with the first ChangeLog.md section as its body,
# followed by every prior section as its own dated, versioned entry.
#
# Usage: deb-changelog.sh <package-name> <version> <ChangeLog.md> [<authors-file>]
#
# <authors-file>, if given, is a "<version><TAB><name> <email>" mapping
# (see gen-changelog-authors.sh) used to credit each historical entry to
# whoever actually tagged that release. The current (top) entry, and any
# historical one missing from the file, falls back to the MAINTAINER
# environment variable, or the last git committer if that's unset too.

set -e

pkg=$1
version=$2
md=$3
authors_file=$4

if [ -z "$pkg" ] || [ -z "$version" ] || [ -z "$md" ]; then
    echo "usage: $0 <package-name> <version> <ChangeLog.md> [<authors-file>]" >&2
    exit 1
fi

if [ ! -f "$md" ]; then
    echo "error: changelog file '$md' not found" >&2
    exit 1
fi

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
        elif [ $section -ge 0 ] && [[ "$line" =~ ^[[:space:]]*[-*][[:space:]]+(.*)$ ]]; then
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

default_author() {
    echo "${MAINTAINER:-$(git log -1 --format='%cn <%ce>' 2> /dev/null || echo "unknown <unknown@example.com>")}"
}

author_for() {
    local entry_version=$1 found=""
    if [ -n "$authors_file" ] && [ -f "$authors_file" ]; then
        found=$(awk -F'\t' -v v="$entry_version" '$1 == v { print $2; exit }' "$authors_file")
    fi
    echo "${found:-$(default_author)}"
}

print_entry() {
    local idx=$1 entry_version=$2 distribution=$3 author=$4
    echo "${pkg} (${entry_version}) ${distribution}; urgency=medium"
    echo
    print_body "$idx"
    echo
    echo " -- ${author}  $(to_rfc2822 "${dates[$idx]}")"
}

read_sections

# Find the ChangeLog.md section matching the version actually being
# built. This is normally section 0 (the top, in-progress one), but
# doesn't have to be -- e.g. when backporting a fix to an older release
# while ChangeLog.md's top section already describes newer, unreleased
# work. Default to 0 if $version isn't recorded in ChangeLog.md at all.
target_idx=0
for ((idx = 0; idx <= section; idx++)); do
    if [ "${versions[$idx]}" = "$version" ]; then
        target_idx=$idx
        break
    fi
done

# The current, in-progress entry: always the version actually being
# built, not whatever ChangeLog.md's own top section happens to say.
print_entry "$target_idx" "$version" UNRELEASED "$(default_author)"

# Everything older is a real past release, credited to whoever tagged
# it. Sections newer than target_idx (if any) are skipped, since they
# describe work that hasn't shipped as $version.
for ((i = target_idx + 1; i <= section; i++)); do
    echo
    print_entry "$i" "${versions[$i]}" unstable "$(author_for "${versions[$i]}")"
done
