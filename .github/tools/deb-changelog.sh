#!/bin/bash
#
# Converts ChangeLog.md (Keep a Changelog format) into a full Debian
# changelog: the top entry uses the given package name/version (the one
# actually being built) with the first ChangeLog.md section as its body,
# followed by every prior section as its own dated, versioned entry.
#
# Usage: deb-changelog.sh <package-name> <version> <full-version> <ChangeLog.md> [<authors-file>]
#
# <full-version> is the untruncated build version (e.g. autoconf's
# PACKAGE_VERSION, which keeps a "-N-gSHA" suffix unless this is an exact
# tag build -- see .github/tools/git-version.sh). It's used only to tell a
# real release from a dev/snapshot build: when it equals <version> exactly
# (no such suffix), the top entry's distribution is "unstable" instead of
# "UNRELEASED".
#
# <authors-file>, if given, is a "<version><TAB><name> <email><TAB><date>"
# mapping (see gen-changelog-authors.sh) crediting each entry to whoever
# actually tagged that release, dated to that tag's own commit date. Any
# entry missing from the file (usually only the current one, when it's
# not an exact tag build) falls back to the MAINTAINER environment
# variable (or the last git committer) and the current date/time.

set -e

pkg=$1
version=$2
full_version=$3
md=$4
authors_file=$5

if [ -z "$pkg" ] || [ -z "$version" ] || [ -z "$full_version" ] || [ -z "$md" ]; then
    echo "usage: $0 <package-name> <version> <full-version> <ChangeLog.md> [<authors-file>]" >&2
    exit 1
fi

if [ "$version" = "$full_version" ]; then
    distribution=unstable
else
    distribution=UNRELEASED
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

tag_info_for() {
    local entry_version=$1
    if [ -n "$authors_file" ] && [ -f "$authors_file" ]; then
        awk -F'\t' -v v="$entry_version" '$1 == v { print $2 "\t" $3; exit }' "$authors_file"
    fi
}

print_entry() {
    local idx=$1 entry_version=$2 distribution=$3
    local info author date_str
    info=$(tag_info_for "$entry_version")
    if [ -n "$info" ]; then
        author=${info%%$'\t'*}
        date_str=${info#*$'\t'}
    else
        author=$(default_author)
        date_str=$(to_rfc2822 "${dates[$idx]}")
    fi
    echo "${pkg} (${entry_version}) ${distribution}; urgency=medium"
    echo
    print_body "$idx"
    echo
    echo " -- ${author}  ${date_str}"
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
print_entry "$target_idx" "$version" "$distribution"

# Everything older is a real past release, credited (and dated) to
# whoever tagged it. Sections newer than target_idx (if any) are
# skipped, since they describe work that hasn't shipped as $version.
for ((i = target_idx + 1; i <= section; i++)); do
    echo
    print_entry "$i" "${versions[$i]}" unstable
done
