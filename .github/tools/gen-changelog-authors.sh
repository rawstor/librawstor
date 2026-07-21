#!/bin/bash
#
# For each version in ChangeLog.md (Keep a Changelog format) that has a
# matching "vX.Y.Z" git tag, prints a "<version><TAB><committer><TAB><date>"
# line with that tag's committer and commit date (RFC 2822). Versions with
# no matching tag yet (including, usually, the current one) are skipped --
# ChangeLog.md's own "Unreleased" placeholder text is not consulted, only
# whether the tag actually exists.
#
# Usage: gen-changelog-authors.sh <ChangeLog.md>
#
# Run at autogen time (in a full git checkout) since downstream jobs
# that build from the dist tarball don't have .git available.

set -e

md=$1

if [ -z "$md" ]; then
    echo "usage: $0 <ChangeLog.md>" >&2
    exit 1
fi

if [ ! -f "$md" ]; then
    echo "error: changelog file '$md' not found" >&2
    exit 1
fi

while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^##\ \[([^]]+)\]\ -\ (.*)$ ]]; then
        version="${BASH_REMATCH[1]}"
        info=$(git log -1 --format='%cn <%ce>%x09%cd' --date=rfc2822 "v${version}" 2> /dev/null || true)
        [ -n "$info" ] && printf '%s\t%s\n' "$version" "$info"
    fi
done < "$md"
