#!/bin/bash
#
# For each released version in ChangeLog.md (Keep a Changelog format),
# looks up the committer of the matching "vX.Y.Z" git tag and prints a
# "<version><TAB><committer>" line for it. Versions with no matching tag
# (including the current "Unreleased" one) are skipped.
#
# Usage: gen-changelog-authors.sh <ChangeLog.md>
#
# Run at autogen time (in a full git checkout) since downstream jobs
# that build from the dist tarball don't have .git available.

set -e

md=$1

while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^##\ \[([^]]+)\]\ -\ (.*)$ ]]; then
        version="${BASH_REMATCH[1]}"
        date="${BASH_REMATCH[2]}"
        if [ "$date" != "Unreleased" ]; then
            author=$(git log -1 --format='%cn <%ce>' "v${version}" 2> /dev/null || true)
            [ -n "$author" ] && printf '%s\t%s\n' "$version" "$author"
        fi
    fi
done < "$md"
