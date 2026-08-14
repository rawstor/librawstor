#!/bin/bash
#
# Builds the GitHub release body: this version's ChangeLog.md section (via
# changelog-section.sh), then the release's assets grouped by kind.
#
# GitHub Releases has no folder/grouping support for the assets list
# itself -- it's always one flat, alphabetically-sorted list. This is the
# workaround: a curated, categorized index in the release body, on top of
# (not instead of) that flat list.
#
# Usage: release-notes.sh TAG ARTIFACTS_DIR REPO CHANGELOG_FILE
#   TAG            git tag being released, e.g. v0.2.7
#   ARTIFACTS_DIR  directory of per-job artifact subdirectories, as laid
#                  out by `actions/download-artifact` with no `name:`
#                  (one subdirectory per upload-artifact `name:` in
#                  dist.yml, containing that job's files)
#   REPO           "owner/repo", for building asset download URLs
#   CHANGELOG_FILE path to ChangeLog.md -- not assumed to be relative to
#                  the caller's cwd (e.g. dist.yml's release job runs this
#                  from the workspace root, one level above the checkout)

set -euo pipefail

USAGE="usage: release-notes.sh TAG ARTIFACTS_DIR REPO CHANGELOG_FILE"
TAG="${1:?$USAGE}"
ARTIFACTS_DIR="${2:?$USAGE}"
REPO="${3:?$USAGE}"
CHANGELOG_FILE="${4:?$USAGE}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Which category an artifact group (an ARTIFACTS_DIR subdirectory, named
# after the matching upload-artifact `name:` in dist.yml) belongs under,
# as "sort-key\tlabel" -- the sort key just fixes display order, stripped
# before printing. Keep in sync with dist.yml's upload-artifact names.
category_for() {
    # Non-numeric sort keys on purpose: awk compares two operands
    # numerically, not as strings, the moment both merely *look* like
    # numbers -- including an uninitialized variable, which doubles as
    # 0 -- so a numeric-looking key here would make the very first
    # group's heading silently fail to print ("0" != uninitialized
    # evaluates as 0 != 0, i.e. false).
    case "$1" in
    sources) printf 'a\tSource tarball\n' ;;
    *.deb) printf 'b\tDebian/Ubuntu packages\n' ;;
    *.rpm) printf 'c\tRPM packages\n' ;;
    python3-rawstor.whl | python3-rawstor.sdist) printf 'd\tPython package\n' ;;
    *) printf 'z\tOther\n' ;;
    esac
}

changelog="$("$SCRIPT_DIR/changelog-section.sh" "$TAG" "$CHANGELOG_FILE")"
if [ -n "$changelog" ]; then
    printf '## Changelog\n\n%s\n\n' "$changelog"
fi

echo "## Assets"

pairs="$(
    for dir in "$ARTIFACTS_DIR"/*/; do
        [ -d "$dir" ] || continue
        group="$(basename "$dir")"
        category="$(category_for "$group")"
        for f in "$dir"*; do
            [ -f "$f" ] || continue
            printf '%s\t%s\n' "$category" "$(basename "$f")"
        done
    done | sort
)"

if [ -z "$pairs" ]; then
    echo "(no assets found)"
    exit 0
fi

echo "$pairs" | awk -F'\t' -v tag="$TAG" -v repo="$REPO" '
    $1 != prev_key {
        if (prev_key != "") print ""
        print "### " $2
        prev_key = $1
    }
    {
        printf "- [%s](https://github.com/%s/releases/download/%s/%s)\n", $3, repo, tag, $3
    }
'
