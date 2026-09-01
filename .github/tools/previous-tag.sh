#!/bin/bash
#
# Prints the highest "vX.Y.Z" git tag that sorts strictly below TAG by
# semantic version -- deliberately not "the tag that was created right
# before it" or "the tag TAG's commit descends from". Those two coincide
# for a plain, linear release history, but not once a patch is backported
# onto an older line after a newer one has already shipped from main
# (e.g. v0.3.0 ships, then v0.2.11 is cut as a v0.2.10 backport): v0.2.11's
# right diff base is v0.2.10, not v0.3.0, even though v0.3.0 was tagged
# first. GitHub's own "previous tag" auto-detection for generated release
# notes doesn't document this case reliably, hence doing it ourselves.
#
# Prints nothing (exit 0) if there's no lower tag (TAG is the first
# release), so callers can just check for empty output.
#
# Usage: previous-tag.sh TAG [REPO_DIR]

set -euo pipefail

USAGE="usage: previous-tag.sh TAG [REPO_DIR]"
TAG="${1:?$USAGE}"
REPO_DIR="${2:-.}"

{
    git -C "$REPO_DIR" tag --list 'v*.*.*'
    echo "$TAG"
} | sort -V -u | awk -v tag="$TAG" '
    $0 == tag { print prev; exit }
    { prev = $0 }
'
