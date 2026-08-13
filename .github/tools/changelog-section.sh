#!/bin/bash
#
# Prints the ChangeLog.md section for one version -- everything between
# its "## [VERSION] - ..." heading and the next "## [" heading (or end of
# file), heading line excluded. Prints nothing (and exits 0) if the
# version has no section, so callers can just check for empty output
# rather than handling a separate error case.
#
# Usage: changelog-section.sh VERSION [CHANGELOG_FILE]

set -euo pipefail

VERSION="${1:?usage: changelog-section.sh VERSION [CHANGELOG_FILE]}"
# Tags are "vX.Y.Z"; ChangeLog.md headings are "## [X.Y.Z]" -- accept
# either so this works whether the caller passes a git ref or a bare
# version.
VERSION="${VERSION#v}"
FILE="${2:-ChangeLog.md}"

awk -v version="$VERSION" '
    /^## \[/ {
        if (in_section) exit
        if ($0 ~ ("^## \\[" version "\\]")) {
            in_section = 1
        }
        next
    }
    in_section { buf[++n] = $0 }
    END {
        start = 1
        while (start <= n && buf[start] == "") start++
        stop = n
        while (stop >= start && buf[stop] == "") stop--
        for (i = start; i <= stop; i++) print buf[i]
    }
' "$FILE"
