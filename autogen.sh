#!/bin/sh

set -e

libtoolize --copy --force
aclocal -I m4
autoheader
autoconf
automake -a -c

if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    .github/tools/gen-changelog-authors.sh ChangeLog.md > changelog-authors.tsv
fi
