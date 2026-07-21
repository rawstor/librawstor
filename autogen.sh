#!/bin/sh

set -e

libtoolize --copy --force
aclocal -I m4
autoheader
autoconf
automake -a -c

if [ -d .git ]; then
    .github/tools/gen-changelog-authors.sh ChangeLog.md > changelog-authors.tsv
fi
