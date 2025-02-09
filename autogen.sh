#!/bin/sh

set -e

libtoolize --copy --force
aclocal -I m4
autoheader
autoconf
automake -a -c
