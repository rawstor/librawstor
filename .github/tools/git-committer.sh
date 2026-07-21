#!/bin/bash

set -e

git log -1 --format='%cn <%ce>' 2> /dev/null || echo "unknown <unknown@example.com>"
