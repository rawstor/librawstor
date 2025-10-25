#!/bin/bash

set -e

SHA=$(git rev-parse --short HEAD)

VERSION=$(
  git describe --tags --exact-match --match "v*.*.*" 2> /dev/null ||
  git describe --match "v*.*.*" --tags 2> /dev/null ||
  echo v99.0.0-0-${SHA})

echo ${VERSION:1}
