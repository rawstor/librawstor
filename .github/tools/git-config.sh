#!/bin/bash

set -e

REPO=$1

pushd .
cd ${REPO}
git config --global user.name "$(git log -1 --pretty=%an)"
git config --global user.email "$(git log -1 --pretty=%ae)"
popd

