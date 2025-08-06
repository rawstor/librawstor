#!/bin/bash

set -ex

REPO=$1
MESSAGE=$2

pushd .
cd librawstor
COMMIT_AUTHOR=$(git log -1 --pretty=%an)
COMMIT_EMAIL=$(git log -1 --pretty=%ae)
popd

git config --global user.name "${COMMIT_AUTHOR}"
git config --global user.email "${COMMIT_EMAIL}"

cd ${REPO}

git add .
git commit -m "${MESSAGE}"
git push
