#!/bin/bash

set -e

REPO=$1
MESSAGE=$2

cd ${REPO}

git add .
git commit -m "${MESSAGE}"
while ! git push; do
    git fetch
    git rebase
done
