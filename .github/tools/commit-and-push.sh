#!/bin/bash

set -ex

REPO=$1
MESSAGE=$2

cd ${REPO}

git add .
git commit -m "${MESSAGE}"
git push
