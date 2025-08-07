#!/bin/bash

set -ex

REPO=$1
MESSAGE=$2

MAXWAIT=10
MAXRETRY=100

cd ${REPO}

git add .
git commit -m "${MESSAGE}"
count=1
while ! git push; do
    git pull --rebase -X ours --no-edit
    ((count++))
    sleep $((RANDOM % MAXWAIT))
    if [[ $count -gt $MAXRETRY ]]; then
        echo "Retry exceeded"
        exit 1
    fi
done
