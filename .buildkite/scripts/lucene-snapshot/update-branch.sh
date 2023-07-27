#!/bin/bash

set -euo pipefail

if [[ "$BUILDKITE_BRANCH" != "lucene_snapshot" ]]; then
  echo "Error: This script should only be run on the lucene_snapshot branch"
  exit 1
fi

git config --global user.name elasticmachine
git config --global user.email '15837671+elasticmachine@users.noreply.github.com'

git checkout lucene_snapshot
git fetch origin main
git merge origin/main
git push origin lucene_snapshot
