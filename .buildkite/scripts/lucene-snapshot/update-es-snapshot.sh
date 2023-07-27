#!/bin/bash

set -euo pipefail

echo --- Update Lucene snapshot in Elasticsearch

# TODO ability to pass in
LUCENE_REVISION=SNAPSHOT-$(buildkite-agent meta-data get lucene-snapshot-revision)

# Replace `lucene = <version>` string in version.properties
sed -E "s/^(:lucene_version[^ ]*  *).*\$/\1$LUCENE_REVISION/" build-tools-internal/version.properties > new-version.properties
mv new-version.properties build-tools-internal/version.properties

git config --global user.name elasticmachine
git config --global user.email '15837671+elasticmachine@users.noreply.github.com'

git checkout "$BUILDKITE_BRANCH"
git pull --ff-only origin "$BUILDKITE_BRANCH"
git add -u build-tools-internal/version.properties
git push origin "$BUILDKITE_BRANCH"
