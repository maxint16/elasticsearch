#!/bin/bash

set -euo pipefail

echo --- Building Lucene snapshot

# TODO custom branches
cd ..
git clone git@github.com:apache/lucene.git --branch main --single-branch --depth 1

REVISION=$(git rev-parse --short HEAD)
echo "Lucene Revision: $REVISION"

./gradlew localSettings
./gradlew clean mavenToLocal -Dversion.suffix="SNAPSHOT-$REVISION" -Dmaven.repo.local="$(pwd)/build/maven-local"
aws s3 sync build/maven-local/ "s3://download.elasticsearch.org/lucenesnapshots/$REVISION/" --acl public-read

buildkite-agent meta-data set lucene-snapshot-revision "$REVISION"

if [[ "${UPDATE_ES_LUCENE_SNAPSHOT:-}" ]]; then
  .buildkite/scripts/lucene-snapshot/update-es-snapshot.sh
fi
