#!/bin/sh
# Validate and publish release artifacts to our GitLab Maven artifact rpo
# This should be run from the project root directory and inside the `nix develop` shell
# JRELEASER_GITLAB_TOKEN should be set before running
if [[ $1 != "--dry-run" && $1 != "" ]]; then
    echo "Usage: $0 [--dry-run]"
    exit 1
fi

set -x
OPTIONS=${1:-""}
export REVISION=$(mvn -q help:evaluate -Dexpression=revision -DforceStdout)
export CI_REVISION=$(echo "$REVISION" | sed 's/-SNAPSHOT$/-ci/')

export JRELEASER_PROJECT_VERSION="$CI_REVISION"
jreleaser-cli deploy $OPTIONS
