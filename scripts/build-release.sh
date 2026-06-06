#!/bin/sh
# Build all release artifacts and copies them to a writable directory for signing (with JReleaser)
# This should be run from the project root directory and inside the `nix develop` shell
set -x
export REVISION=$(mvn -q help:evaluate -Dexpression=revision -DforceStdout)
# Maven deploys of `-SNAPSHOT` versions are not reproducible because Maven adds timestamps to filenames,
# so we change `-SNAPSHOT` to `-ci`.
export CI_REVISION=$(echo "$REVISION" | sed 's/-SNAPSHOT$/-ci/')
mvn -Drevision="$CI_REVISION" deploy

# In the future `ARTIFACT_REPO` will be read-only.
# Copy to a writable staging dir (`SIGNED_REPO`) for JReleaser to do signing in:
ARTIFACT_REPO="target/repo"
SIGNED_REPO="target/repo-signed"
rm -rf "$SIGNED_REPO"
cp -rL "$ARTIFACT_REPO" "$SIGNED_REPO" # -L dereferences any symlinks
chmod -R u+w "$SIGNED_REPO"            # /nix/store files are read-only; make the copy writable
