#!/bin/sh
# Start a Guix shell that can build secp256k1-jdk
# Once the shell is started use `mvn verify` to build secp256k1-jdk
# Update with: `guix pull && guix describe -f channels > channels.scm`
exec guix time-machine -C channels.scm -- shell -m manifest.scm -- bash -c '
  export LIBSECP_DIR="$(dirname "$(readlink -f "$GUIX_ENVIRONMENT/lib/libsecp256k1.so")")"
  export MAVEN_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED"
  exec "${SHELL:-bash}"
'
