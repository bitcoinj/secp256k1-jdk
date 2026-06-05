#!/bin/sh
# Start a Guix shell that can build secp256k1-jdk
# Once the shell is started use `mvn verify` to build secp256k1-jdk
exec guix shell -m manifest.scm -- bash -c '
  export LIBSECP_DIR="$(guix build libsecp256k1 | tail -1)/lib"
  export MAVEN_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED"
  exec "${SHELL:-bash}"
'
