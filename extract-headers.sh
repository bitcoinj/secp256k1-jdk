#!/bin/sh
NIX_STORE="/nix/store"
LIB_PKG="secp256k1-0.4.0"
HASH="j9mf1fh4wbb8c3x1zwqfs218bhml1rbw"
SECP_PATH=$NIX_STORE/$HASH-$LIB_PKG
mkdir -p build
jextract --target-package org.consensusj.secp256k1 \
        --output build \
        --source \
        $SECP_PATH/include/secp256k1.h
