#!/bin/sh
NIX_STORE="/nix/store"
LIB_PKG="secp256k1-0.4.0"
HASH="j9mf1fh4wbb8c3x1zwqfs218bhml1rbw"
SECP_PATH=$NIX_STORE/$HASH-$LIB_PKG
mkdir -p build
jextract --target-package org.bitcoinj.secp256k1.foreign.jextract \
        --output build \
        --source \
        -lsecp256k1 \
        --header-class-name secp256k1_h \
        $SECP_PATH/include/secp256k1_schnorrsig.h
