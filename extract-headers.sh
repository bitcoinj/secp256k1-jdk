#!/bin/sh
# This script assumes you are using Nix Packages with `experimental-features = nix-command flakes`
# and are running in the Nix devshell or have used `nix profile install secp256k1` to install the secp256k1
# library and headers into your profile.
# It also assumes you have `jextract` version 25 in your `$PATH` via the devshell, Nix Home Manager, or
# `nix profile install nixpkgs#jextract`.
# `$SECP256K1_INCLUDE_DIR` should be set to point to the header files, the Nix devshell also sets this up.
mkdir -p build
jextract --target-package org.bitcoinj.secp.ffm.jextract \
        --output target \
        --use-system-load-library \
        -lsecp256k1 \
        --header-class-name secp256k1_h \
        $SECP256K1_INCLUDE_DIR/secp256k1_schnorrsig.h \
        $SECP256K1_INCLUDE_DIR/secp256k1_ecdh.h
