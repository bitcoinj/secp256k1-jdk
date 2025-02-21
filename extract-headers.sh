#!/bin/sh
# This script assumes you are using Nix Packages with `experimental-features = nix-command flakes`
# and have used `nix profile install secp256k1` to install the secp256k1 library and headers.
# It also assumes you have `jextract` version 23 in your `$PATH`. (To install with Nix, use
# `nix profile install jextract`)
INC_PATH="$HOME/.nix-profile/include/"
mkdir -p build
jextract --target-package org.bitcoinj.secp.ffm.jextract \
        --output build \
        --use-system-load-library \
        -lsecp256k1 \
        --header-class-name secp256k1_h \
        $INC_PATH/secp256k1_schnorrsig.h
