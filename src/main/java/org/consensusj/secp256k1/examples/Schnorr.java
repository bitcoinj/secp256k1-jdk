package org.consensusj.secp256k1.examples;

import org.consensusj.secp256k1.foreign.Secp256k1Foreign;

import java.util.HexFormat;

/**
 *
 */
public class Schnorr {
    private static final HexFormat formatter = HexFormat.of();

    public static void main(String[] args) {
        /* Use a java try-with-resources to allocate and cleanup -- secp256k1_context_destroy is automatically called */
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
        }
    }
}
