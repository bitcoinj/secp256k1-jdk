package org.consensusj.secp256k1.api;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.HexFormat;

/**
 *
 */
public interface P256k1PubKey extends ECPublicKey {
    HexFormat hf = HexFormat.of();

    @Override
    default String getAlgorithm() {
        return null;
    }

    @Override
    default String getFormat() {
        return null;
    }

    /**
     * Return key in primary encoded format (uncompressed for now)
     * @return public key in uncompressed format
     */
    @Override
    default byte[] getEncoded() {
        ECPoint point = getW();
        byte[] x = integerTo32Bytes(point.getAffineX());
        byte[] y = integerTo32Bytes(point.getAffineY());
        byte[] encoded = new byte[65];
        encoded[0] = 0x04;
        System.arraycopy(x, 0, encoded, 1, 32);
        System.arraycopy(y, 0, encoded, 33, 32);
        return encoded;
    }

    default byte[] getSerialized(boolean compressed) {
        return compressed
                ? getCompressed()
                : getEncoded();
    }

    default byte[] getCompressed() {
        ECPoint point = getW();
        byte[] compressed = new byte[33];
        compressed[0] = point.getAffineY().testBit(0)
                ? (byte) 0x03      // odd
                : (byte) 0x02;     // even;
        System.arraycopy(integerTo32Bytes(point.getAffineX()),
                0,
                compressed,
                1,
                32);
        return compressed;
    }

    @Override
    ECPoint getW();

    @Override
    default ECParameterSpec getParams() {
        return null;
    }

    /**
     * Convert a BigInteger to a fixed-length byte array
     * @param i an unsigned BigInteger containing a valid Secp256k1 field value
     * @return a 32-byte, big-endian unsigned integer value
     */
    static byte[] integerTo32Bytes(BigInteger i) {
        // TODO: Check for negative or greater than p?
        byte[] minBytes = i.toByteArray(); // return minimum, signed bytes
        if (minBytes.length > 33) throw new IllegalStateException("privKey BigInteger value too large");
        // Convert from signed, variable length to unsigned, fixed 32-byte length.
        byte[] result = new byte[32];
        System.arraycopy(minBytes,                                  // src
                minBytes.length == 33 ? 1 : 0,                      // src pos (skip sign byte if present)
                result,                                             // dest
                minBytes.length == 33 ? 0 : 32 - minBytes.length,   // dest pos
                minBytes.length == 33 ? 32 : minBytes.length);      // num bytes to copy
        return result;
    }
}
