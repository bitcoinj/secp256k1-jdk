/*
 * Copyright 2023-2026 secp256k1-jdk Developers.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoinj.secp;

import org.bitcoinj.secp.internal.SecpECPoint;

import java.security.spec.ECPoint;

/**
 * A P256K1 point -- either {@link Compressed}, {@link Uncompressed}, or {@link Infinity}.
 * <p>
 * {@link SecpPubKey} implements {@code SecpPoint.Uncompressed} and Java's {@link java.security.interfaces.ECPublicKey}
 * interface.
 * <p>
 * Implementations of this interface <i>need not</i> be subclasses of {@link java.security.spec.ECPoint}.
 * {@code ECPoint} is a concrete class and uses {@link java.math.BigInteger} internally.
 * {@code SecpPoint} may use {@link SecpFieldElement} to represent point coordinates. If you need a type that
 * is both a {@code SecpPoint} and a {@code ECPoint}, use {@link SecpECPoint}.
 */
public interface SecpPoint {
    /** The P256K1 infinity point */
    Infinity POINT_INFINITY = Infinity.INSTANCE;

    /** Singleton representing the point-at-infinity */
    enum Infinity implements SecpPoint {
        /** Singleton instance */
        INSTANCE;

        public ECPoint toECPoint() {
            return ECPoint.POINT_INFINITY;
        }
    }

    /**
     * A non-infinity point, either {@link Compressed} or {@link Uncompressed}.
     */
    interface Point extends SecpPoint {
        /**
         * Get the x-coordinate field value
         * @return x-coordinate
         */
        SecpFieldElement x();

        /**
         * Get the parity of the y-coordinate field value
         * @return {@code true} if odd, {@code false} if even
         */
        boolean isOdd();

        /**
         * Serialize using the implementation's default format
         * @return serialized point
         */
        byte[] serialize();
    }

    /**
     * A P256K1 point in compressed format.
     */
    interface Compressed extends Point {
        /**
         * Compute the y-value and return an uncompressed point.
         * @return uncompressed point
         */
        Uncompressed uncompress();
    }

    /**
     * A P256K1 point in uncompressed format.
     */
    interface Uncompressed extends Point {
        /**
         * Get the y-coordinate field value
         * @return y-coordinate
         */
        SecpFieldElement y();
        /**
         * Convert to a compressed point.
         * @return compressed point
         */
        Compressed compress();

        /**
         * Get the default serialization encoding. Uncompressed points default to uncompressed serialization,
         * but his can be overridden by calling {@link #serialize(boolean)}.
         * @return serialized point
         */
        @Override
        default byte[] serialize() {
            return serialize(false);
        }

        /**
         * Return encoded key in either compressed or uncompressed SEC format.
         * @param compressed Use compressed variant of format
         * @return public key in SEC format
         */
        byte[] serialize(boolean compressed);

        default ECPoint toECPoint() {
            return this instanceof SecpECPoint
                    ? (SecpECPoint) this
                    : new ECPoint(x().toBigInteger(), y().toBigInteger());
        }
    }

    /**
     * Serialize a point to SEC Compressed format
     * @param x x coordinate in 32-byte big-endian format
     * @param isOdd low-bit of y coordinate
     * @return serialized bytes
     */
    static byte[] serializeCompressed(byte[] x, boolean isOdd) {
        byte[] compressed = new byte[33];
        compressed[0] = serializationPrefix(isOdd);
        System.arraycopy(x, 0, compressed, 1, 32);
        return compressed;
    }

    /**
     * Serialize a point to SEC Uncompressed format
     * @param x x coordinate in 32-byte big-endian format
     * @param y y coordinate in 32-byte big-endian format
     * @return serialized bytes
     */
    static byte[] serializeUncompressed(byte[] x, byte[] y) {
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(x, 0, uncompressed, 1, 32);
        System.arraycopy(y, 0, uncompressed, 33, 32);
        return uncompressed;
    }

    /**
     * Return SEC serialization prefix
     * @param isOdd true if the y-coordinate is odd
     * @return {@code 2} for even, {@code 3} for odd
     */
    static byte serializationPrefix(boolean isOdd) {
        return isOdd ? (byte) 0x03 : (byte) 0x02;
    }
}
