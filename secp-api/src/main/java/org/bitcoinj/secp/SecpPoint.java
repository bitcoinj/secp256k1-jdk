/*
 * Copyright 2023-2025 secp256k1-jdk Developers.
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
import org.bitcoinj.secp.internal.SecpPointUncompressed;

import java.security.spec.ECPoint;

/**
 * A P256K1 point -- either {@link Compressed}, {@link Uncompressed}, or {@link Infinity}. Implementations of this interface
 * <i>need not</i> be subclasses of {@link java.security.spec.ECPoint}. {@code ECPoint} is a concrete class
 * and uses {@link java.math.BigInteger} internally. {@code SecpPoint} uses
 * {@link SecpFieldElement} to represent point coordinates. If you need a type that
 * is both a {@code SecpPoint} and a {@code ECPoint}, use {@link SecpECPoint}.
 */
public interface SecpPoint {
    /** The P256K1 infinity point */
    Infinity POINT_INFINITY = Infinity.INSTANCE;

    /**
     * Construct an uncompressed SecpPoint from two field elements
     * @param x x component
     * @param y y component
     * @return point
     */
    static SecpPointUncompressed of(SecpFieldElement x, SecpFieldElement y) {
        return new SecpPointUncompressed(x, y);
    }

    /**
     * Construct a SecpPoint from a Java Cryptography {@link ECPoint}
     * @param point Java point
     * @return SecpPoint point
     */
    static SecpPoint of(ECPoint point) {
        return  point == ECPoint.POINT_INFINITY
                    ? SecpPoint.POINT_INFINITY
                    : point instanceof SecpECPoint
                        ? (SecpECPoint) point
                        : SecpPointUncompressed.of(point);
    }

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

        /**
         * Get the default serialization encoding
         * @return serialized point
         */
        default byte[] serialize() {
            byte[] compressed = new byte[33];
            compressed[0] = isOdd()
                    ? (byte) 0x03      // odd
                    : (byte) 0x02;     // even;
            System.arraycopy(x().serialize(),
                    0,
                    compressed,
                    1,
                    32);
            return compressed;
        }
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
         * Get the default serialization encoding
         * @return serialized point
         */
        default byte[] serialize() {
            byte[] uncompressed = new byte[65];
            uncompressed[0] = 0x04;
            System.arraycopy(x().serialize(), 0, uncompressed, 1, 32);
            System.arraycopy(y().serialize(), 0, uncompressed, 33, 32);
            return uncompressed;
        }

        default ECPoint toECPoint() {
            return this instanceof SecpECPoint
                    ? (SecpECPoint) this
                    : new ECPoint(x().toBigInteger(), y().toBigInteger());
        }
    }
}
