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

import org.bitcoinj.secp.internal.P256K1ECPoint;
import org.bitcoinj.secp.internal.P256K1PointUncompressed;

import java.security.spec.ECPoint;

/**
 * A P256K1 point -- either {@link Compressed}, {@link Uncompressed}, or {@link Infinity}. Implementations of this interface
 * <i>need not</i> be subclasses of {@link java.security.spec.ECPoint}. {@code ECPoint} is a concrete class
 * and uses {@link java.math.BigInteger} internally. {@code P256K1Point} uses
 * {@link P256K1FieldElement} to represent point coordinates. If you need a type that
 * is both a {@code P256K1Point} and a {@code ECPoint}, use {@link P256K1ECPoint}.
 */
public interface P256K1Point {
    /** The P256K1 infinity point */
    Infinity POINT_INFINITY = Infinity.INSTANCE;

    /**
     * Construct an uncompressed P256K1Point from two field elements
     * @param x x component
     * @param y y component
     * @return point
     */
    static P256K1PointUncompressed of(P256K1FieldElement x, P256K1FieldElement y) {
        return new P256K1PointUncompressed(x, y);
    }

    /**
     * Construct a P256K1Point from a Java Cryptography {@link ECPoint}
     * @param point Java point
     * @return P256K1Point point
     */
    static P256K1Point of(ECPoint point) {
        return  point == ECPoint.POINT_INFINITY
                    ? P256K1Point.POINT_INFINITY
                    : point instanceof P256K1ECPoint
                        ? (P256K1ECPoint) point
                        : P256K1PointUncompressed.of(point);
    }

    /** Singleton representing the point-at-infinity */
    enum Infinity implements P256K1Point {
        /** Singleton instance */
        INSTANCE;
    }

    /**
     * A non-infinity point, either {@link Compressed} or {@link Uncompressed}.
     */
    interface Point extends P256K1Point {
        /**
         * Get the x-coordinate field value
         * @return x-coordinate
         */
        P256K1FieldElement x();

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
        P256K1FieldElement y();
        /**
         * Convert to a compressed point.
         * @return compressed point
         */
        Compressed compress();
    }
}
