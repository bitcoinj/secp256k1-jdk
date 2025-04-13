/*
 * Copyright 2023-2024 secp256k1-jdk Developers.
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
package org.bitcoinj.secp.api;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.Objects;

/**
 * Interface for P256K1 points. Implementations of this interface <i>need not</i> be
 * subclasses of {@link java.security.spec.ECPoint}. {@code ECPoint} is a concrete class
 * and uses {@link java.math.BigInteger} internally. {@code P256K1Point} prefers the use
 * of {@link P256K1FieldElement} to represent point coordinates. If you need a type that
 * is both a {@code P256K1Point} and a {@code ECPoint}, use {@link P256K1ECPoint}.
 */
public interface P256K1Point {
    P256K1PointInfinity INFINITY = new P256K1PointInfinity();


    static P256K1PointUncompressed of(P256K1FieldElement x, P256K1FieldElement y) {
        return new P256K1PointUncompressed(x, y);
    }

    static P256K1Point of(ECPoint point) {
        return  point == ECPoint.POINT_INFINITY
                    ? P256K1Point.INFINITY
                    : point instanceof P256K1ECPoint
                        ?  (P256K1ECPoint) point
                        :  P256K1PointUncompressed.of(point);
    }

    interface Infinity extends P256K1Point {}

    interface RegularPoint extends P256K1Point {
        P256K1FieldElement x();
        boolean isOdd();
    }

    interface Compressed extends RegularPoint {
        Uncompressed uncompress();
        default byte[] getEncoded() {
            byte[] compressed = new byte[33];
            compressed[0] = isOdd()
                    ? (byte) 0x03      // odd
                    : (byte) 0x02;     // even;
            System.arraycopy(x().toBytes(),
                    0,
                    compressed,
                    1,
                    32);
            return compressed;
        }
    }

    interface Uncompressed extends RegularPoint {
        P256K1FieldElement y();
        Compressed compress();
    }

    /**
     * Default implementation of {@link P256K1Point}
     */
    abstract class P256K1PointImpl implements P256K1Point {
        public static P256K1PointUncompressed of(P256K1FieldElement x, P256K1FieldElement y) {
            return new P256K1PointUncompressed(x, y);
        }
    }

    class P256K1PointUncompressed extends P256K1PointImpl implements Uncompressed {
        private final P256K1FieldElement x;
        private final P256K1FieldElement y;

        P256K1PointUncompressed(P256K1FieldElement x, P256K1FieldElement y) {
            this.x = x;
            this.y = y;
        }

        public static P256K1PointUncompressed of(ECPoint point) {
            return new P256K1PointUncompressed(P256K1FieldElement.of(point.getAffineX()),
                    P256K1FieldElement.of(point.getAffineY()));
        }

        @Override
        public P256K1FieldElement x() {
            return x;
        }

        @Override
        public boolean isOdd() {
            return y.isOdd();
        }

        @Override
        public P256K1FieldElement y() {
            return y;
        }

        // Must be overridden so it can return something that knows how to uncompress itself
        @Override
        public Compressed compress() {
            return new P256K1PointCompressed(x, y);
        }

        public boolean equals(P256K1Point other) {
            if (!(other instanceof P256K1PointUncompressed)) return false;
            Uncompressed otherUncompressed = (Uncompressed) other;
            return x().equals(otherUncompressed.x()) && y().equals(otherUncompressed.y());
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            P256K1PointUncompressed that = (P256K1PointUncompressed) o;
            return Objects.equals(x, that.x) && Objects.equals(y, that.y);
        }

        @Override
        public int hashCode() {
            return Objects.hash(x, y);
        }
    }

    class P256K1PointCompressed implements Compressed {
        private final P256K1FieldElement x;
        private final boolean isOdd;

        P256K1PointCompressed(P256K1FieldElement x, P256K1FieldElement y) {
            this.x = x;
            this.isOdd = y.isOdd();
        }

        @Override
        public P256K1FieldElement x() {
            return x;
        }

        @Override
        public boolean isOdd() {
            return isOdd;
        }

        @Override
        public Uncompressed uncompress() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            P256K1PointCompressed that = (P256K1PointCompressed) o;
            return isOdd == that.isOdd && Objects.equals(x, that.x);
        }

        @Override
        public int hashCode() {
            return Objects.hash(x, isOdd);
        }
    }

    class P256K1PointInfinity implements P256K1Point {
        private P256K1PointInfinity() {}
    }


    /**
     * An {@link ECPoint} that has been validated to also be a {@code P256K1Point}. This class cannot
     * represent the "point at infinity", if you need it use {@link ECPoint#POINT_INFINITY} and the
     * superclass {@link ECPoint}.
     */
    class P256K1ECPoint extends ECPoint implements P256K1Point.Uncompressed {
        /**
         * Creates an ECPoint from the specified affine x-coordinate
         * {@code x} and affine y-coordinate {@code y}.
         *
         * @param x the affine x-coordinate.
         * @param y the affine y-coordinate.
         * @throws NullPointerException if {@code x} or
         *                              {@code y} is null.
         */
        public P256K1ECPoint(BigInteger x, BigInteger y) {
            super(P256K1FieldElement.checkInRange(x), P256K1FieldElement.checkInRange(y));
        }

        public P256K1ECPoint(P256K1FieldElement x, P256K1FieldElement y) {
            super(x.toBigInteger(), y.toBigInteger());
        }

        @Override
        public P256K1FieldElement x() {
            return P256K1FieldElement.of(super.getAffineX());
        }

        @Override
        public P256K1FieldElement y() {
            return P256K1FieldElement.of(super.getAffineY());
        }

        @Override
        public Compressed compress() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isOdd() {
            return P256K1FieldElement.of(super.getAffineY()).isOdd();
        }
    }
}
