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
package org.bitcoinj.secp.internal;

import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpPoint;

import java.math.BigInteger;
import java.security.spec.ECPoint;

/**
 * An {@link ECPoint} that has been validated to also be a {@code SecpPoint}. This class cannot
 * represent the "point at infinity", if you need it use {@link ECPoint#POINT_INFINITY} and the
 * superclass {@link ECPoint}.
 */
public class SecpECPoint extends ECPoint implements SecpPoint.Uncompressed {
    /**
     * Creates an ECPoint from the specified affine x-coordinate
     * {@code x} and affine y-coordinate {@code y}. Constructor is private,
     * and {@link SecpECPoint#of(Uncompressed)} only allows validated points.
     *
     * @param x the affine x-coordinate.
     * @param y the affine y-coordinate.
     * @throws NullPointerException if {@code x} or
     *                              {@code y} is null.
     */
    private SecpECPoint(BigInteger x, BigInteger y) {
        super(x, y);
    }

    public static SecpECPoint of(SecpPoint.Uncompressed point) {
        return new SecpECPoint(point.x().toBigInteger(), point.y().toBigInteger());
    }

    // Unvalidated, assumes caller has validated the point.
    // We should have implementation-specific versions/subclasses of this type (make it abstract)
    public static SecpECPoint of(BigInteger x, BigInteger y) {
        return new SecpECPoint(x, y);
    }

    @Override
    public SecpFieldElement x() {
        return SecpFieldElement.of(super.getAffineX());
    }

    @Override
    public SecpFieldElement y() {
        return SecpFieldElement.of(super.getAffineY());
    }

    @Override
    public Compressed compress() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] serialize(boolean compressed) {
        return compressed
                ? SecpPoint.serializeUncompressed(UInt256.to32Bytes(getAffineX()), UInt256.to32Bytes(getAffineY()))
                : SecpPoint.serializeCompressed(UInt256.to32Bytes(getAffineX()), isOdd());
    }

    @Override
    public boolean isOdd() {
        return getAffineY().testBit(0);
    }
}
