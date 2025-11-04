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
     * {@code x} and affine y-coordinate {@code y}.
     *
     * @param x the affine x-coordinate.
     * @param y the affine y-coordinate.
     * @throws NullPointerException if {@code x} or
     *                              {@code y} is null.
     */
    public SecpECPoint(BigInteger x, BigInteger y) {
        super(SecpFieldElement.checkInRange(x), SecpFieldElement.checkInRange(y));
    }

    public SecpECPoint(SecpFieldElement x, SecpFieldElement y) {
        super(x.toBigInteger(), y.toBigInteger());
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
    public boolean isOdd() {
        return SecpFieldElement.of(super.getAffineY()).isOdd();
    }
}
