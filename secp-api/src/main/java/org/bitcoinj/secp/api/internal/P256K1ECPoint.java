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
package org.bitcoinj.secp.api.internal;

import org.bitcoinj.secp.api.SPFieldElement;
import org.bitcoinj.secp.api.SPPoint;

import java.math.BigInteger;
import java.security.spec.ECPoint;

/**
 * An {@link ECPoint} that has been validated to also be a {@code P256K1Point}. This class cannot
 * represent the "point at infinity", if you need it use {@link ECPoint#POINT_INFINITY} and the
 * superclass {@link ECPoint}.
 */
public class P256K1ECPoint extends ECPoint implements SPPoint.Uncompressed {
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
        super(SPFieldElement.checkInRange(x), SPFieldElement.checkInRange(y));
    }

    public P256K1ECPoint(SPFieldElement x, SPFieldElement y) {
        super(x.toBigInteger(), y.toBigInteger());
    }

    @Override
    public SPFieldElement x() {
        return SPFieldElement.of(super.getAffineX());
    }

    @Override
    public SPFieldElement y() {
        return SPFieldElement.of(super.getAffineY());
    }

    @Override
    public Compressed compress() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isOdd() {
        return SPFieldElement.of(super.getAffineY()).isOdd();
    }
}
