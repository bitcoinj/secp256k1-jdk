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
import java.util.Objects;

/**
 *
 */
public
class P256K1PointUncompressed extends P256K1PointImpl implements SPPoint.Uncompressed {
    private final SPFieldElement x;
    private final SPFieldElement y;

    public P256K1PointUncompressed(SPFieldElement x, SPFieldElement y) {
        this.x = x;
        this.y = y;
    }

    public static org.bitcoinj.secp.api.internal.P256K1PointUncompressed of(ECPoint point) {
        return new org.bitcoinj.secp.api.internal.P256K1PointUncompressed(SPFieldElement.of(point.getAffineX()),
                SPFieldElement.of(point.getAffineY()));
    }

    public static org.bitcoinj.secp.api.internal.P256K1PointUncompressed of(BigInteger x, BigInteger y) {
        return new org.bitcoinj.secp.api.internal.P256K1PointUncompressed(SPFieldElement.of(x), SPFieldElement.of(y));
    }

    @Override
    public SPFieldElement x() {
        return x;
    }

    @Override
    public boolean isOdd() {
        return y.isOdd();
    }

    @Override
    public SPFieldElement y() {
        return y;
    }

    // Must be overridden so it can return something that knows how to uncompress itself
    @Override
    public Compressed compress() {
        return new P256K1PointCompressed(x, y);
    }

    public boolean equals(SPPoint other) {
        if (!(other instanceof org.bitcoinj.secp.api.internal.P256K1PointUncompressed)) return false;
        Uncompressed otherUncompressed = (Uncompressed) other;
        return x().equals(otherUncompressed.x()) && y().equals(otherUncompressed.y());
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        org.bitcoinj.secp.api.internal.P256K1PointUncompressed that = (org.bitcoinj.secp.api.internal.P256K1PointUncompressed) o;
        return Objects.equals(x, that.x) && Objects.equals(y, that.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }
}
