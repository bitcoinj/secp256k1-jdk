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

import org.bitcoinj.secp.P256K1FieldElement;
import org.bitcoinj.secp.P256K1Point;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.Objects;

/**
 *
 */
public
class P256K1PointUncompressed extends P256K1PointImpl implements P256K1Point.Uncompressed {
    private final P256K1FieldElement x;
    private final P256K1FieldElement y;

    public P256K1PointUncompressed(P256K1FieldElement x, P256K1FieldElement y) {
        this.x = x;
        this.y = y;
    }

    public static P256K1PointUncompressed of(ECPoint point) {
        return new P256K1PointUncompressed(P256K1FieldElement.of(point.getAffineX()),
                P256K1FieldElement.of(point.getAffineY()));
    }

    public static P256K1PointUncompressed of(BigInteger x, BigInteger y) {
        return new P256K1PointUncompressed(P256K1FieldElement.of(x), P256K1FieldElement.of(y));
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
        if (!(other instanceof org.bitcoinj.secp.internal.P256K1PointUncompressed)) return false;
        Uncompressed otherUncompressed = (Uncompressed) other;
        return x().equals(otherUncompressed.x()) && y().equals(otherUncompressed.y());
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        org.bitcoinj.secp.internal.P256K1PointUncompressed that = (org.bitcoinj.secp.internal.P256K1PointUncompressed) o;
        return Objects.equals(x, that.x) && Objects.equals(y, that.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }

    @Override
    public String toString() {
        return ByteArrayBase.HEX_FORMAT.formatHex(this.serialize());
    }
}
