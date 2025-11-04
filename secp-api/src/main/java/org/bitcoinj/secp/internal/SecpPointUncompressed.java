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
import java.util.Objects;

/**
 *
 */
public
class SecpPointUncompressed extends SecpPointImpl implements SecpPoint.Uncompressed {
    private final SecpFieldElement x;
    private final SecpFieldElement y;

    public SecpPointUncompressed(SecpFieldElement x, SecpFieldElement y) {
        this.x = x;
        this.y = y;
    }

    public static SecpPointUncompressed of(ECPoint point) {
        return new SecpPointUncompressed(SecpFieldElement.of(point.getAffineX()),
                SecpFieldElement.of(point.getAffineY()));
    }

    public static SecpPointUncompressed of(BigInteger x, BigInteger y) {
        return new SecpPointUncompressed(SecpFieldElement.of(x), SecpFieldElement.of(y));
    }

    @Override
    public SecpFieldElement x() {
        return x;
    }

    @Override
    public boolean isOdd() {
        return y.isOdd();
    }

    @Override
    public SecpFieldElement y() {
        return y;
    }

    // Must be overridden so it can return something that knows how to uncompress itself
    @Override
    public Compressed compress() {
        return new SecpPointCompressed(x, y);
    }

    public boolean equals(SecpPoint other) {
        if (!(other instanceof SecpPointUncompressed)) return false;
        Uncompressed otherUncompressed = (Uncompressed) other;
        return x().equals(otherUncompressed.x()) && y().equals(otherUncompressed.y());
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        SecpPointUncompressed that = (SecpPointUncompressed) o;
        return Objects.equals(x, that.x) && Objects.equals(y, that.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }

    @Override
    public String toString() {
        return ByteArrayBase.toHexString(this.serialize());
    }
}
