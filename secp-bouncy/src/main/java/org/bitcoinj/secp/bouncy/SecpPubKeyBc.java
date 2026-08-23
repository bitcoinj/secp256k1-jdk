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
package org.bitcoinj.secp.bouncy;

import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.internal.SecpECPoint;
import org.bitcoinj.secp.internal.SecpPointCompressed;
import org.bitcoinj.secp.internal.UInt256;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Point;
import org.jspecify.annotations.Nullable;

import java.security.spec.ECPoint;
import java.util.Objects;

/**
 * Bouncy Castle implementation of SecpPubKey using {@link SecP256K1Point}.
 */
class SecpPubKeyBc implements SecpPubKey {
    private final SecP256K1Point bcPoint;

    SecpPubKeyBc(SecP256K1Point bcPoint) {
        this.bcPoint = bcPoint;
    }

    static SecpPubKeyBc of(org.bouncycastle.math.ec.ECPoint bcPoint) {
        if (bcPoint.isInfinity()) { throw new IllegalArgumentException("bcPoint is infinity"); }
        if (bcPoint instanceof SecP256K1Point) {
            return new SecpPubKeyBc((SecP256K1Point) bcPoint);
        } else {
            throw new IllegalArgumentException("point must be SecP256K1Point");
        }
    }

    @Override
    public ECPoint getW() {
        org.bouncycastle.math.ec.ECPoint normalized = bcPoint.normalize();
        return SecpECPoint.of(normalized.getAffineXCoord().toBigInteger(), normalized.getAffineYCoord().toBigInteger());
    }

    /**
     * Return Bouncy Castle native secp256k1 point
     * @return secp256k1 point
     */
    SecP256K1Point getQ() {
        return bcPoint;
    }

    @Override
    public Uncompressed point() {
        return this;
    }

    @Override
    public SecpFieldElement x() {
        org.bouncycastle.math.ec.ECPoint normalized = bcPoint.normalize();
        return SecpFieldElement.of(normalized.getAffineXCoord().getEncoded());
    }

    @Override
    public SecpFieldElement y() {
        org.bouncycastle.math.ec.ECPoint normalized = bcPoint.normalize();
        return SecpFieldElement.of(normalized.getAffineYCoord().getEncoded());
    }

    @Override
    public Compressed compress() {
        return new SecpPointCompressed(x(), y());
    }

    @Override
    public String getFormat() {
        return COMPRESSED_FORMAT_NAME;
    }

    @Override
    public byte[] serialize(boolean compressed) {
        return compressed
                ? SecpPubKeyBc.serializeCompressed(bcPoint)
                : serializeUncompressed(bcPoint);
    }

    /**
     * {@inheritDoc}
     * Note: Public Keys are stored uncompressed, but their default serialization is compressed.
     * @return
     */
    @Override
    public byte[] serialize() {
        return serializeCompressed(bcPoint);
    }

    static byte[] serializeUncompressed(SecP256K1Point bcPoint) {
        org.bouncycastle.math.ec.ECPoint norm = bcPoint.normalize();
        return SecpPoint.serializeUncompressed(norm.getAffineXCoord().getEncoded(), norm.getAffineYCoord().getEncoded());
    }

    static byte[] serializeCompressed(SecP256K1Point bcPoint) {
        org.bouncycastle.math.ec.ECPoint norm = bcPoint.normalize();
        return SecpPoint.serializeCompressed(norm.getAffineXCoord().getEncoded(), isOdd(norm));
    }

    @Override
    public boolean isOdd() {
        return SecpPubKeyBc.isOdd(bcPoint.normalize());
    }

    private static boolean isOdd(org.bouncycastle.math.ec.ECPoint normalizePoint) {
        return normalizePoint.getAffineYCoord().testBitZero();
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (!(o instanceof SecpPoint.Uncompressed)) return false;
        if (o instanceof SecpPubKeyBc) {
            SecpPubKeyBc other = (SecpPubKeyBc) o;
            return bcPoint.equals(other.bcPoint);
        } else {
            SecpPoint.Uncompressed other = (SecpPoint.Uncompressed) o;
            org.bouncycastle.math.ec.ECPoint norm = bcPoint.normalize();
            return Objects.equals(norm.getAffineXCoord().toBigInteger(), other.x().toBigInteger()) &&
                    Objects.equals(norm.getAffineYCoord().toBigInteger(), other.y().toBigInteger());
        }
    }

    @Override
    public int hashCode() {
        org.bouncycastle.math.ec.ECPoint norm = bcPoint.normalize();
        return Objects.hash(norm.getAffineXCoord(), norm.getAffineYCoord());
    }

    @Override
    public String toString() {
        return UInt256.toHexString(this.serialize());
    }
}
