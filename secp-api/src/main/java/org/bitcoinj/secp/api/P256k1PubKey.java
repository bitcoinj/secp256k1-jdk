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

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 *
 */
public interface P256k1PubKey extends ECPublicKey {
    @Override
    default String getAlgorithm() {
        return "Secp256k1";
    }

    @Override
    default String getFormat() {
        return "Compressed SEC";
    }

    /**
     * Return key in primary encoded format (compressed)
     * @return public key in compressed format
     */
    @Override
    default byte[] getEncoded() {
        return getCompressed();
    }

    /**
     * Return encoded key in either compressed or uncompressed SEC format.
     * @param compressed Use compressed variant of format
     * @return public key in SEC format
     */
    default byte[] getEncoded(boolean compressed) {
        return compressed
                ? getCompressed()
                : getUncompressed();
    }

    default byte[] getCompressed() {
        ECPoint point = getW();
        byte[] compressed = new byte[33];
        compressed[0] = point.getAffineY().testBit(0)
                ? (byte) 0x03      // odd
                : (byte) 0x02;     // even;
        System.arraycopy(P256K1FieldElement.integerTo32Bytes(point.getAffineX()),
                0,
                compressed,
                1,
                32);
        return compressed;
    }

    default byte[] getUncompressed() {
        ECPoint point = getW();
        byte[] x = P256K1FieldElement.integerTo32Bytes(point.getAffineX());
        byte[] y = P256K1FieldElement.integerTo32Bytes(point.getAffineY());
        byte[] encoded = new byte[65];
        encoded[0] = 0x04;
        System.arraycopy(x, 0, encoded, 1, 32);
        System.arraycopy(y, 0, encoded, 33, 32);
        return encoded;
    }

    default P256K1XOnlyPubKey getXOnly() {
        return P256K1XOnlyPubKey.of(this.getW().getAffineX());
    }

    /**
     * Returns this key as a {@link org.bitcoinj.secp.api.P256K1Point.P256K1ECPoint} or, if it is
     * the "point at infinity" it returns {@link ECPoint#POINT_INFINITY}
     * @return point as {@code ECPoint} or subclass.
     */
    @Override
    ECPoint getW();

    P256K1Point.Uncompressed getPoint();

    @Override
    default ECParameterSpec getParams() {
        return Secp256k1.EC_PARAMS;
    }

    /**
     * Since we can't provide a default implementation of {@link Object#toString()}, we can
     * at least make the default implementation easily available to implementations.
     * @return string representation of the key
     */
    default String toStringDefault() {
        ECPoint point = getW();
        return point.equals(ECPoint.POINT_INFINITY)
                ? "POINT_INFINITY"
                : point.getAffineX().toString(16) + "," + point.getAffineY().toString(16);
    }

}
