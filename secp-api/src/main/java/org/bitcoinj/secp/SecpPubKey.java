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

import org.bitcoinj.secp.internal.SecpECPoint;
import org.bitcoinj.secp.internal.SecpPubKeyImpl;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * A valid secp256k1 Public Key that is a subclass of {@link ECPublicKey}
 */
public interface SecpPubKey extends ECPublicKey {
    /**
     * Return associated cryptographic algorithm. This implements the {@link java.security.Key} interface.
     * @return string indicating algorithm
     */
    @Override
    default String getAlgorithm() {
        return "Secp256k1";
    }

    /**
     * Return default encoding (serialization) format. This implements the {@link java.security.Key} interface.
     * @return string indicating format
     */
    @Override
    default String getFormat() {
        return "Compressed SEC";
    }

    /**
     * Return serialized key. This implements the {@link java.security.Key} interface and is an alias for {@link #serialize()}.
     * @return public key in compressed format
     */
    @Override
    default byte[] getEncoded() {
        return serialize();
    }

    /**
     * Serialize key in primary encoded format (compressed)
     * @return public key in compressed format
     */
    default byte[] serialize() {
        return serialize(true);
    }

    /**
     * Return encoded key in either compressed or uncompressed SEC format.
     * @param compressed Use compressed variant of format
     * @return public key in SEC format
     */
    default byte[] serialize(boolean compressed) {
        return compressed
                ? getCompressed().serialize()
                : getUncompressed().serialize();
    }

    /**
     * Return as a compressed point
     * @return compressed point
     */
    default SecpPoint.Compressed getCompressed() {
        return point().compress();
    }

    /**
     * Return as an uncompressed point
     * @return uncompressed point
     */
    default SecpPoint.Uncompressed getUncompressed() {
        return point();
    }

    /**
     * Return the x-only public key.
     * @return x-only pubkey
     */
    default SecpXOnlyPubKey xOnly() {
        return SecpXOnlyPubKey.of(this.getW().getAffineX());
    }

    /**
     * Returns this key as a {@link SecpECPoint} or, if it is
     * the "point at infinity" it returns {@link ECPoint#POINT_INFINITY}
     * @return point as {@code ECPoint} or subclass.
     */
    @Override
    ECPoint getW();

    /**
     * Get the uncompressed {@link SecpPoint}
     * @return point
     */
    SecpPoint.Uncompressed point();

    /**
     * Get the Elliptic Curve parameters
     * @return the parameter spec
     */
    @Override
    default ECParameterSpec getParams() {
        return Secp256k1.EC_PARAMS;
    }

    /**
     * Construct a public key from an {@link ECPoint}
     * @param ecPoint the point
     * @return the pubkey
     */
    static SecpPubKey ofPoint(ECPoint ecPoint) {
        return new SecpPubKeyImpl(ecPoint);
    }

    /**
     * Construct a public key from an {@link SecpPoint.Uncompressed}
     * @param point the point
     * @return the pubkey
     */
    static SecpPubKey ofPoint(SecpPoint.Uncompressed point) {
        return new SecpPubKeyImpl(point);
    }
}
