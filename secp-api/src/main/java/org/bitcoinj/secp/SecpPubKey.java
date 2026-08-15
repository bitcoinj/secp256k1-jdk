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
package org.bitcoinj.secp;

import org.bitcoinj.secp.internal.SecpECPoint;
import org.bitcoinj.secp.internal.SecpXOnlyPubKeyImpl;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * A valid secp256k1 Public Key that is a subclass of {@link ECPublicKey}.
 */
public interface SecpPubKey extends ECPublicKey, SecpPoint.Uncompressed {
    /** The format name returned by {@link ECPublicKey#getFormat()} for compressed keys (the default) */
    String COMPRESSED_FORMAT_NAME = "Compressed SEC";
    /** The format name returned by {@link ECPublicKey#getFormat()} for uncompressed keys (typically non-HD {@code P2PKH} keys) */
    String UNCOMPRESSED_FORMAT_NAME = "Uncompressed SEC";

    /**
     * Return associated cryptographic algorithm. This implements the {@link java.security.Key} interface.
     * @return string indicating algorithm
     */
    @Override
    default String getAlgorithm() {
        return Secp256k1.ALGORITHM_NAME;
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
                ? point().compress().serialize()
                : point().serialize();
    }

    /**
     * Return as a compressed point
     * @return compressed point
     */
    @Deprecated(forRemoval = true)
    default SecpPoint.Compressed getCompressed() {
        return point().compress();
    }

    /**
     * Return as an uncompressed point
     * @return uncompressed point
     */
    @Deprecated(forRemoval = true)
    default SecpPoint.Uncompressed getUncompressed() {
        return point();
    }

    /**
     * Return the x-only public key.
     * @return x-only pubkey
     */
    default SecpXOnlyPubKey xOnly() {
        return new SecpXOnlyPubKeyImpl(this.point().x());
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
}
