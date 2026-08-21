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

import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpPubKey;

/**
 * Default/Internal SecpPubKey implementation storing as {@link SecpPointUncompressed}.
 */
public class SecpPubKeyImpl implements SecpPubKey {
    private final SecpPointUncompressed point;

    public SecpPubKeyImpl(SecpPointUncompressed point) {
        this.point = point;
    }

    public SecpPubKeyImpl(SecpPoint.Uncompressed point) {
        this.point = (point instanceof SecpPointUncompressed)
                ? (SecpPointUncompressed) point
                : new SecpPointUncompressed(point.x(), point.y());
    }

    // TODO: Add support for uncompressed format (for P2PKH non-HD keys)
    /**
     * Return default encoding (serialization) format. This implements the {@link java.security.Key} interface.
     * @return string indicating format
     */
    @Override
    public String getFormat() {
        return COMPRESSED_FORMAT_NAME;
    }

    @Override
    public SecpECPoint getW() {
        return SecpECPoint.of(point);
    }

    @Override
    public SecpPoint.Uncompressed point() {
        return point;
    }

    @Override
    public byte[] serialize(boolean compressed) {
        return point.serialize(compressed);
    }

    @Override
    public String toString() {
        return ByteUtils.toHexString(serialize(true));
    }

    @Override
    public SecpFieldElement y() {
        return point.y();
    }

    @Override
    public Compressed compress() {
        return point.compress();
    }

    @Override
    public SecpFieldElement x() {
        return point.x();
    }

    @Override
    public boolean isOdd() {
        return point.isOdd();
    }
}
