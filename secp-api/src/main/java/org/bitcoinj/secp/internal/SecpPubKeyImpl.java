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

import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpPubKey;

import java.security.spec.ECPoint;

/**
 * Default/Internal SecpPubKey implementation storing as {@link SecpPointUncompressed}.
 */
public class SecpPubKeyImpl implements SecpPubKey {
    private final SecpPointUncompressed point;

    public SecpPubKeyImpl(SecpPointUncompressed point) {
        this.point = point;
    }

    public SecpPubKeyImpl(SecpPoint.Uncompressed point) {
        this.point = new SecpPointUncompressed(point.x(), point.y());
    }

    public SecpPubKeyImpl(SecpECPoint ecPoint) {
        this.point = new SecpPointUncompressed(ecPoint.x(), ecPoint.y());
    }

    public SecpPubKeyImpl(ECPoint ecPoint) {
        this.point = SecpPointUncompressed.of(ecPoint);
    }

    @Override
    public SecpECPoint getW() {
        return new SecpECPoint(point.x(), point.y());
    }

    @Override
    public SecpPoint.Uncompressed point() {
        return point;
    }

    @Override
    public String toString() {
        return ByteArrayBase.toHexString(point.serialize());
    }
}
