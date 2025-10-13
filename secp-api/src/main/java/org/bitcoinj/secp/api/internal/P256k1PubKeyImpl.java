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

import org.bitcoinj.secp.api.P256K1Point;
import org.bitcoinj.secp.api.P256k1PubKey;

import java.security.spec.ECPoint;

/**
 * Default/Internal P256k1PubKey implementation storing as {@link ECPoint}.
 */
public class P256k1PubKeyImpl implements P256k1PubKey {
    private final ECPoint point;

    public P256k1PubKeyImpl(P256K1Point.Uncompressed point) {
        this(new P256K1ECPoint(point.x(), point.y()));
    }

    public P256k1PubKeyImpl(P256K1ECPoint ecPoint) {
        point = ecPoint;
    }

    public P256k1PubKeyImpl(ECPoint ecPoint) {
        point = ecPoint;
    }

    @Override
    public ECPoint getW() {
        return point;
    }

    @Override
    public P256K1Point.Uncompressed point() {
        return P256K1PointUncompressed.of(getW());
    }

    @Override
    public String toString() {
        return toStringDefault();
    }
}
