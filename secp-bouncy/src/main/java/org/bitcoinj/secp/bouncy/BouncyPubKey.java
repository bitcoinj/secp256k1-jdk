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
package org.bitcoinj.secp.bouncy;


import org.bitcoinj.secp.api.ByteArray;
import org.bitcoinj.secp.api.P256k1PubKey;
import org.bouncycastle.math.ec.ECPoint;

import static org.bitcoinj.secp.bouncy.Bouncy256k1.BC_CURVE;

/**
 *
 */
public class BouncyPubKey implements P256k1PubKey {
    private final ECPoint point;

    public BouncyPubKey(ECPoint point) {
        this.point = point;
    }

    public BouncyPubKey(java.security.spec.ECPoint javaPoint) {
        this(BC_CURVE.getCurve().createPoint(javaPoint.getAffineX(), javaPoint.getAffineY())) ;
    }

    private byte[] bytes() {
        byte[] bytes = new byte[64];
        byte[] encoded = getEncoded();  // This has a prefix byte
        System.arraycopy(encoded, 1, bytes, 0, bytes.length); // remove prefix byte
        return bytes;
    }

    @Override
    public byte[] getEncoded() {
        return point.getEncoded(false);  // This has a prefix byte
    }

    @Override
    public String toString() {
        return ByteArray.HEX_FORMAT.formatHex(bytes());
    }

    @Override
    public java.security.spec.ECPoint getW() {
        return new java.security.spec.ECPoint(
                point.normalize().getAffineXCoord().toBigInteger(),
                point.normalize().getAffineYCoord().toBigInteger());
    }
}
