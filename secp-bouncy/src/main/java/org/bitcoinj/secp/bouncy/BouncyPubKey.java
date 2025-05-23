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

import org.bitcoinj.secp.api.P256k1PubKey;

import java.security.spec.ECPoint;

import static org.bitcoinj.secp.bouncy.Bouncy256k1.BC_CURVE;

/**
 * Bouncy Castle implementation of {@link P256k1PubKey}.
 */
public class BouncyPubKey implements P256k1PubKey {
    private final org.bouncycastle.math.ec.ECPoint point;

    public BouncyPubKey(org.bouncycastle.math.ec.ECPoint point) {
        this.point = point;
    }

    public BouncyPubKey(ECPoint javaPoint) {
        this(toBouncy(javaPoint));
    }

    private static ECPoint toJCA(org.bouncycastle.math.ec.ECPoint bcPoint) {
        return bcPoint.isInfinity()
                ? java.security.spec.ECPoint.POINT_INFINITY
                : new java.security.spec.ECPoint(
                    bcPoint.normalize().getAffineXCoord().toBigInteger(),
                    bcPoint.normalize().getAffineYCoord().toBigInteger());
    }

    private static org.bouncycastle.math.ec.ECPoint toBouncy(ECPoint point) {
        return point == ECPoint.POINT_INFINITY
                ? BC_CURVE.getCurve().getInfinity()
                : BC_CURVE.getCurve().createPoint(point.getAffineX(), point.getAffineY());
    }

    private byte[] bytes() {
        byte[] bytes = new byte[64];
        byte[] encoded = getEncoded();  // This has a prefix byte
        System.arraycopy(encoded, 1, bytes, 0, bytes.length); // remove prefix byte
        return bytes;
    }

    @Override
    public byte[] getEncoded() {
        return point.getEncoded(true);        //  default encoding is compressed
    }

    public byte[] getEncoded(boolean compressed) {
        return point.getEncoded(compressed);  // This has a prefix byte
    }

    @Override
    public ECPoint getW() {
        return toJCA(point);
    }

    // Return Bouncy Castle ECPoint type (used by tests)
    org.bouncycastle.math.ec.ECPoint getBouncyPoint() {
        return point;
    }

    @Override
    public String toString() {
        return toStringDefault();
    }

}
