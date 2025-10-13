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
package org.bitcoinj.secp.bitcoinj;

import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.secp.api.SPPubKey;
import org.bitcoinj.secp.api.internal.P256K1ECPoint;
import org.bitcoinj.secp.api.internal.P256K1PointUncompressed;
import org.bouncycastle.crypto.params.ECDomainParameters;

import java.security.spec.ECPoint;

/**
 * Bouncy Castle conversion methods for use in bitcoinj during the secp256k1-jdk conversion process only.
 */
interface BC {
    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    ECDomainParameters BC_CURVE = ECKey.ecDomainParameters();

    static SPPubKey toP256K1PubKey(org.bouncycastle.math.ec.ECPoint bcPoint) {
        if (bcPoint.isInfinity()) { throw new IllegalArgumentException("bcPoint is infinity"); }
        return  SPPubKey.ofPoint(BC.toECPoint(bcPoint));
    }

    static P256K1PointUncompressed toP256K1Point(org.bouncycastle.math.ec.ECPoint bcPoint) {
        if (bcPoint.isInfinity()) { throw new IllegalArgumentException("bcPoint is infinity"); }
        return P256K1PointUncompressed.of(bcPoint.getAffineXCoord().toBigInteger(), bcPoint.getAffineYCoord().toBigInteger());
    }

    static ECPoint toECPoint(org.bouncycastle.math.ec.ECPoint bcPoint) {
        return bcPoint.isInfinity()
                ? ECPoint.POINT_INFINITY
                : new P256K1ECPoint(
                    bcPoint.normalize().getAffineXCoord().toBigInteger(),
                    bcPoint.normalize().getAffineYCoord().toBigInteger());
    }

    static org.bouncycastle.math.ec.ECPoint fromECPoint(ECPoint point) {
        return point == ECPoint.POINT_INFINITY
                ? BC_CURVE.getCurve().getInfinity()
                : BC_CURVE.getCurve().createPoint(point.getAffineX(), point.getAffineY());
    }
}
