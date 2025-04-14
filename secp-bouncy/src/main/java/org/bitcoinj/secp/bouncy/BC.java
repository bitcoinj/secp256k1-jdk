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

import org.bitcoinj.secp.api.P256K1Point;

import java.security.spec.ECPoint;

import static org.bitcoinj.secp.bouncy.Bouncy256k1.BC_CURVE;

/**
 * Bouncy Castle conversion methods
 */
public interface BC {
    static ECPoint toECPoint(org.bouncycastle.math.ec.ECPoint bcPoint) {
        return bcPoint.isInfinity()
                ? ECPoint.POINT_INFINITY
                : new P256K1Point.P256K1ECPoint(
                    bcPoint.normalize().getAffineXCoord().toBigInteger(),
                    bcPoint.normalize().getAffineYCoord().toBigInteger());
    }

    static org.bouncycastle.math.ec.ECPoint fromECPoint(ECPoint point) {
        return point == ECPoint.POINT_INFINITY
                ? BC_CURVE.getCurve().getInfinity()
                : BC_CURVE.getCurve().createPoint(point.getAffineX(), point.getAffineY());
    }
}
