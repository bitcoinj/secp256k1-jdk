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
package org.bitcoinj.secp.bouncy;

import org.bitcoinj.secp.SecpPoint;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Point;

import static org.bitcoinj.secp.bouncy.Bouncy256k1.BC_CURVE;

/**
 * Bouncy Castle conversion methods
 */
interface BC {

    static SecpPubKeyBc toSecpPubKey(ECPoint bcPoint) {
        return SecpPubKeyBc.of(bcPoint);
    }

    static SecpPubKeyBc toSecpPoint(ECPoint bcPoint) {
        return SecpPubKeyBc.of(bcPoint);
    }

    static SecP256K1Point fromSecpPoint(SecpPoint.Uncompressed point) {
        return point instanceof SecpPubKeyBc
                ? ((SecpPubKeyBc) point).getQ()
                : (SecP256K1Point) BC_CURVE.createPoint(point.x().toBigInteger(), point.y().toBigInteger());
    }
}
