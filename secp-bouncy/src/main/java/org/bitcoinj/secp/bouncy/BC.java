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
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.internal.SecpPointUncompressed;
import org.bitcoinj.secp.internal.SecpPubKeyImpl;
import org.bouncycastle.math.ec.ECPoint;

import static org.bitcoinj.secp.bouncy.Bouncy256k1.BC_ECDOMAIN_PARAMS;

/**
 * Bouncy Castle conversion methods
 */
interface BC {

    static SecpPubKey toSecpPubKey(ECPoint bcPoint) {
        if (bcPoint.isInfinity()) { throw new IllegalArgumentException("bcPoint is infinity"); }
        return  new SecpPubKeyImpl(BC.toSecpPoint(bcPoint));
    }

    static SecpPointUncompressed toSecpPoint(ECPoint bcPoint) {
        if (bcPoint.isInfinity()) { throw new IllegalArgumentException("bcPoint is infinity"); }
        return SecpPointUncompressed.of(
                bcPoint.normalize().getAffineXCoord().toBigInteger(),
                bcPoint.normalize().getAffineYCoord().toBigInteger());
    }

    static ECPoint fromSecpPoint(SecpPoint.Uncompressed point) {
        return BC_ECDOMAIN_PARAMS.getCurve().createPoint(point.x().toBigInteger(), point.y().toBigInteger());
    }
}
