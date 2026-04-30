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

import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpFieldElement;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests comparing Bouncy Castle curve parameters with Secp256k1 curve parameters (some of which use JCA types.)
 * This is a "Rosetta Stone" comparing Secp256k1/JCA parameters with their Bouncy Castle equivalent.
 */
public class BouncyCurveParamsTest {
    @Test
    void curveParamCompare() {
        // "P" = "P"
        assertEquals(Secp256k1.P, Bouncy256k1.BC_CURVE.getCurve().getField().getCharacteristic());
        // "G" = "G"
        assertEquals(Secp256k1.G, BC.toSecpPoint(Bouncy256k1.BC_CURVE.getG()));
        // "Order" = "N"
        assertEquals(Secp256k1.EC_PARAMS.getOrder(), Bouncy256k1.BC_CURVE.getN());
        // HALF_CURVE_ORDER = HALF_CURVE_ORDER
        assertEquals(Secp256k1.HALF_CURVE_ORDER, SecpFieldElement.of(Bouncy256k1.BC_CURVE.getN().shiftRight(1)));
        // "Cofactor" = "H"
        assertEquals(Secp256k1.EC_PARAMS.getCofactor(), Bouncy256k1.BC_CURVE.getH().intValueExact());
        // "A" = "A"
        assertEquals(Secp256k1.CURVE.getA(), Bouncy256k1.BC_CURVE.getCurve().getA().toBigInteger());
        // "B" = "B"
        assertEquals(Secp256k1.CURVE.getB(), Bouncy256k1.BC_CURVE.getCurve().getB().toBigInteger());
    }
}
