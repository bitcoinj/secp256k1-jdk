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
import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.internal.SecpPointUncompressed;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Point;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *  Tests for BouncyPubKey.
 */
public class BouncyPubKeyTest {
    SecP256K1Point BOUNCY_INFINITY = (SecP256K1Point) Bouncy256k1.BC_CURVE.getInfinity();

    @Test
    public void convertRandomPoint() {
        // Create a random SecpPoint
        SecpPoint.Uncompressed point;
        try (Bouncy256k1 secp = new Bouncy256k1()) {
            point = secp.ecPubKeyCreate(secp.ecPrivKeyCreate()).point();
        }
        assertNotNull(point);
        SecP256K1Point bcPoint = (SecP256K1Point) Bouncy256k1.fromSecpPoint(point).normalize();

        assertNotNull(bcPoint);
        assertEquals(point.x().toBigInteger(), bcPoint.getAffineXCoord().toBigInteger());
        assertEquals(point.y().toBigInteger(), bcPoint.getAffineYCoord().toBigInteger());
    }

    @Test
    public void testEquals() {
        SecpPubKeyBc g1 = Bouncy256k1.toSecpPoint(Bouncy256k1.BC_ECDOMAIN_PARAMS.getG());
        assertEquals(Secp256k1.G.x(), g1.x());
        assertEquals(Secp256k1.G.y(), g1.y());

        SecpPubKeyBc g2 = new SecpPubKeyBc(g1.getQ());
        assertEquals(g1, g2);

        SecpPointUncompressed g3 = SecpPointUncompressed.of(g1.x().toBigInteger(), g1.y().toBigInteger());
        assertEquals(g1, g3);   // Test SecpPubKeyBc.equals()
        assertEquals(g3, g1);   // Test SecpPointUncompressed.equals()
    }

    @Test
    public void infinityConversionTest() {
        assertThrows(IllegalArgumentException.class,
                () -> Bouncy256k1.toSecpPubKey(BOUNCY_INFINITY)
        );
    }
}
