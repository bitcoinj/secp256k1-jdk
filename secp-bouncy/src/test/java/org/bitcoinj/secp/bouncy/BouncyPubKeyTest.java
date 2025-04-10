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

import org.junit.jupiter.api.Test;

import java.security.spec.ECPoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 *  Tests for BouncyPubKey.
 */
public class BouncyPubKeyTest {
    org.bouncycastle.math.ec.ECPoint BOUNCY_INFINITY = Bouncy256k1.BC_CURVE.getCurve().getInfinity();
    ECPoint JAVA_INFINITY = ECPoint.POINT_INFINITY;

    @Test
    public void convertRandomPoint() {
        // Create a random JCA ECPoint
        ECPoint point;
        try (Bouncy256k1 secp = new Bouncy256k1()) {
            point = secp.ecPubKeyCreate(secp.ecPrivKeyCreate()).getW();
        }
        assertNotNull(point);
        org.bouncycastle.math.ec.ECPoint bcPoint = new BouncyPubKey(point).getBouncyPoint();

        assertNotNull(bcPoint);
        assertEquals(point.getAffineX(), bcPoint.getAffineXCoord().toBigInteger());
        assertEquals(point.getAffineY(), bcPoint.getAffineYCoord().toBigInteger());
    }

    @Test
    public void infinityConversionTest() {
        BouncyPubKey key1 = new BouncyPubKey(JAVA_INFINITY);
        BouncyPubKey key2 = new BouncyPubKey(BOUNCY_INFINITY);

        assertEquals(key1.getW(), key2.getW());
        assertEquals(JAVA_INFINITY, key1.getW());
        assertEquals(JAVA_INFINITY, key2.getW());
    }
}
