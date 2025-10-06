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
package org.bitcoinj.secp.api;

import org.bitcoinj.secp.api.internal.P256K1ECPoint;
import org.bitcoinj.secp.api.internal.P256K1PointUncompressed;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Tests of {@link P256K1Point}
 */
public class P256K1PointTest {
    static BigInteger p = Secp256k1.FIELD.getP();
    static P256K1FieldElement ONE = P256K1FieldElement.of(BigInteger.ONE);
    static P256K1FieldElement MAX = P256K1FieldElement.of(p.subtract(BigInteger.ONE));
    static BigInteger INT_MAX = MAX.toBigInteger();

    @Test
    void testDefaultImpl() {
        P256K1Point.Uncompressed uncompressed = new P256K1PointUncompressed(ONE, MAX);
        assertEquals(ONE, uncompressed.x());
        assertEquals(MAX, uncompressed.y());

        P256K1Point.Compressed compressed = uncompressed.compress();
        assertEquals(ONE, compressed.x());
        assertFalse(compressed.isOdd());
    }

    @Test
    void testECPointSubclass() {
        P256K1ECPoint p = new P256K1ECPoint(ONE, MAX);
        assertEquals(ONE, p.x());
        assertEquals(MAX, p.y());
        assertEquals(BigInteger.ONE, p.getAffineX());
        assertEquals(INT_MAX, p.getAffineY());
    }
}
