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
package org.bitcoinj.secp;

import org.bitcoinj.secp.internal.SecpECPoint;
import org.bitcoinj.secp.internal.SecpPointUncompressed;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.bitcoinj.secp.Secp256k1.G;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Tests of {@link SecpPoint}
 */
public class P256K1PointTest {
    static BigInteger p = Secp256k1.P;

    @Test
    void testDefaultImpl() {
        SecpPoint.Uncompressed uncompressed = new SecpPointUncompressed(G.x(), G.y());
        assertEquals(G.x(), uncompressed.x());
        assertEquals(G.y(), uncompressed.y());

        SecpPoint.Compressed compressed = uncompressed.compress();
        assertEquals(G.x(), compressed.x());
        assertFalse(compressed.isOdd());
    }

    @Test
    void testECPointSubclass() {
        SecpECPoint p = SecpECPoint.of(G);
        assertEquals(G.x(), p.x());
        assertEquals(G.y(), p.y());
        assertEquals(G.x().toBigInteger(), p.getAffineX());
        assertEquals(G.y().toBigInteger(), p.getAffineY());
    }
}
