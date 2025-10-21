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
package org.bitcoinj.secp;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for P256K1FieldElementTest
 */
public class P256K1FieldElementTest {
    static BigInteger p = Secp256k1.FIELD.getP();
    static List<BigInteger> inRangeFieldInts = List.of(BigInteger.ZERO,BigInteger.ONE, p.subtract(BigInteger.ONE));
    static List<BigInteger> outOfRangeFieldInts =List.of(BigInteger.ONE.negate(), p);

    @FieldSource("inRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testDefaultImplementation(BigInteger n) {
        P256K1FieldElement element = P256K1FieldElement.of(n);
        assertEquals(n, element.toBigInteger());
    }

    @FieldSource("inRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testIsInRange(BigInteger n) {
        assertTrue(P256K1FieldElement.isInRange(n));
    }

    @FieldSource("outOfRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testIsOutOfRange(BigInteger n) {
        assertFalse(P256K1FieldElement.isInRange(n));
    }

    @FieldSource("inRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testCheckInRangeValid(BigInteger n) {
        assertDoesNotThrow(
            () -> P256K1FieldElement.checkInRange(n)
        );
        assertEquals(n, P256K1FieldElement.checkInRange(n));
    }

    @FieldSource("outOfRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testCheckInRangeInvalid(BigInteger n) {
        assertThrows(IllegalArgumentException.class,
            () -> P256K1FieldElement.checkInRange(n)
        );
    }
}
