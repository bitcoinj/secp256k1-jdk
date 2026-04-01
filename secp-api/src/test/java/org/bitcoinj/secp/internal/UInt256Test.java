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
package org.bitcoinj.secp.internal;

import org.junit.jupiter.api.Assertions;
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
 * Tests for UInt256Test
 */
public class UInt256Test {
    static BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    static List<BigInteger> inRangeInts = List.of(
            BigInteger.ZERO,
            BigInteger.ONE,
            P.subtract(BigInteger.ONE),
            P,
            UInt256.MAX_VALUE);
    static List<BigInteger> outOfRangeInts = List.of(
            BigInteger.ONE.negate(),
            UInt256.MAX_VALUE.add(BigInteger.ONE));

    @FieldSource("inRangeInts")
    @ParameterizedTest(name = "n: {0}")
    void testIsInRange(BigInteger n) {
        assertTrue(UInt256.isInRange(n));
    }

    @FieldSource("outOfRangeInts")
    @ParameterizedTest(name = "n: {0}")
    void testIsOutOfRange(BigInteger n) {
        assertFalse(UInt256.isInRange(n));
    }

    @FieldSource("inRangeInts")
    @ParameterizedTest(name = "n: {0}")
    void testCheckInRangeValid(BigInteger n) {
        assertDoesNotThrow(
            () -> UInt256.checkInRange(n)
        );
        assertEquals(n, UInt256.checkInRange(n));
    }

    @FieldSource("outOfRangeInts")
    @ParameterizedTest(name = "n: {0}")
    void testCheckInRangeInvalid(BigInteger n) {
        assertThrows(IllegalArgumentException.class,
            () -> UInt256.checkInRange(n)
        );
    }
}
