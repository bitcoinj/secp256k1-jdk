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
package org.bitcoinj.secp.internal;

import org.bitcoinj.secp.SecpFieldElement;
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
 * Tests for SecpFieldElementImpl
 */
public class P256K1FieldElementImplTest {
    static BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    static List<BigInteger> inRangeFieldInts = List.of(BigInteger.ZERO,BigInteger.ONE, P.subtract(BigInteger.ONE));
    static List<BigInteger> outOfRangeFieldInts = List.of(BigInteger.ONE.negate(), P);

    @FieldSource("inRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testConstructors(BigInteger n) {
        SecpFieldElement element = new SecpFieldElementImpl(n);
        assertEquals(n, element.toBigInteger());
        SecpFieldElement element2 = new SecpFieldElementImpl(UInt256.integerTo32Bytes(n));
        assertEquals(n, element2.toBigInteger());
    }

    @FieldSource("inRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testIsInRange(BigInteger n) {
        assertTrue(SecpFieldElement.isInRange(n));
        assertTrue(SecpFieldElementImpl.isInRange(UInt256.integerTo32Bytes(n)));
    }

    @FieldSource("outOfRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testIsOutOfRange(BigInteger n) {
        assertFalse(SecpFieldElement.isInRange(n));
        if (UInt256.isInRange(n)) {
            // Integer is a valid UInt256, isInRange should report `false`
            byte[] bytes = UInt256.integerTo32Bytes(n);
            assertFalse(SecpFieldElementImpl.isInRange(bytes));
        } else {
            // Integer is not a valid UInt256, attempt to convert should throw
            assertThrows(IllegalArgumentException.class,
                    () -> UInt256.integerTo32Bytes(n)
            );
        }
    }

    @FieldSource("inRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testCheckInRangeValid(BigInteger n) {
        assertDoesNotThrow(
            () -> SecpFieldElement.checkInRange(n)
        );
        assertEquals(n, SecpFieldElement.checkInRange(n));
        byte[] bytes = UInt256.integerTo32Bytes(n);
        assertDoesNotThrow(
                () -> SecpFieldElementImpl.checkInRange(bytes)
        );
        assertEquals(bytes, SecpFieldElementImpl.checkInRange(bytes));
    }

    @FieldSource("outOfRangeFieldInts")
    @ParameterizedTest(name = "n: {0}")
    void testCheckInRangeInvalid(BigInteger n) {
        assertThrows(IllegalArgumentException.class,
            () -> SecpFieldElement.checkInRange(n)
        );
        byte[] bytes = n.toByteArray();
        assertThrows(IllegalArgumentException.class,
                () -> SecpFieldElementImpl.checkInRange(bytes)
        );
    }
}
