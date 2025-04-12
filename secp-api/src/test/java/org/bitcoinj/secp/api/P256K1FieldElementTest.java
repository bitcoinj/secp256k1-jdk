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

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

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

    @Test
    void testIsInRange() {
        // Less than zero is not in range
        assertFalse(P256K1FieldElement.isInRange(BigInteger.ONE.negate()));

        // Zero to p - 1 is in range
        assertTrue(P256K1FieldElement.isInRange(BigInteger.ZERO));
        assertTrue(P256K1FieldElement.isInRange(BigInteger.ONE));
        assertTrue(P256K1FieldElement.isInRange(p.subtract(BigInteger.ONE)));

        // p or greater is out of range
        assertFalse(P256K1FieldElement.isInRange(p));
    }

    @Test
    void testCheckInRangeValid() {
        assertDoesNotThrow(
            () -> P256K1FieldElement.checkInRange(BigInteger.ONE)
        );
    }

    @Test
    void testCheckInRangeInvalid() {
        assertThrows(IllegalArgumentException.class,
            () -> P256K1FieldElement.checkInRange(p)
        );
    }
}
