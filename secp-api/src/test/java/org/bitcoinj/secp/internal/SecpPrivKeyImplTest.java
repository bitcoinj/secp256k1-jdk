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

import org.bitcoinj.secp.SecpScalar;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import java.math.BigInteger;
import java.util.List;

import static org.bitcoinj.secp.Secp256k1.N;
import static org.bitcoinj.secp.Secp256k1.P;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SecpPrivKeyImplTest {
    static List<BigInteger> inRangeScalarInts = List.of(BigInteger.ONE, N.subtract(BigInteger.ONE));
    static List<BigInteger> outOfRangeScalarInts = List.of(BigInteger.ONE.negate(), BigInteger.ZERO, N, P);

    @FieldSource("inRangeScalarInts")
    @ParameterizedTest(name = "n: {0}")
    void testIsInRange(BigInteger n) {
        assertTrue(SecpScalar.isInRange(n));
        assertTrue(SecpScalarImpl.isInRange(UInt256.integerTo32Bytes(n)));
    }

    @FieldSource("outOfRangeScalarInts")
    @ParameterizedTest(name = "n: {0}")
    void testIsOutOfRange(BigInteger n) {
        assertFalse(SecpScalar.isInRange(n));
        if (UInt256.isInRange(n)) {
            // Integer is a valid UInt256, isInRange should report `false`
            byte[] bytes = UInt256.integerTo32Bytes(n);
            assertFalse(SecpScalarImpl.isInRange(bytes));
        } else {
            // Integer is not a valid UInt256, attempt to convert should throw
            assertThrows(IllegalArgumentException.class,
                    () -> UInt256.integerTo32Bytes(n)
            );
        }
    }

    @FieldSource("inRangeScalarInts")
    @ParameterizedTest(name = "n: {0}")
    void testCheckInRangeValid(BigInteger n) {
        assertDoesNotThrow(
                () -> SecpScalar.checkInRange(n)
        );
        assertEquals(n, SecpScalar.checkInRange(n));
        byte[] bytes = UInt256.integerTo32Bytes(n);
        assertDoesNotThrow(
                () -> SecpScalarImpl.checkInRange(bytes)
        );
        assertEquals(bytes, SecpScalarImpl.checkInRange(bytes));
    }

    @FieldSource("outOfRangeScalarInts")
    @ParameterizedTest(name = "n: {0}")
    void testCheckInRangeInvalid(BigInteger n) {
        assertThrows(IllegalArgumentException.class,
                () -> SecpScalar.checkInRange(n)
        );
        byte[] bytes = n.toByteArray();
        assertThrows(IllegalArgumentException.class,
                () -> SecpScalarImpl.checkInRange(bytes)
        );
    }
}
