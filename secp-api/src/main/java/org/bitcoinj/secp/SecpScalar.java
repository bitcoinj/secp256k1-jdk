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

import java.math.BigInteger;

public interface SecpScalar {
    BigInteger MIN_VALUE = BigInteger.ONE;
    BigInteger MAX_VALUE = Secp256k1.N.subtract(BigInteger.ONE);

    /**
     * Get the scalar as a {@code BigInteger}
     * @return scalar value
     */
    BigInteger toBigInteger();

    /**
     * Check if an integer is in the inclusive range {@code 1} to {@code N - 1}, where {@code N} is
     * the order of the SECG P256K1 generator point.
     *
     * @param e A possible scalar to validate
     * @return true if valid
     */
    static boolean isInRange(BigInteger e) {
        return e.signum() > 0 && e.compareTo(MAX_VALUE) <= 0;
    }

    /**
     * Throw {@link IllegalArgumentException} if an integer is not in the inclusive range {@code 1} to {@code N - 1}, where {@code N} is
     * the order of the SECG P256K1 generator point.
     *
     * @param e unvalidated integer
     * @return a validated integer
     */
    static BigInteger checkInRange(BigInteger e) {
        if (!isInRange(e)) {
            throw new IllegalArgumentException("BigInteger is not a valid SecpScalar: " + e);
        }
        return e;
    }

    byte[] serialize();
}
