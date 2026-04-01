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

import org.bitcoinj.secp.internal.SecpFieldElementImpl;

import java.math.BigInteger;

/**
 * A number that is a valid element of the P256K1 field. We use this instead of {@link BigInteger}
 * so we can use a fixed-length, unsigned representation for simplicity and performance.
 */
public interface SecpFieldElement {

    /**
     * Get the field element as a {@code BigInteger}
     * @return field element value
     */
    BigInteger toBigInteger();

    /**
     * Get serialized field element (32 bytes unsigned)
     * @return serialized field element
     */
    byte[] serialize();

    /**
     * Get the parity of the field value
     * @return {@code true} if odd, {@code false} if even
     */
    boolean isOdd();

    /**
     * Construct a {@code SecpFieldElement} from a BigInteger
     * @param i integer
     * @return valid element
     */
    static SecpFieldElement of(BigInteger i) {
        return new SecpFieldElementImpl(i);
    }

    /**
     * Construct a field element from a byte-array of 32 bytes
     * @param bytes array containing a valid field element
     * @return field element
     */
    static SecpFieldElement of(byte[] bytes) {
        return new SecpFieldElementImpl(bytes);
    }

    // TODO: Constant-time implementation?
    /**
     * Check if an integer is in the inclusive range {@code 0} to {@code P - 1}, where {@code P} is
     * the prime of the SECG P256K1 prime finite field.
     * @param e A possible field element to validate
     * @return true if valid
     */
    static boolean isInRange(BigInteger e) {
        return e.signum() >= 0 && e.compareTo(Secp256k1.P) < 0;
    }

    /**
     * Throw {@link IllegalArgumentException} if an integer is not in the inclusive range {@code 0} to {@code P - 1}, where {@code P} is
     * the prime of the SECP256K1 prime finite field.
     * @param e unvalidated integer
     * @return a validated integer
     */
    static BigInteger checkInRange(BigInteger e) {
        if (!isInRange(e)) {
            throw new IllegalArgumentException("BigInteger is not a valid SecpFieldElement: " + e);
        }
        return e;
    }
}
