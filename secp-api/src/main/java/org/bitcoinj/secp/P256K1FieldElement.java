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

import org.bitcoinj.secp.internal.P256K1FieldElementImpl;

import java.math.BigInteger;

/**
 * A number that is a valid element of the P256K1 field. We use this instead of {@link BigInteger}
 * so we can use a fixed-length, unsigned representation for simplicity and performance.
 */
public interface P256K1FieldElement {

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
     * Construct a {@code P256K1FieldElement} from a BigInteger
     * @param i integer
     * @return valid element
     */
    static P256K1FieldElement of(BigInteger i) {
        return new P256K1FieldElementImpl(i);
    }

    /**
     * Construct a field element from a byte-array of 32 bytes
     * @param bytes array containing a valid field element
     * @return field element
     */
    static P256K1FieldElement of(byte[] bytes) {
        return new P256K1FieldElementImpl(bytes);
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
            throw new IllegalArgumentException("BigInteger is not a valid P256K1FieldElement: " + e);
        }
        return e;
    }

    // TODO: Full-validation (i.e. check for < P), constant-time implementation?
    /**
     * Throw {@link IllegalArgumentException} if the byte array is not the length.
     * <p>
     * <b>NOTE:</b> We are not currently validating for value less than {@code P}
     * @param e unvalidated integer
     * @return a validated integer
     */
    static byte[] checkInRange(byte[] e) {
        if (e.length != 32) {
            throw new IllegalArgumentException("P256K1FieldElement must have 32 bytes, found : " + e.length);
        }
        return e;
    }

    /**
     * Convert a BigInteger to a fixed-length byte array
     * @param i an unsigned BigInteger containing a valid Secp256k1 field value
     * @return a 32-byte, big-endian unsigned integer value
     */
    static byte[] integerTo32Bytes(BigInteger i) {
        checkInRange(i);
        byte[] minBytes = i.toByteArray(); // return minimum, signed bytes
        // Since toByteArray() returns a sign bit (even though we know there isn't one) and a variable
        // length result, we need to convert to fixed 32-byte length with no sign bit.
        byte[] result = new byte[32];
        System.arraycopy(minBytes,                                  // src
                minBytes.length == 33 ? 1 : 0,                      // src pos (skip sign byte if present)
                result,                                             // dest
                minBytes.length == 33 ? 0 : 32 - minBytes.length,   // dest pos
                minBytes.length == 33 ? 32 : minBytes.length);      // num bytes to copy
        return result;
    }
}
