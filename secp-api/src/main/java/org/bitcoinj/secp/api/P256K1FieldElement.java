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

import java.math.BigInteger;

/**
 * Interface for numbers that are valid elements of the P256K1 field
 */
public interface P256K1FieldElement {
    /**
     * Check if an integer is in the inclusive range {@code 0} to {@code P - 1}, where {@code P} is
     * the prime of the SECP256K1 prime finite field.
     * @param x A possible field element to validate
     * @return true if valid
     */
    static boolean isInRange(BigInteger x) {
        return x.signum() >= 0 && x.compareTo(Secp256k1.FIELD.getP()) < 0;
    }

    /**
     * Convert a BigInteger to a fixed-length byte array
     * @param i an unsigned BigInteger containing a valid Secp256k1 field value
     * @return a 32-byte, big-endian unsigned integer value
     */
    static byte[] integerTo32Bytes(BigInteger i) {
        // TODO: Check for negative or greater than p?
        byte[] minBytes = i.toByteArray(); // return minimum, signed bytes
        if (minBytes.length > 33) throw new IllegalStateException("privKey BigInteger value too large");
        // Convert from signed, variable length to unsigned, fixed 32-byte length.
        byte[] result = new byte[32];
        System.arraycopy(minBytes,                                  // src
                minBytes.length == 33 ? 1 : 0,                      // src pos (skip sign byte if present)
                result,                                             // dest
                minBytes.length == 33 ? 0 : 32 - minBytes.length,   // dest pos
                minBytes.length == 33 ? 32 : minBytes.length);      // num bytes to copy
        return result;
    }
}
