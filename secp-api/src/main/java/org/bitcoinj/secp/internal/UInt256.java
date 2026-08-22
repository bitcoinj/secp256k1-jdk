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

import java.math.BigInteger;

/**
 * Utility methods for handling UInt256 (32-byte unsigned) values.
 * <p>
 * Note that {@link org.bitcoinj.secp.SecpFieldElement} values are a subset of {@code UInt256} because
 * they cannot exceed {@code P-1}.
 */
public interface UInt256 {
    BigInteger MIN_VALUE = BigInteger.ZERO;
    /** The maximum unsigned 32-byte / 256-bit value. ({@code 2^256 - 1}) */
    BigInteger MAX_VALUE = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
    byte[] ZERO_VALUE = new byte[32];

    /**
     * Convert a BigInteger to a 32-byte fixed-length byte array (UInt256).
     * @param i an unsigned BigInteger in the range {@link #MIN_VALUE} to {@link #MAX_VALUE}
     * @return a 32-byte, big-endian unsigned integer value
     * @throws IllegalArgumentException if out of range
     */
    static byte[] to32Bytes(BigInteger i) {
        checkInRange(i);
        byte[] result = new byte[32];
        ByteUtils.copyAsUnsigned32Bytes(i, result, 0);
        return result;
    }

    /**
     * Check if an integer is positive and can be represented in 32 unsigned bytes.
     * @param e A possible field element to validate
     * @return true if valid
     */
    static boolean isInRange(BigInteger e) {
        // For non-negative, bitLength() returns the minimal, unsigned bit length
        return e.signum() >= 0 && e.bitLength() <= 8 * 32;
    }

    /**
     * Throw {@link IllegalArgumentException} if an integer is not in the inclusive range {@link #MIN_VALUE} to {@link #MAX_VALUE}.
     * @param e unvalidated integer
     * @return a validated integer
     */
    static BigInteger checkInRange(BigInteger e) {
        if (!isInRange(e)) {
            throw new IllegalArgumentException("BigInteger is not a valid UInt256: " + e);
        }
        return e;
    }

    static String toString(BigInteger uint256) {
        return String.format("%064X", uint256);
    }

    static String toString(byte[] uint256) {
        return ByteUtils.toHexString(uint256);
    }

    /**
     * Utility to convert unsigned big-endian {@code byte[]} to integer
     * @param bytes bytes
     * @return integer representation of unsigned, big-endian bytes
     */
    static BigInteger toBigInteger(byte[] bytes) {
        // byte[] is unsigned, so `signum` can be 0 or 1: default to 0 then search for nonzero bytes
        int signum = 0;
        for (byte b : bytes) {
            if (b != 0) {
                signum = 1;
                break;
            }
        }
        return new BigInteger(signum, bytes);
    }
}
