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

import org.bitcoinj.secp.SecpScalar;

import java.math.BigInteger;
import java.security.MessageDigest;

public class SecpScalarImpl implements SecpScalar {
    static final byte[] MAX_VALUE_BYTES = integerTo32Bytes(MAX_VALUE);

    /** scalar value as a 32-byte big-endian byte array */
    private final byte[] value;

    public SecpScalarImpl(byte[] bytes) {
        value = checkInRange(bytes);
    }

    public SecpScalarImpl(BigInteger i) {
        value = SecpScalarImpl.integerTo32Bytes(i);
    }

    @Override
    public BigInteger toBigInteger() {
        return ByteArray.toInteger(value);
    }

    @Override
    public byte[] serialize() {
        return value.clone();
    }

    static boolean isInRange(byte[] e) {
        if (e.length != 32) {
            throw new IllegalArgumentException("SecpScalar must have 32 bytes, found : " + e.length);
        }
        return !MessageDigest.isEqual(e, UInt256.ZERO_VALUE) && ByteUtils.compareUnsigned(e, MAX_VALUE_BYTES) <= 0;
    }

    // TODO: constant-time implementation?
    /**
     * Throw {@link IllegalArgumentException} if the byte array is not the length.
     * <p>
     * <b>NOTE:</b> We are not currently validating for value less than {@code N}
     * @param e unvalidated integer ({@code byte[]} format)
     * @return a validated integer ({@code byte[]} format)
     */
    static byte[] checkInRange(byte[] e) {
        if (e.length != 32) {
            throw new IllegalArgumentException("SecpScalar must have 32 bytes, found : " + e.length);
        }
        if (!isInRange(e)) {
            throw new IllegalArgumentException("byte[] is not a valid SecpScalar: " + ByteUtils.toHexString(e));
        }
        return e;
    }

    /**
     * Convert a BigInteger to a fixed-length byte array verifying it's a valid P256k1 scalar.
     * @param i an unsigned BigInteger containing a valid Secp256k1 scalar value
     * @return a 32-byte, big-endian, unsigned, in-range integer value
     */
    public static byte[] integerTo32Bytes(BigInteger i) {
        return UInt256.integerTo32Bytes(SecpScalar.checkInRange(i));
    }
}
