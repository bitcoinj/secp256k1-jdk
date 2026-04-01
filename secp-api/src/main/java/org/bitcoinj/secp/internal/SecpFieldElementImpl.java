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

import org.bitcoinj.secp.ByteArray;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpFieldElement;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 *
 */
public class SecpFieldElementImpl implements SecpFieldElement, ByteArray {
    static byte[] MAX_VALUE_BYTES = integerTo32Bytes(Secp256k1.P.subtract(BigInteger.ONE));
    private final byte[] value;

    public SecpFieldElementImpl(BigInteger i) {
        value = SecpFieldElementImpl.integerTo32Bytes(SecpFieldElement.checkInRange(i));
    }

    public SecpFieldElementImpl(byte[] bytes) {
        value = SecpFieldElementImpl.checkInRange(bytes);
    }

    @Override
    public BigInteger toBigInteger() {
        return ByteArray.toInteger(value);
    }

    @Override
    public byte[] serialize() {
        return value.clone();
    }

    @Override
    public boolean isOdd() {
        return ByteArray.toInteger(value).mod(BigInteger.TWO).equals(BigInteger.ONE);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        SecpFieldElementImpl that = (SecpFieldElementImpl) o;
        return Objects.deepEquals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public byte[] bytes() {
        return value.clone();
    }

    @Override
    public String toString() {
        return formatHex();
    }

    /**
     * Convert a BigInteger to a fixed-length byte array
     * @param i an unsigned BigInteger containing a valid Secp256k1 field value
     * @return a 32-byte, big-endian unsigned integer value
     */
    public static byte[] integerTo32Bytes(BigInteger i) {
        return UInt256.integerTo32Bytes(SecpFieldElement.checkInRange(i));
    }

    static boolean isInRange(byte[] e) {
        if (e.length != 32) {
            throw new IllegalArgumentException("SecpFieldElement must have 32 bytes, found : " + e.length);
        }
        return ByteUtils.arrayUnsignedComparator().compare(e, SecpFieldElementImpl.MAX_VALUE_BYTES) <= 0;
    }

    // TODO: constant-time implementation?
    /**
     * Throw {@link IllegalArgumentException} if the byte array is not the length.
     * <p>
     * <b>NOTE:</b> We are not currently validating for value less than {@code P}
     * @param e unvalidated integer
     * @return a validated integer
     */
    public static byte[] checkInRange(byte[] e) {
        if (e.length != 32) {
            throw new IllegalArgumentException("SecpFieldElement must have 32 bytes, found : " + e.length);
        }
        if (!isInRange(e)) {
            throw new IllegalArgumentException("byte[] is not a valid SecpFieldElement: " + ByteArrayBase.toHexString(e));
        }
        return e;
    }
}
