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
import org.bitcoinj.secp.P256K1FieldElement;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 *
 */
public class P256K1FieldElementDefault implements P256K1FieldElement {
    private final byte[] value;

    public P256K1FieldElementDefault(BigInteger i) {
        value = P256K1FieldElement.integerTo32Bytes(P256K1FieldElement.checkInRange(i));
    }

    public P256K1FieldElementDefault(byte[] bytes) {
        value = P256K1FieldElement.checkInRange(bytes);
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
        P256K1FieldElementDefault that = (P256K1FieldElementDefault) o;
        return Objects.deepEquals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }
}
