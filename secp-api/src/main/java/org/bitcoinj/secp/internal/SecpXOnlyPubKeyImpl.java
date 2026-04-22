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

import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpXOnlyPubKey;

import java.math.BigInteger;

/**
 * Simple implementation using {code @byte[]} as internal storage.
 */
public class SecpXOnlyPubKeyImpl implements SecpXOnlyPubKey, ByteArray {
    private final byte[] x;

    public SecpXOnlyPubKeyImpl(SecpFieldElement x) {
        this.x = x.serialize();
    }

    // Only call this method for x-only pubkeys that have been verified as valid
    public static SecpXOnlyPubKeyImpl ofVerifiedBytes(byte[] bytes) {
        return new SecpXOnlyPubKeyImpl(SecpFieldElement.of(bytes));
    }

    @Override
    public BigInteger getX() {
        return ByteArray.toInteger(x);
    }

    @Override
    public byte[] bytes() {
        // Defensive copy
        return x.clone();
    }

    /**
     * @return Big-endian, 32 bytes
     */
    @Override
    public byte[] serialize() {
        return x.clone();
    }

    /**
     * @return A hex string representing the default binary serialization format
     */
    @Override
    public String toString() {
        return ByteUtils.toHexString(serialize());
    }
}
