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
import org.bitcoinj.secp.P256K1XOnlyPubKey;
import org.bitcoinj.secp.P256k1PubKey;

import java.math.BigInteger;

/**
 * Simple implementation using {code @byte[]} as internal storage.
 */
public class P256K1XOnlyPubKeyBytes implements P256K1XOnlyPubKey, ByteArray {
    private final byte[] x;

    public P256K1XOnlyPubKeyBytes(P256k1PubKey pubKey) {
        // Avoid using pubKey.getXOnly() and possible infinite recursion
        this.x = pubKey.xOnly().serialize();
    }

    public P256K1XOnlyPubKeyBytes(byte[] xBytes) {
        // Defensive copy
        x = new byte[xBytes.length];
        System.arraycopy(xBytes, 0, x, 0, x.length);
    }

    @Override
    public BigInteger getX() {
        return ByteArray.toInteger(x);
    }

    @Override
    public byte[] bytes() {
        // Defensive copy
        byte[] result = new byte[x.length];
        System.arraycopy(x, 0, result, 0, x.length);
        return result;
    }

    /**
     * @return Big-endian, 32 bytes
     */
    @Override
    public byte[] serialize() {
        return bytes();
    }

    /**
     * @return A hex string representing the default binary serialization format
     */
    @Override
    public String toString() {
        return ByteArray.toHexString(serialize());
    }
}
