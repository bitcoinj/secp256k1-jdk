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
package org.bitcoinj.secp.api.internal;

import org.bitcoinj.secp.api.ByteArray;
import org.bitcoinj.secp.api.P256K1FieldElement;
import org.bitcoinj.secp.api.P256K1XOnlyPubKey;
import org.bitcoinj.secp.api.P256k1PubKey;

import java.math.BigInteger;

/**
 * Default implementation. Currently used by all known implementations
 */
public class P256K1XOnlyPubKeyBigInteger implements P256K1XOnlyPubKey {
    private final BigInteger x;

    public P256K1XOnlyPubKeyBigInteger(P256k1PubKey pubKey) {
        // Avoid using pubKey.getXOnly() and possible infinite recursion
        this.x = pubKey.getW().getAffineX();
    }

    public P256K1XOnlyPubKeyBigInteger(BigInteger x) {
        this.x = x;
    }

    @Override
    public BigInteger getX() {
        return x;
    }

    /**
     * @return Big-endian, 32 bytes
     */
    @Override
    public byte[] serialize() {
        return P256K1FieldElement.integerTo32Bytes(x);
    }

    /**
     * @return A hex string representing the default binary serialization format
     */
    @Override
    public String toString() {
        return ByteArray.toHexString(serialize());
    }
}
