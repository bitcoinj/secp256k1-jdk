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

import org.bitcoinj.secp.api.internal.P256K1XOnlyPubKeyBigInteger;
import org.bitcoinj.secp.api.internal.P256K1XOnlyPubKeyBytes;

import java.math.BigInteger;

/**
 * An x-only public key from a point on the secp256k1 curve
 */
public interface P256K1XOnlyPubKey {
    /**
     *  Get X as a {@link BigInteger}
     * @return X as a {@link BigInteger}
     */
    BigInteger getX();

    /**
     * Serialize as a 32-byte, Big-endian byte array
     * @return Big-endian, 32 bytes
     */
    byte[] serialize();

    /**
     * Parses a serialized x-only pubkey and returns an instance of the default implementation
     * @param serialized byte string in x-only pubkey serialization format
     * @return an instance of the default implementation
     */
    static Result<P256K1XOnlyPubKey> parse(byte[] serialized) {
        BigInteger x = new BigInteger(1, serialized);
        return !P256K1FieldElement.isInRange(x)
                ? Result.err(-1)
                : Result.ok(P256K1XOnlyPubKey.of(x));
    }

    /**
     * Create an X-only public key from a {@link BigInteger}.
     * @param x X
     * @return an instance of the default implementation
     */
    static P256K1XOnlyPubKey of(BigInteger x) {
        return new P256K1XOnlyPubKeyBigInteger(x);
    }

    /**
     * Create an X-only public key from a 32-byte, big-endian {@code byte[]}.
     * @param xBytes X
     * @return an instance of the default implementation
     */
    static P256K1XOnlyPubKey of(byte[] xBytes) {
        return new P256K1XOnlyPubKeyBytes(xBytes);
    }
}
