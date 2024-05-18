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
package org.bitcoinj.secp256k1.api;

import java.math.BigInteger;

/**
 *
 */
public interface P256K1XOnlyPubKey {
    /**
     * @return X as a {@link BigInteger}
     */
    BigInteger getX();

    /**
     * @return Big-endian, 32 bytes
     */
    byte[] getSerialized();

    /**
     * Parses a serialized x-only pubkey and returns an instance of the default implementation
     * @param serialized byte string in x-only pubkey serialization format
     * @return an instance of the default implementation
     */
    static Result<P256K1XOnlyPubKey> parse(byte[] serialized) {
        BigInteger x = new BigInteger(1, serialized);
        return (x.compareTo((Secp256k1.FIELD.getP())) > 0)
                ? Result.err(-1)
                : Result.ok(P256K1XOnlyPubKey.of(x));
    }

    /**
     * @param x X as a {@link BigInteger}
     * @return an instance of the default implementation
     */
    static P256K1XOnlyPubKey of(BigInteger x) {
        return new P256K1XOnlyPubKeyImpl(x);
    }

    /**
     * Default implementation. Currently used by all known implementations
     */
    class P256K1XOnlyPubKeyImpl implements P256K1XOnlyPubKey {
        private final BigInteger x;

        public P256K1XOnlyPubKeyImpl(P256k1PubKey pubKey) {
            // Avoid using pubKey.getXOnly() and possible infinite recursion
            this.x = pubKey.getW().getAffineX();
        }

        public P256K1XOnlyPubKeyImpl(BigInteger x) {
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
        public byte[] getSerialized() {
            return P256k1PubKey.integerTo32Bytes(x);
        }
    }
}
