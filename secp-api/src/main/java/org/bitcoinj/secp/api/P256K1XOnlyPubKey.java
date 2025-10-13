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
package org.bitcoinj.secp.api;

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
     * @param x X as a {@link BigInteger}
     * @return an instance of the default implementation
     */
    static P256K1XOnlyPubKey of(BigInteger x) {
        return new P256K1XOnlyPubKeyBigInteger(x);
    }

    /**
     * @param xBytes X in its standard {@code byte[]} format
     * @return an instance of the default implementation
     */
    static P256K1XOnlyPubKey of(byte[] xBytes) {
        return new P256K1XOnlyPubKeyBytes(xBytes);
    }

    /**
     * Default implementation. Currently used by all known implementations
     */
    class P256K1XOnlyPubKeyBigInteger implements P256K1XOnlyPubKey {
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

    /**
     * Simple implementation using {code @byte[]} as internal storage.
     */
    class P256K1XOnlyPubKeyBytes implements P256K1XOnlyPubKey, ByteArray {
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
}
