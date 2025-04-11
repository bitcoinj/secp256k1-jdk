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

import org.jspecify.annotations.Nullable;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

import static org.bitcoinj.secp.api.P256k1PubKey.integerTo32Bytes;

/**
 *  Verified private secret key
 *  TODO: Override/prevent serialization
 */
public interface P256k1PrivKey extends ECPrivateKey {


    @Override
    default String getAlgorithm() {
        return "Secp256k1";
    }

    @Override
    default String getFormat() {
        return "Big-endian";
    }

    /**
     * @return 32-bytes, Big endian with no prefix or suffix
     */
    @Override
    byte[] getEncoded();

    @Override
    default BigInteger getS() {
        return ByteArray.toInteger(getEncoded());
    }

    @Override
    default ECParameterSpec getParams() {
        return Secp256k1.EC_PARAMS;
    }

    /**
     * Construct a private key from an integer
     * @param p Must be a member of the Secp256k1 field
     * @return private key
     */
    static P256k1PrivKey of(BigInteger p) {
        return new P256k1PrivKeyDefault(p);
    }

    /**
     * Destroy must be implemented and must not throw (checked) exceptions
     */
    @Override
    void destroy();

    class P256k1PrivKeyDefault implements P256k1PrivKey {
        /** private key or null if key was destroyed */
        private byte @Nullable [] privKeyBytes;

        /**
         * Caller is responsible to defensively copy byte[]. This is to avoid
         * a redundant copy. Exclusive ownership must be passed to this instance.
         * @param bytes (will not be defensively copied)
         */
        protected P256k1PrivKeyDefault(byte[] bytes) {
            // TODO: Range validation?
            privKeyBytes = bytes;
        }

        private P256k1PrivKeyDefault(BigInteger privKey) {
            // TODO: Valid integer is valid for field
            this.privKeyBytes = integerTo32Bytes(privKey);
        }

        @Override
        public byte[] getEncoded() {
            if (privKeyBytes == null) throwKeyDestroyed();
            byte[] copy = new byte[privKeyBytes.length];
            System.arraycopy(privKeyBytes, 0, copy, 0, privKeyBytes.length);
            return copy;
        }

        @Override
        public BigInteger getS() {
            if (privKeyBytes == null) throwKeyDestroyed();
            return ByteArray.toInteger(getEncoded());
        }

        @Override
        public void destroy() {
            // TODO: Make sure the zeroing is not optimized out by the compiler or JIT
            if (privKeyBytes != null) {
                Arrays.fill( privKeyBytes, (byte) 0x00 );
                privKeyBytes = null;
            }
        }

        @Override
        public boolean isDestroyed() {
            return privKeyBytes == null;
        }

        private void throwKeyDestroyed() {
            throw new IllegalStateException("Private Key has been destroyed");
        }
    }
}
