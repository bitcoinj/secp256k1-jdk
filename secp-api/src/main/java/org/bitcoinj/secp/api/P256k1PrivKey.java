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

import org.bitcoinj.secp.api.internal.P256k1PrivKeyDefault;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

import static org.bitcoinj.secp.api.P256K1FieldElement.checkInRange;

// TODO: Override/prevent serialization
/**
 * A P256k1 private key.
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
     * Construct a private key from bytes
     * @param bytes bytes
     * @return private key
     */
    static P256k1PrivKey of(byte[] bytes) {
        return new P256k1PrivKeyDefault(bytes);
    }

    /**
     * Destroy must be implemented and must not throw (checked) exceptions
     */
    @Override
    void destroy();
}
