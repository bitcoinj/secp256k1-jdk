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

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

/**
 *  Verified private secret key
 *  TODO: Override/prevent serialization
 */
public interface P256k1PrivKey extends ECPrivateKey {

    /* package */ static BigInteger toInteger(byte[] bytes) {
        int signum = 0;
        for (byte b : bytes) {
            if (b != 0) {
                signum = 1;
                break;
            }
        }
        return new BigInteger(signum, bytes);
    }

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
        return toInteger(getEncoded());
    }

    @Override
    default ECParameterSpec getParams() {
        return Secp256k1.EC_PARAMS;
    }

    /**
     * Destroy must be implemented and must not throw (checked) exceptions
     */
    @Override
    void destroy();
}
