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

import org.bitcoinj.secp.api.internal.SignatureDataImpl;

/**
 * An secp256k1 ECDSA signature.
 */
public interface SignatureData extends ByteArray {
    /**
     * Get field element R
     * @return R
     */
    P256K1FieldElement r();

    /**
     * Get field element S
     * @return S
     */
    P256K1FieldElement s();

    /**
     * Create an ECDSA signature from serialized bytes
     * @param bytes bytes
     * @return signature
     */
    static SignatureData of(byte[] bytes) {
        return new SignatureDataImpl(bytes);
    }

    /**
     * Create an ECDSA signature from R and S values
     * @param r R
     * @param s S
     * @return signature
     */
    static SignatureData of(P256K1FieldElement r, P256K1FieldElement s) {
        return new SignatureDataImpl(r,s);
    }
}
