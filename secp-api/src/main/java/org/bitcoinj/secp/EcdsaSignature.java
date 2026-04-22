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
package org.bitcoinj.secp;

import org.bitcoinj.secp.internal.EcdsaSignatureImpl;

/**
 * An secp256k1 ECDSA signature.
 */
public interface EcdsaSignature {
    /**
     * Get scalar R
     * @return R
     */
    SecpScalar r();

    /**
     * Get scalar S
     * @return S
     */
    SecpScalar s();

    /**
     * Serialize as a Bitcoin <i>compact signature</i>. A compact signature is  the two signature component
     * scalars (known as {@code r} and {@code s}) serialized in-order as binary data in big-endian format.
     * @return a Bitcoin compact signature
     */
    byte[] serializeCompact();

    /**
     * Is this signature a "low R" signature.
     * In other words: In a 256-bit big-endian representation of {@code R}, the high-bit is zero.
     * @return true if this signature has a <i>low R</i> value.
     */
    boolean hasLowR();

    /**
     * Create an ECDSA signature from serialized bytes
     * @param bytes bytes
     * @return signature
     */
    static EcdsaSignature of(byte[] bytes) {
        return new EcdsaSignatureImpl(bytes);
    }

    /**
     * Create an ECDSA signature from R and S values
     * @param r R
     * @param s S
     * @return signature
     */
    static EcdsaSignature of(SecpScalar r, SecpScalar s) {
        return new EcdsaSignatureImpl(r, s);
    }
}
