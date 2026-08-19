/*
 * Copyright 2023-2026 secp256k1-jdk Developers.
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

import java.math.BigInteger;

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
     * Get scalar R
     * @return R
     */
    BigInteger rBigInteger();

    /**
     * Get scalar S
     * @return S
     */
    BigInteger sBigInteger();

    /**
     * Serialize as a Bitcoin <i>compact signature</i>. A compact signature is  the two signature component
     * scalars (known as {@code r} and {@code s}) serialized in-order as binary data in big-endian format.
     * @return a Bitcoin compact signature
     */
    byte[] serializeCompact();

    /**
     * Indicates this signature has a "low-r" value.
     * In other words: In a 256-bit big-endian representation of {@code R}, the high-bit is zero.
     * @return true if this signature has a low-<i>r</i> value.
     */
    boolean hasLowR();

    /**
     * Indicates this signature has a "low-s" value.
     * In other words: if s is less than or equal to the half curve order.
     * @return true if this signature has a low-<i>s</i> value.
     */
    boolean hasLowS();

    /**
     * Normalize this signature to its low-<i>s</i> form.
     * If {@link #hasLowS()} is already true, this signature is returned unchanged. Otherwise, an equivalent
     * signature is returned with <i>s</i> replaced by {@link Secp256k1#N} - <i>s</i>.
     * @return a signature with a low-<i>s</i> value
     */
    EcdsaSignature normalize();

    /**
     * Create an ECDSA signature from serialized bytes
     * @param bytes bytes
     * @return signature
     * @deprecated use {@link Secp256k1#ecdsaSignatureParseCompact(byte[])}
     */
    @Deprecated(forRemoval = true)
    static EcdsaSignature of(byte[] bytes) {
        return new EcdsaSignatureImpl(bytes);
    }

    /**
     * Create an ECDSA signature from R and S values
     * @param r R
     * @param s S
     * @return signature
     */
    @Deprecated(forRemoval = true)
    static EcdsaSignature of(SecpScalar r, SecpScalar s) {
        return new EcdsaSignatureImpl(r, s);
    }
}
