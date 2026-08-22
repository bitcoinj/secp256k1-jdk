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
package org.bitcoinj.secp.internal;

import org.bitcoinj.secp.EcdsaSignature;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpScalar;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Default/Internal implementation of {@link EcdsaSignature}
 */
public class EcdsaSignatureImpl implements EcdsaSignature {
    private final SecpScalarImpl r;
    private final SecpScalarImpl s;

    private EcdsaSignatureImpl(BigInteger r, BigInteger s) {
        this.r = new SecpScalarImpl(r);
        this.s = new SecpScalarImpl(s);
    }

    /**
     * Construct from a 64-byte, big-endian compact serialized signature
     * @param signature Signature in compact serialized format.
     */
    public EcdsaSignatureImpl(byte[] signature) {
        if (signature.length != 64) {
            throw new IllegalArgumentException("Sig Not 64 bytes");
        }
        this.r = new SecpScalarImpl(Arrays.copyOfRange(signature, 0, 32));
        this.s = new SecpScalarImpl(Arrays.copyOfRange(signature, 32, 64));
    }

    @Override
    public SecpScalarImpl r() {
        return r;
    }

    @Override
    public SecpScalarImpl s() {
        return s;
    }

    @Override
    public BigInteger rBigInteger() {
        return r.toBigInteger();
    }

    @Override
    public BigInteger sBigInteger() {
        return s.toBigInteger();
    }

    @Override
    public boolean hasLowR() {
        // Is the high-bit of the first (high, big-endian) byte zero?
        return this.r().toByteArray()[0] >= 0;
    }

    @Override
    public boolean hasLowS() {
        return this.sBigInteger().compareTo(Secp256k1.HALF_CURVE_ORDER.toBigInteger()) <= 0;
    }

    @Override
    public EcdsaSignature normalize() {
        return hasLowS() ? this : new EcdsaSignatureImpl(rBigInteger(), Secp256k1.N.subtract(sBigInteger()));
    }

    @Override
    public byte[] serializeCompact() {
        byte[] signature = new byte[64];
        System.arraycopy(r.toByteArray(), 0, signature, 0, 32);
        System.arraycopy(s.toByteArray(), 0, signature, 32, 32);
        return signature;
    }

    @Override
    public String toString() {
        return "EcdsaSignatureImpl [r=" + r + ", s=" + s + "]";
    }
}
