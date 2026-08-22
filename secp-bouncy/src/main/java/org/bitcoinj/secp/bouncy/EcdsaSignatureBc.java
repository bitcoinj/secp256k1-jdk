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
package org.bitcoinj.secp.bouncy;

import org.bitcoinj.secp.EcdsaSignature;
import org.bitcoinj.secp.SecpScalar;
import org.bitcoinj.secp.internal.SecpScalarImpl;
import org.bitcoinj.secp.internal.UInt256;

import java.math.BigInteger;

/**
 * BigInteger-based ECDSA Signature implementation for Bouncy Castle.
 */
public class EcdsaSignatureBc implements EcdsaSignature {
    private final BigInteger r, s;

    public EcdsaSignatureBc(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    @Override
    public SecpScalar r() {
        return new SecpScalarImpl(r);
    }

    @Override
    public SecpScalar s() {
        return new SecpScalarImpl(s);
    }

    @Override
    public BigInteger rBigInteger() {
        return r;
    }

    @Override
    public BigInteger sBigInteger() {
        return s;
    }

    @Override
    public byte[] serializeCompact() {
        byte[] signature = new byte[64];
        UInt256.writeTo32Bytes(r, signature, 0);
        UInt256.writeTo32Bytes(s, signature, 32);
        return signature;
    }

    @Override
    public boolean hasLowR() {
        return !r.testBit(255);
    }

    @Override
    public boolean hasLowS() {
        return s.compareTo(Bouncy256k1.HALF_CURVE_ORDER) <= 0;
    }

    @Override
    public EcdsaSignature normalize() {
        return hasLowS() ? this : new EcdsaSignatureBc(rBigInteger(), Bouncy256k1.N.subtract(sBigInteger()));
    }

    @Override
    public String toString() {
        return "EcdsaSignatureBc [r=" + UInt256.toString(r) + ", s=" + UInt256.toString(s) + "]";
    }
}
