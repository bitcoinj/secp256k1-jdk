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
import org.bitcoinj.secp.SecpScalar;

import java.util.Arrays;

/**
 * Default/Internal implementation of {@link EcdsaSignature}
 */
public class EcdsaSignatureImpl implements EcdsaSignature {
    private final SecpScalarImpl r;
    private final SecpScalarImpl s;

    public EcdsaSignatureImpl(SecpScalarImpl r, SecpScalarImpl s) {
        this.r = r;
        this.s = s;
    }

    public EcdsaSignatureImpl(SecpScalar r, SecpScalar s) {
        this.r = new SecpScalarImpl(r.serialize());
        this.s = new SecpScalarImpl(s.serialize());
    }

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
    public boolean hasLowR() {
        // Is the high-bit of the first (high, big-endian) byte zero?
        return this.r().serialize()[0] >= 0;
    }

    @Override
    public byte[] serializeCompact() {
        byte[] signature = new byte[64];
        System.arraycopy(r.serialize(), 0, signature, 0, 32);
        System.arraycopy(s.serialize(), 0, signature, 32, 32);
        return signature;
    }

    @Override
    public String toString() {
        return ByteUtils.toHexString(serializeCompact());
    }
}
