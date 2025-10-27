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
package org.bitcoinj.secp.internal;

import org.bitcoinj.secp.P256K1FieldElement;
import org.bitcoinj.secp.EcdsaSignature;

import java.util.Arrays;

/**
 * Default/Internal implementation of {@link EcdsaSignature}
 */
public class EcdsaSignatureImpl implements EcdsaSignature {
    private final P256K1FieldElement r;
    private final P256K1FieldElement s;

    public EcdsaSignatureImpl(P256K1FieldElement r, P256K1FieldElement s) {
        this.r = r;
        this.s = s;
    }

    public EcdsaSignatureImpl(byte[] signature) {
        if (signature.length != 64) {
            throw new IllegalArgumentException("Sig Not 64 bytes");
        }
        this.r = P256K1FieldElement.of(Arrays.copyOfRange(signature, 0, 32));
        this.s = P256K1FieldElement.of(Arrays.copyOfRange(signature, 32, 64));
    }

    public P256K1FieldElement r() {
        return r;
    }

    public P256K1FieldElement s() {
        return s;
    }


    @Override
    public byte[] bytes() {
        byte[] signature = new byte[64];
        System.arraycopy(r.serialize(), 0, signature, 0, 32);
        System.arraycopy(s.serialize(), 0, signature, 32, 32);
        return signature;
    }

    @Override
    public String toString() {
        return this.formatHex();
    }
}
