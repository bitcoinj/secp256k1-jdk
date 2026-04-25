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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.jspecify.annotations.Nullable;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * Custom K calculator with ability to add additional entropy to the calculation. This is needed for grinding for
 * low signature R values. Before calling {@link #setEntropy(byte[])}, no entropy is added.
 */
class HMacDSAKCalculatorWithEntropy extends HMacDSAKCalculator {

    byte @Nullable[] entropy = null;

    HMacDSAKCalculatorWithEntropy(Digest digest) {
        super(digest);
    }

    /**
     * Add 32 bytes of additional entropy to the K calculation via RFC 6979.
     *
     * @param entropy 32 bytes of entropy
     * @see
     * <a href="https://www.rfc-editor.org/rfc/rfc6979#section-3.6">RFC 6979 section 3.6. "Additional data…"</a>
     */
    private void setEntropy(byte[] entropy) {
        Objects.requireNonNull(entropy);
        checkArg(entropy.length == 32, "entropy must be 32 bytes");
        this.entropy = entropy;
    }

    public void setEntropy(int counter) {
        byte[] entropy =
                ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN).putInt(0, counter).array();
        setEntropy(entropy);
    }

    @Override
    protected void initAdditionalInput0(HMac hmac0) {
        if (entropy != null)
            hmac0.update(entropy, 0, 32);
    }

    @Override
    protected void initAdditionalInput1(HMac hmac1) {
        if (entropy != null)
            hmac1.update(entropy, 0, 32);
    }

    private static void checkArg(boolean condition, String string) {
        if (!condition) {
            throw new IllegalArgumentException(string);
        }
    }
 }
