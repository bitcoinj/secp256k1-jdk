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
package org.bitcoinj.secp.api.internal;

import org.bitcoinj.secp.api.SPByteArray;
import org.bitcoinj.secp.api.SPPrivKey;
import org.jspecify.annotations.Nullable;

import java.math.BigInteger;
import java.util.Arrays;

import static org.bitcoinj.secp.api.SPFieldElement.checkInRange;
import static org.bitcoinj.secp.api.SPFieldElement.integerTo32Bytes;

/**
 * Default/internal implementation of {@link SPPrivKey}
 */
public class SPPrivKeyDefault implements SPPrivKey {
    /**
     * private key or null if key was destroyed
     */
    private byte @Nullable [] privKeyBytes;

    /**
     * Caller is responsible for defensively copying {@code byte[]}. This is to avoid
     * a redundant copy. Exclusive ownership must be passed to this instance.
     *
     * @param bytes (will not be defensively copied)
     */
    public SPPrivKeyDefault(byte[] bytes) {
        // TODO: Full, constant-time Range validation?
        checkInRange(bytes);
        privKeyBytes = checkInRange(bytes);
    }

    public SPPrivKeyDefault(BigInteger privKey) {
        // TODO: Valid integer is valid for field
        this.privKeyBytes = integerTo32Bytes(privKey);
    }

    @Override
    public byte[] getEncoded() {
        if (privKeyBytes == null) throwKeyDestroyed();
        byte[] copy = new byte[privKeyBytes.length];
        System.arraycopy(privKeyBytes, 0, copy, 0, privKeyBytes.length);
        return copy;
    }

    @Override
    public BigInteger getS() {
        if (privKeyBytes == null) throwKeyDestroyed();
        return SPByteArray.toInteger(getEncoded());
    }

    @Override
    public void destroy() {
        // TODO: Make sure the zeroing is not optimized out by the compiler or JIT
        if (privKeyBytes != null) {
            Arrays.fill(privKeyBytes, (byte) 0x00);
            privKeyBytes = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return privKeyBytes == null;
    }

    private void throwKeyDestroyed() {
        throw new IllegalStateException("Private Key has been destroyed");
    }
}
