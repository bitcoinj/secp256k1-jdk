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
package org.bitcoinj.secp.ffm;

import org.bitcoinj.secp.api.P256k1PrivKey;
import org.jspecify.annotations.Nullable;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * TODO: Verify validity at creation time
 */
public class PrivKeyPojo implements P256k1PrivKey {

    /** private key or null if key was destroyed */
    private byte @Nullable [] privKeyBytes;

    /**
     * Package private to ensure it is only created from a valid private key
     * @param privKey
     */
    PrivKeyPojo(MemorySegment privKey) {
        // Make defensive copy, so we are effectively immutable
        privKeyBytes = privKey.toArray(ValueLayout.JAVA_BYTE);
    }

    PrivKeyPojo(byte[] bytes) {
        // Make defensive copy, so we are effectively immutable
        privKeyBytes = bytes.clone();
    }

    @Override
    public byte[] getEncoded() {
        if (privKeyBytes == null) throw new IllegalStateException("Private Key has been destroyed");
        byte[] copy = new byte[privKeyBytes.length];
        System.arraycopy(privKeyBytes, 0, copy, 0, privKeyBytes.length);
        return copy;
    }

    public BigInteger integer() {
        if (privKeyBytes == null) throw new IllegalStateException("Private Key has been destroyed");
        return new BigInteger(1, privKeyBytes);
    }

    @Override
    public void destroy() {
        // TODO: Make sure the zeroing is not optimized out by the compiler or JIT
        if (privKeyBytes != null) {
            Arrays.fill( privKeyBytes, (byte) 0x00 );
            privKeyBytes = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return privKeyBytes == null;
    }
}
