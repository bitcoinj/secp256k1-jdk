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
package org.bitcoinj.secp.ffm;

import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.internal.SecpScalarImpl;
import org.bitcoinj.secp.internal.UInt256;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.util.Arrays;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/// Native implementation of SecpPrivKey
class SecpPrivKeyNative implements SecpPrivKey {
    private static final int KEY_LENGTH = 32;

    private volatile boolean destroyed = false;
    private final MemorySegment segment;

    SecpPrivKeyNative(MemorySegment privKeySeg) {
        var segment = Arena.ofAuto().allocate(KEY_LENGTH);
        MemorySegment.copy(privKeySeg, 0, segment, 0, KEY_LENGTH);
        this.segment = segment;
    }

    SecpPrivKeyNative(byte[] privKeyBytes) {
        SecpScalarImpl.checkInRange(privKeyBytes);
        this(MemorySegment.ofArray(privKeyBytes));
    }

    @Override
    public byte[] getEncoded() {
        if (destroyed) throwKeyDestroyed();
        return segment.toArray(JAVA_BYTE);
    }

    @Override
    public BigInteger getS() {
        if (destroyed) throwKeyDestroyed();
        byte[] bytes = getEncoded();
        try {
            return UInt256.toBigInteger(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    @Override
    public void destroy() {
        // TODO: Make sure the zeroing is not optimized out by the compiler or JIT
        if (!destroyed) {
            segment.fill((byte) 0);
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    MemorySegment segment() {
        if (destroyed) throwKeyDestroyed();
        return segment.asReadOnly();
    }

    private void throwKeyDestroyed() {
        throw new IllegalStateException("Private Key has been destroyed");
    }

    @Serial
    private void writeObject(ObjectOutputStream out) throws IOException {
        throw new NotSerializableException("Serialization of private keys is prohibited.");
    }

    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        throw new NotSerializableException("Deserialization of private keys is prohibited.");
    }
}
