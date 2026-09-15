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

import org.bitcoinj.secp.SecpKeyPair;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.ffm.jextract.secp256k1_h;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;

import static org.bitcoinj.secp.ffm.Secp256k1Foreign.pubKeySerializeSegment;

/// Native KeyPair
public class SecpKeyPairNative implements SecpKeyPair {
    private static final long SIZE = 96;

    private volatile boolean destroyed = false;
    /// Native memory segment containing a 65-byte, serialized uncompressed public key
    private final MemorySegment segment;

    private SecpKeyPairNative(MemorySegment segment) {
        this.segment = segment;
    }

    /// Construct from a [MemorySegment] in libsecp internal pubKey format. The data is serialized
    /// into a newly-allocated `ofAuto` [MemorySegment] which is owned by the created instance.
    /// @param segment A segment in internal pubKey format
    /// @return a pubKey object
    static SecpKeyPairNative ofInternal(MemorySegment segment) {
        var keyPairAutoSegment = Arena.ofAuto().allocate(SIZE);
        MemorySegment.copy(segment, 0, keyPairAutoSegment, 0, SIZE);
        return new SecpKeyPairNative(keyPairAutoSegment);
    }

    static @Nullable SecpKeyPairNative fromPriv(MemorySegment context, MemorySegment privKeySeg) {
        var keyPairAutoSegment = Arena.ofAuto().allocate(SIZE);
        int result = secp256k1_h.secp256k1_keypair_create(context, keyPairAutoSegment, privKeySeg);
        return result == 1
                ? new SecpKeyPairNative(keyPairAutoSegment)
                : null;
    }

    @Override
    public SecpPubKey publicKey() {
        if (destroyed) throwKeyDestroyed();
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment pubKeySeg = ta.allocate(64);
            secp256k1_h.secp256k1_keypair_pub(Secp256k1Foreign.STATIC_CTX, pubKeySeg, segment);
            MemorySegment serializedPubKey = pubKeySerializeSegment(ta, pubKeySeg, 2);
            return new SecpPubKeyNative(serializedPubKey);
        }
    }

    @Override
    public SecpPrivKey privateKey() {
        if (destroyed) throwKeyDestroyed();
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment privKeySeg = ta.allocate(32);
            secp256k1_h.secp256k1_keypair_sec(Secp256k1Foreign.STATIC_CTX, privKeySeg, segment);
            return new SecpPrivKeyNative(privKeySeg);
        }
    }

    @Override
    public byte[] getEncoded() {
        if (destroyed) throwKeyDestroyed();
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment privKeySeg = ta.allocate(32);
            secp256k1_h.secp256k1_keypair_sec(Secp256k1Foreign.STATIC_CTX, privKeySeg, segment);
            return new SecpPrivKeyNative(privKeySeg).getEncoded();
        }
    }

    @Override
    public BigInteger getS() {
        if (destroyed) throwKeyDestroyed();
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment privKeySeg = ta.allocate(32);
            secp256k1_h.secp256k1_keypair_sec(Secp256k1Foreign.STATIC_CTX, privKeySeg, segment);
            return new SecpPrivKeyNative(privKeySeg).getS();
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

    /// Get the key pair's memory segment
    /// @return A read-only memory segment containing the key pair in internal format
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
