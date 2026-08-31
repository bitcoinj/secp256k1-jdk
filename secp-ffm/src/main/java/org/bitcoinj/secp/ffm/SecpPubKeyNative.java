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

import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.internal.SecpPointCompressed;
import org.bitcoinj.secp.internal.SecpXOnlyPubKeyImpl;
import org.bitcoinj.secp.internal.UInt256;
import org.bitcoinj.secp.internal.SecpECPoint;
import org.jspecify.annotations.Nullable;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.spec.ECPoint;
import java.util.Objects;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/// Native implementation of SecpPubKey.
public class SecpPubKeyNative implements SecpPubKey {
    private static final long SIZE = 65;
    /// Native memory segment containing a 65-byte, serialized uncompressed public key
    private final MemorySegment segment;

    /// Construct a public key by copying a [MemorySegment]
    /// @param pubKeySegment memory segment containing a serialized uncompressed public key
    public SecpPubKeyNative(MemorySegment pubKeySegment) {
        var segment = Arena.ofAuto().allocate(SIZE);
        MemorySegment.copy(pubKeySegment, 0, segment, 0, SIZE);
        this.segment = segment.asReadOnly();
    }

    /// Get the public key's memory segment
    /// @return A read-only memory segment containing the public key in uncompressed serialized format
    MemorySegment segment() {
        return segment;
    }

    @Override
    public ECPoint getW() {
        return SecpECPoint.of(x().toBigInteger(), y().toBigInteger());
    }

    @Override
    public Uncompressed point() {
        return this;
    }

    @Override
    public SecpFieldElement x() {
        return Secp256k1Foreign.serializedPubKeyToX(segment);
    }

    @Override
    public SecpFieldElement y() {
        return Secp256k1Foreign.serializedPubKeyToY(segment);
    }

    @Override
    public Compressed compress() {
        return new SecpPointCompressed(x(), y().isOdd());
    }

    @Override
    public SecpXOnlyPubKey xOnly() {
        return new SecpXOnlyPubKeyImpl(x());
    }

    @Override
    public byte[] serialize(boolean compressed) {
        return compressed
                ? SecpPoint.serializeCompressed(segment.asSlice(1, 32).toArray(JAVA_BYTE), isOdd())
                : segment.toArray(JAVA_BYTE);
    }

    @Override
    public String toString() {
        return UInt256.toHexString(serialize(true));
    }

    @Override
    public boolean isOdd() {
        return Secp256k1Foreign.serializedPubKeyIsOdd(segment);
    }

    @Override
    public String getFormat() {
        return SecpPubKey.COMPRESSED_FORMAT_NAME;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (!(o instanceof Uncompressed that)) return false;
        return x().equals(that.x()) && isOdd() == that.isOdd();
    }

    @Override
    public int hashCode() {
        return Objects.hash(x(), isOdd());
    }
}
