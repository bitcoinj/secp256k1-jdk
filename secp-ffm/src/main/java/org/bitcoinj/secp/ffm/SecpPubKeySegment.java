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
import org.bitcoinj.secp.ffm.jextract.secp256k1_pubkey;
import org.bitcoinj.secp.internal.ByteUtils;
import org.bitcoinj.secp.internal.SecpECPoint;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.security.spec.ECPoint;

import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.SECP256K1_EC_UNCOMPRESSED;

///
public class SecpPubKeySegment implements SecpPubKey {
    private static final long SIZE = secp256k1_pubkey.sizeof();
    private final MemorySegment segment;

    public SecpPubKeySegment(MemorySegment pubKeySegment) {
        var segment = Arena.ofAuto().allocate(SIZE);
        MemorySegment.copy(pubKeySegment, 0, segment, 0, SIZE);
        this.segment = segment.asReadOnly();
    }

    MemorySegment segment() {
        return segment;
    }

    @Override
    public ECPoint getW() {
        Uncompressed point = point();
        return SecpECPoint.of(point);
    }

    @Override
    public Uncompressed point() {
        SegmentAllocator alloc = Arena.ofAuto();
        MemorySegment serializedPubKeySeg = Secp256k1Foreign.pubKeySerializeSegment(alloc, segment, SECP256K1_EC_UNCOMPRESSED());
        return Secp256k1Foreign.serializedPubKeyToPoint(serializedPubKeySeg);
    }

    @Override
    public SecpFieldElement x() {
        return point().x();
    }

    @Override
    public SecpFieldElement y() {
        return point().y();
    }

    @Override
    public Compressed compress() {
        return point().compress();
    }

    @Override
    public byte[] serialize(boolean compressed) {
        return compressed
                ? SecpPoint.serializeCompressed(x().serialize(), isOdd())
                : SecpPoint.serializeUncompressed(x().serialize(), y().serialize());
    }

    @Override
    public String toString() {
        return ByteUtils.toHexString(serialize(true));
    }

    @Override
    public boolean isOdd() {
        return point().isOdd();
    }

    @Override
    public String getFormat() {
        return SecpPubKey.COMPRESSED_FORMAT_NAME;
    }
}
