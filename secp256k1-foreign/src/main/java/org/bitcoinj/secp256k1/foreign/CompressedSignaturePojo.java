package org.bitcoinj.secp256k1.foreign;

import org.bitcoinj.secp256k1.api.CompressedSignatureData;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 *
 */
public class CompressedSignaturePojo implements CompressedSignatureData {
    private final byte[] bytes;

    public CompressedSignaturePojo(byte[] compressedPubKey) {
        bytes = new byte[compressedPubKey.length];
        System.arraycopy(compressedPubKey, 0, bytes, 0, compressedPubKey.length);
    }

    CompressedSignaturePojo(MemorySegment pubKey) {
        // Make defensive copy, so we are effectively immutable
        bytes = pubKey.toArray(ValueLayout.JAVA_BYTE);
    }


    public byte[] bytes() {
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, bytes.length);
        return copy;
    }
}
