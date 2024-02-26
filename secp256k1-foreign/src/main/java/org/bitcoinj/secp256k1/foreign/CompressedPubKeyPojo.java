package org.bitcoinj.secp256k1.foreign;

import org.bitcoinj.secp256k1.api.CompressedPubKeyData;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 *
 */
public class CompressedPubKeyPojo implements CompressedPubKeyData {
    private final byte[] bytes;

    public CompressedPubKeyPojo(byte[] compressedPubKey) {
        bytes = new byte[compressedPubKey.length];
        System.arraycopy(compressedPubKey, 0, bytes, 0, compressedPubKey.length);
    }
    
    public byte[] bytes() {
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, bytes.length);
        return copy;
    }
}
