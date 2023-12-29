package org.consensusj.secp256k1.foreign;

import org.consensusj.secp256k1.api.SignatureData;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 *
 */
public class SignaturePojo implements SignatureData {
    private final byte[] bytes;

    public SignaturePojo(byte[] signatureBytes) {
        bytes = new byte[signatureBytes.length];
        System.arraycopy(signatureBytes, 0, bytes, 0, signatureBytes.length);
    }

    SignaturePojo(MemorySegment signature) {
        // Make defensive copy, so we are effectively immutable
        bytes = signature.toArray(ValueLayout.JAVA_BYTE);
    }


    public byte[] bytes() {
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, bytes.length);
        return copy;
    }
}
