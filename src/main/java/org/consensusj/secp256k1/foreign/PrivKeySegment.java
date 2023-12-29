package org.consensusj.secp256k1.foreign;

import org.consensusj.secp256k1.api.P256k1PrivKey;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 *
 */
/* package */ class PrivKeySegment  implements P256k1PrivKey {
    final MemorySegment segment;

    PrivKeySegment(MemorySegment segment) {
        this.segment = segment;
    }

    @Override
    public byte[] bytes() {
        return new byte[0];
    }

    @Override
    public void destroy() {
        // TODO: TBD!
    }

    MemorySegment segment() {
        return segment;
    }
}
