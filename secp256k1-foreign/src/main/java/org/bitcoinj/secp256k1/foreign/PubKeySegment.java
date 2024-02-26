package org.bitcoinj.secp256k1.foreign;

import org.bitcoinj.secp256k1.api.P256k1PubKey;

import java.lang.foreign.MemorySegment;
import java.security.spec.ECPoint;

/**
 *
 */
/* package */ class PubKeySegment implements P256k1PubKey {
    final MemorySegment segment;

    PubKeySegment(MemorySegment segment) {
        this.segment = segment;
    }

    MemorySegment segment() {
        return segment;
    }

    @Override
    public ECPoint getW() {
        return null;
    }
}
