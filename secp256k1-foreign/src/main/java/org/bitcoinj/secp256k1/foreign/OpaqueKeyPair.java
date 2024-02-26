package org.bitcoinj.secp256k1.foreign;

import org.bitcoinj.secp256k1.api.P256K1KeyPair;
import org.bitcoinj.secp256k1.api.P256k1PrivKey;
import org.bitcoinj.secp256k1.api.P256k1PubKey;
import org.bitcoinj.secp256k1.foreign.jextract.secp256k1_h;
import org.bitcoinj.secp256k1.foreign.jextract.secp256k1_pubkey;

import java.lang.foreign.MemorySegment;
import java.security.spec.ECPoint;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 *
 */
public class OpaqueKeyPair implements P256K1KeyPair {
    private final byte[] opaque;

    public OpaqueKeyPair(byte[] opaque) {
        this.opaque = opaque.clone();
    }

    @Override
    public P256k1PubKey getPublic() {
        MemorySegment keyPairSegment = Secp256k1Foreign.globalArena.allocateArray(JAVA_BYTE, opaque);
        MemorySegment pubKeySegment = secp256k1_pubkey.allocate(Secp256k1Foreign.globalArena);
        int return_val = secp256k1_h.secp256k1_keypair_pub(secp256k1_h.secp256k1_context_static$get(), pubKeySegment, keyPairSegment);
        assert(return_val == 1);
        ECPoint pubKeyPoint = Secp256k1Foreign.toPoint(pubKeySegment);
        return new PubKeyPojo(pubKeyPoint);
    }

    public byte[] getOpaque() {
        return opaque.clone();
    }

    public P256k1PrivKey getPrivate() {
        return new PrivKeyPojo(getEncoded());
    }

    @Override
    public byte[] getEncoded() {
        MemorySegment keyPairSegment = Secp256k1Foreign.globalArena.allocateArray(JAVA_BYTE, opaque);
        MemorySegment privKeySegment = Secp256k1Foreign.globalArena.allocate(32);
        int return_val = secp256k1_h.secp256k1_keypair_sec(secp256k1_h.secp256k1_context_static$get(), privKeySegment, keyPairSegment);
        assert(return_val == 1);
        return privKeySegment.toArray(JAVA_BYTE);
    }

    @Override
    public void destroy() {
        // TODO
    }
}
