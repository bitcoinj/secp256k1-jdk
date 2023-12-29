package org.consensusj.secp256k1.bouncy;


import org.bouncycastle.math.ec.ECPoint;
import org.consensusj.secp256k1.api.P256k1PubKey;

/**
 *
 */
public class BouncyPubKey implements P256k1PubKey {
    private final ECPoint point;

    public BouncyPubKey(ECPoint point) {
        this.point = point;
    }

    private byte[] bytes() {
        byte[] bytes = new byte[64];
        byte[] encoded =  point.getEncoded(false);  // This has a prefix byte
        System.arraycopy(encoded, 1, bytes, 0, bytes.length); // remove prefix byte
        return bytes;
    }

    @Override
    public String toString() {
        return hf.formatHex(bytes()) ;
    }

    @Override
    public java.security.spec.ECPoint getW() {
        return new java.security.spec.ECPoint(
                point.getAffineXCoord().toBigInteger(),
                point.getAffineYCoord().toBigInteger());
    }
}
