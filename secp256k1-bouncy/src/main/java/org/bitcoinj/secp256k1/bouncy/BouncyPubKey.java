package org.bitcoinj.secp256k1.bouncy;


import org.bouncycastle.math.ec.ECPoint;
import org.bitcoinj.secp256k1.api.P256k1PubKey;

import static org.bitcoinj.secp256k1.bouncy.Bouncy256k1.BC_CURVE;

/**
 *
 */
public class BouncyPubKey implements P256k1PubKey {
    private final ECPoint point;

    public BouncyPubKey(ECPoint point) {
        this.point = point;
    }

    public BouncyPubKey(java.security.spec.ECPoint javaPoint) {
        this(BC_CURVE.getCurve().createPoint(javaPoint.getAffineX(), javaPoint.getAffineY())) ;
    }

    private byte[] bytes() {
        byte[] bytes = new byte[64];
        byte[] encoded = getEncoded();  // This has a prefix byte
        System.arraycopy(encoded, 1, bytes, 0, bytes.length); // remove prefix byte
        return bytes;
    }

    @Override
    public byte[] getEncoded() {
        return point.getEncoded(false);  // This has a prefix byte
    }

    @Override
    public String toString() {
        return hf.formatHex(bytes()) ;
    }

    @Override
    public java.security.spec.ECPoint getW() {
        return new java.security.spec.ECPoint(
                point.normalize().getAffineXCoord().toBigInteger(),
                point.normalize().getAffineYCoord().toBigInteger());
    }
}
