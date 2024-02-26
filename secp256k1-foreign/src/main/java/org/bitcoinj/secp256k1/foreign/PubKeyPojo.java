package org.bitcoinj.secp256k1.foreign;

import org.bitcoinj.secp256k1.api.P256k1PubKey;

import java.security.spec.ECPoint;

/**
 *
 */
public class PubKeyPojo implements P256k1PubKey {
    private final ECPoint point;

    public PubKeyPojo(ECPoint ecPoint) {
        point = ecPoint;
    }
    @Override
    public ECPoint getW() {
        return point;
    }

    @Override
    public String toString() {
        ECPoint point = getW();
        return point.equals(ECPoint.POINT_INFINITY)
                ? "POINT_INFINITY"
                : point.getAffineX().toString(16) + "," + point.getAffineY().toString(16);
    }
}
