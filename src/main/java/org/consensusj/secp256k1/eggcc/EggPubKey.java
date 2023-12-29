package org.consensusj.secp256k1.eggcc;

import org.bouncycastle.math.ec.ECFieldElement;
import org.consensusj.secp256k1.api.P256k1PubKey;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.Objects;

/**
 *
 */
public class EggPubKey implements P256k1PubKey {
    public static final BigInteger ZERO = Element.ZERO;  // TODO: This should maybe not be zero?
    public static final EggPubKey INFINITY = new EggPubKey(ZERO, ZERO);
    final Element x;
    final Element y;

    public EggPubKey(Element x, Element y) {
        this.x = x;
        this.y = y;
    }

    public EggPubKey(BigInteger x, BigInteger y) {
        // TODO: Check to make sure values are on secp256k1 curve
        this.x = new Element(x);
        this.y = new Element(y);
    }

    public EggPubKey add(EggPubKey p2) {
        Objects.requireNonNull(p2);
        if (this.x.equals(ZERO)) {
            return p2;
        } else if (p2.x.equals(ZERO)) {
            return this;
        } else if (this.x.equals(p2.x)) {
            if (!this.y.equals(p2.y)) {
                return INFINITY;
            } else {
                BigInteger slope = BigInteger.ZERO; // TODO: Finish
            }
        } else {
            ECFieldElement slope = p2.y.subtract(this.y).divide(p2.x.subtract(this.x));
            ECFieldElement x3 = slope.square().subtract(this.x).subtract(p2.x);
            ECFieldElement y3 = slope.multiply(this.x.subtract(x3)).subtract(this.y);
            return new EggPubKey(x3.toBigInteger(), y3.toBigInteger());
        }
        return this;
    }

    public EggPubKey multiply(BigInteger scalar) {
        BigInteger coef = scalar;
        EggPubKey current = this;
        EggPubKey result = new EggPubKey(ZERO, ZERO);
        while (!coef.equals(BigInteger.ZERO)) {
            if (coef.and(BigInteger.ONE).equals(BigInteger.ONE)) {
                result = result.add(current);
            }
            current = current.add(current);
            coef = coef.shiftRight(1);
        }
        return result;
    }

    private byte[] bytes() {
        byte[] pubKeyBytes = new byte[64];
        System.arraycopy(x.getEncoded(), 0, pubKeyBytes, 0, 32);
        System.arraycopy(y.getEncoded(), 0, pubKeyBytes, 32, 32);
        return pubKeyBytes;
    }

    @Override
    public ECPoint getW() {
        return null;    // TBD
    }
}
