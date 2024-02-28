package org.bitcoinj.secp256k1.api;

import java.math.BigInteger;
import java.util.Optional;

/**
 *
 */
public class P256K1XOnlyPubKey {
    private final BigInteger x;

    public P256K1XOnlyPubKey(P256k1PubKey pubKey) {
        // Avoid using pubKey.getXOnly() and possible infinite recursion
        this.x = pubKey.getW().getAffineX();
    }

    public /* package */ P256K1XOnlyPubKey(BigInteger x) {
        this.x = x;
    }


    public BigInteger getX() {
        return x;
    }

    /**
     * @return Big-endian, 32 bytes
     */
    public byte[] getSerialized() {
        return P256k1PubKey.integerTo32Bytes(x);
    }

    public static Result<P256K1XOnlyPubKey> parse(byte[] serialized) {
        BigInteger x = new BigInteger(1, serialized);
        return (x.compareTo((Secp256k1.FIELD.getP())) > 0)
                ? Result.err(-1)
                : Result.ok(new P256K1XOnlyPubKey(x));
    }
}
