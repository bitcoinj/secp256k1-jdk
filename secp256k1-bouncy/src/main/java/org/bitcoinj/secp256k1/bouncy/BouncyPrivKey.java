package org.bitcoinj.secp256k1.bouncy;

import org.bitcoinj.secp256k1.api.P256k1PrivKey;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;

import java.math.BigInteger;
import java.util.Arrays;

/**
 *
 */
public class BouncyPrivKey extends SecP256K1FieldElement implements P256k1PrivKey {

    private boolean isDestroyed = false;

    public BouncyPrivKey(BigInteger val) {
        super(val);
    }
    @Override
    public byte[] getEncoded() {
        if (isDestroyed) throw new IllegalStateException("is destroyed");
        return super.getEncoded();
    }

    @Override
    public void destroy() {
        // TODO: Make sure the zeroing is not optimized out by the compiler or JIT
        Arrays.fill(x, (byte) 0x00);
        isDestroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return isDestroyed;
    }
}
