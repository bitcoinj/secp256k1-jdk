package org.consensusj.secp256k1.api;

import org.consensusj.secp256k1.bouncy.BouncyPrivKey;
import org.consensusj.secp256k1.eggcc.EggPrivKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

/**
 *
 */
public class PrivKeyDataTest {
    static final byte[] ones;

    static {
        ones = new byte[32];
        ones[31] = 1;
    }

    @Test
    void testBouncyPriv() {
        P256k1PrivKey priv = new BouncyPrivKey(BigInteger.ONE);

        BigInteger privInt = priv.integer();
        Assertions.assertEquals(BigInteger.ONE, privInt);

        byte[] privBytes = priv.bytes();
        Assertions.assertArrayEquals(ones, privBytes);
    }

    @Test
    void testEggPriv() {
        P256k1PrivKey priv = new EggPrivKey(BigInteger.ONE);

        BigInteger privInt = priv.integer();
        Assertions.assertEquals(BigInteger.ONE, privInt);

        byte[] privBytes = priv.bytes();
        Assertions.assertArrayEquals(ones, privBytes);
    }

}
