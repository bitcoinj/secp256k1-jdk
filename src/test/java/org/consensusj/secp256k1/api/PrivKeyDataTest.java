package org.consensusj.secp256k1.api;

import org.bitcoinj.secp256k1.api.P256k1PrivKey;
import org.bitcoinj.secp256k1.bouncy.BouncyPrivKey;
import org.bitcoinj.secp256k1.eggcc.EggPrivKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

/**
 *
 */
public class PrivKeyDataTest {
    @Test
    void testBouncyPriv() {
        P256k1PrivKey priv = new BouncyPrivKey(BigInteger.ONE);

        BigInteger privInt = priv.getS();
        Assertions.assertEquals(BigInteger.ONE, privInt);
    }

    @Test
    void testEggPriv() {
        P256k1PrivKey priv = new EggPrivKey(BigInteger.ONE);

        BigInteger privInt = priv.getS();
        Assertions.assertEquals(BigInteger.ONE, privInt);
    }

}
