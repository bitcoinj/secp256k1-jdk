package org.consensusj.secp256k1.foreign;

import org.consensusj.secp256k1.api.P256k1PrivKey;
import org.consensusj.secp256k1.api.P256k1PubKey;
import org.consensusj.secp256k1.api.Secp256k1;
import org.consensusj.secp256k1.bouncy.BouncyPrivKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

/**
 *
 */
public class Secp256k1ForeignTest {
    @Test
    void pubKeyAdditionTestOne() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            P256k1PubKey pubKey = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE)).getPublic();
            P256k1PubKey added = secp.ecPubKeyCombine(pubKey);
            P256k1PubKey multiplied = secp.ecPubKeyTweakMul(pubKey, BigInteger.valueOf(1));
            Assertions.assertEquals(added.getW(), multiplied.getW());
        }
    }

    @Test
    void pubKeyAdditionTestTwo() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            P256k1PubKey pubKey = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE)).getPublic();
            P256k1PubKey added = secp.ecPubKeyCombine(pubKey, pubKey);
            P256k1PubKey multiplied = secp.ecPubKeyTweakMul(pubKey, BigInteger.valueOf(2));
            Assertions.assertEquals(added.getW(), multiplied.getW());
        }
    }

}
