package org.consensusj.secp256k1.bouncy;

import org.consensusj.secp256k1.api.P256k1PubKey;
import org.consensusj.secp256k1.api.Secp256k1;
import org.consensusj.secp256k1.foreign.Secp256k1Foreign;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.spec.ECPoint;

/**
 *
 */
public class Bouncy256k1Test {
    @Test
    void pubKeyAdditionTestTwo() {
        try (Bouncy256k1 secp = new Bouncy256k1()) {
            P256k1PubKey pubKey = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE)).getPublic();
            P256k1PubKey added = secp.ecPubKeyCombine(pubKey, pubKey);
            P256k1PubKey multiplied = secp.ecPubKeyTweakMul(pubKey, BigInteger.valueOf(2));
            Assertions.assertEquals(added.getW(), multiplied.getW());
        }
    }
}
