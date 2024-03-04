package org.bitcoinj.secp256k1.integration;

import org.bitcoinj.secp256k1.api.P256k1PrivKey;
import org.bitcoinj.secp256k1.api.P256k1PubKey;
import org.bitcoinj.secp256k1.api.Secp256k1;
import org.bitcoinj.secp256k1.bouncy.Bouncy256k1;
import org.bitcoinj.secp256k1.bouncy.BouncyPrivKey;
import org.bitcoinj.secp256k1.foreign.Secp256k1Foreign;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.spec.ECPoint;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 */
public class CurveTest {
    static final ECPoint G = Secp256k1.EC_PARAMS.getGenerator();

    @Test
    void pubKeyCalc() {
        try (var secp = new Secp256k1Foreign(); var bouncy = new Bouncy256k1()) {
            P256k1PrivKey privkey = new BouncyPrivKey(BigInteger.ONE);

            // Create pubkeys with both implementations
            P256k1PubKey pubkey_secp = secp.ecPubKeyCreate(privkey);
            P256k1PubKey pubkey_bouncy = bouncy.ecPubKeyCreate(privkey);

            // A private key of `1` should result in a public key of `G`
            assertEquals(G, pubkey_secp.getW());
            assertEquals(G, pubkey_bouncy.getW());
            assertEquals(pubkey_secp.getW(), pubkey_bouncy.getW());
        }
    }
}
