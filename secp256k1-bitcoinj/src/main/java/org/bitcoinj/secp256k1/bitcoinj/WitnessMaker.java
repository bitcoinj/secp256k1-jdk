package org.bitcoinj.secp256k1.bitcoinj;

import org.bitcoinj.secp256k1.api.P256K1XOnlyPubKey;
import org.bitcoinj.secp256k1.api.P256k1PubKey;
import org.bitcoinj.secp256k1.api.Secp256k1;
import org.bitcoinj.secp256k1.foreign.PubKeyPojo;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Experimental class for making P2TR witness programs
 */
public class WitnessMaker {
    /**
     * 64-byte concatenation of two 32-byte hashes of "TapTweak"
     */
    private static final byte[] tweakPrefix = calcTagPrefix64("TapTweak");
    private final Secp256k1 secp;

    public WitnessMaker(Secp256k1 secp) {
        this.secp = secp;
    }

    public byte[] calcWitnessProgram(P256k1PubKey pubKey) {
        P256K1XOnlyPubKey xOnlyKey = pubKey.getXOnly();
        BigInteger tweakInt = calcTweak(xOnlyKey);
        P256k1PubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
        P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
        P256k1PubKey Q = secp.ecPubKeyCombine(pubKey, P2);
        return Q.getXOnly().getSerialized();
    }

    public static BigInteger calcTweak(P256K1XOnlyPubKey xOnlyPubKey) {
        var digest = newDigest();
        digest.update(tweakPrefix);
        byte[] hash = digest.digest(xOnlyPubKey.getSerialized());
        return new BigInteger(1, hash);
    }

    public static byte[] calcTagPrefix64(String tag) {
        byte[] hash = hash256(tag.getBytes(StandardCharsets.UTF_8));
        return ByteBuffer.allocate(64)
                .put(hash)
                .put(hash)
                .array();
    }

    private static byte[] hash256(byte[] message) {
        return newDigest().digest(message);
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }
}
