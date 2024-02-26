package org.consensusj.secp256k1.examples;

import org.consensusj.secp256k1.api.P256K1KeyPair;
import org.consensusj.secp256k1.api.P256K1XOnlyPubKey;
import org.consensusj.secp256k1.api.P256k1PrivKey;
import org.consensusj.secp256k1.api.P256k1PubKey;
import org.consensusj.secp256k1.bouncy.BouncyPrivKey;
import org.consensusj.secp256k1.foreign.Secp256k1Foreign;

import java.math.BigInteger;
import java.util.HexFormat;

/**
 *
 */
public class Schnorr {
    private static final HexFormat formatter = HexFormat.of();

    private static final String msg = "Hello, world!";
    private static final String tag = "my_fancy_protocol";

    public static void main(String[] args) {
        System.out.println("Running secp256k1-jdk Schnorr example...");
        /* Use a java try-with-resources to allocate and cleanup -- secp256k1_context_destroy is automatically called */
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            /* === Key Generation === */

            /* Return a non-zero, in-range private key */
            //P256K1KeyPair keyPair = secp.ecKeyPairCreate();
            P256K1KeyPair keyPair = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE));

            /* Public key creation using a valid context with a verified secret key should never fail */
            P256k1PubKey pubkey = secp.ecPubKeyCreate(keyPair);

            P256K1XOnlyPubKey xOnly = pubkey.getXOnly();

            byte[] serializedXOnly = xOnly.getSerialized();

            /* === Signing === */

            byte[] msg_hash = secp.taggedSha256(tag, msg);

            byte[] signature = secp.schnorrSigSign32(msg_hash, keyPair);

            /* === Verification === */

            P256K1XOnlyPubKey xOnly2 = P256K1XOnlyPubKey.parse(serializedXOnly).orElseThrow();

            /* Compute the tagged hash on the received message using the same tag as the signer. */
            byte[] msg_hash2 = secp.taggedSha256(tag, msg);

            boolean is_signature_valid = secp.schnorrSigVerify(signature, msg_hash2, xOnly2).orElseThrow();

            System.out.printf("Is the signature valid? %s\n", is_signature_valid);
            System.out.printf("Secret Key: %s\n", keyPair.getS().toString(16));
            System.out.printf("Public Key (as ECPoint): %s\n", formatter.formatHex(xOnly2.getSerialized()));
            System.out.printf("Signature: %s\n", formatter.formatHex(signature));

            /* It's best practice to try to clear secrets from memory after using them.
             * This is done because some bugs can allow an attacker to leak memory, for
             * example through "out of bounds" array access (see Heartbleed), Or the OS
             * swapping them to disk. Hence, we overwrite the secret key buffer with zeros. */
            keyPair.destroy();
        }
    }
}
