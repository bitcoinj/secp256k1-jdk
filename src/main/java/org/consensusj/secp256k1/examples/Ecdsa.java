package org.consensusj.secp256k1.examples;

import org.consensusj.secp256k1.api.CompressedPubKeyData;
import org.consensusj.secp256k1.api.CompressedSignatureData;
import org.consensusj.secp256k1.api.P256k1PrivKey;
import org.consensusj.secp256k1.api.P256k1PubKey;
import org.consensusj.secp256k1.api.SignatureData;
import org.consensusj.secp256k1.foreign.Secp256k1Foreign;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

import static org.consensusj.secp256k1.secp256k1_h.SECP256K1_EC_COMPRESSED;

/**
 * Port of secp256k1 sample {@code ecdsa.c} to Java
 */
public class Ecdsa {
    private static final HexFormat formatter = HexFormat.of();
    /* Instead of signing the message directly, we must sign a 32-byte hash.
     * Here the message is "Hello, world!" and the hash function is SHA-256.
     * See https://bitcoin.stackexchange.com/questions/81115/if-someone-wanted-to-pretend-to-be-satoshi-by-posting-a-fake-signature-to-defrau/81116#81116
     */
    private static final byte[] msg_hash = hash("Hello, world!");

    public static void main(String[] args) {
        /* Use a java try-with-resources to allocate and cleanup -- secp256k1_context_destroy is automatically called */
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            /* === Key Generation === */

            /* Return a non-zero, in-range private key */
            P256k1PrivKey privKey = secp.ecPrivKeyCreate();
            //PrivKeyData privKey = new BouncyPrivKey(BigInteger.ONE);

            /* Public key creation using a valid context with a verified secret key should never fail */
            P256k1PubKey pubkey = secp.ecPubKeyCreate(privKey);

            /* Serialize the pubkey in a compressed form(33 bytes). */
            CompressedPubKeyData compressed_pubkey = secp.ecPubKeySerialize(pubkey, SECP256K1_EC_COMPRESSED());

            /* === Signing === */

            /* Generate an ECDSA signature using the RFC-6979 safe default nonce.
             * Signing with a valid context, verified secret key and the default nonce function should never fail. */
            SignatureData sig = secp.ecdsaSign(msg_hash, privKey).orElseThrow();

            /* Serialize the signature in a compact form. Should always succeed according to
             the documentation in secp256k1.h. */
            CompressedSignatureData serialized_signature = secp.ecdsaSignatureSerializeCompact(sig).orElseThrow();

            /* === Verification === */

            /* Deserialize the signature. This will return empty if the signature can't be parsed correctly. */
            SignatureData sig2 = secp.ecdsaSignatureParseCompact(serialized_signature).orElseThrow();
            assert(Arrays.equals(sig.bytes(), sig2.bytes()));

            /* Deserialize the public key. This will return empty if the public key can't be parsed correctly. */
            P256k1PubKey pubkey2 = secp.ecPubKeyParse(compressed_pubkey).orElseThrow();
            assert(pubkey.getW().equals(pubkey2.getW()));

            /* Verify a signature. This will return true if it's valid and false if it's not. */
            boolean is_signature_valid = secp.ecdsaVerify(sig2, msg_hash, pubkey2).orElseThrow();

            System.out.printf("Is the signature valid? %s\n", is_signature_valid);
            System.out.printf("Secret Key: %s\n", formatter.formatHex(privKey.bytes()));
            System.out.printf("Public Key (as ECPoint): %s\n", pubkey);
            System.out.printf("Public Key (Compressed): %s\n", formatter.formatHex(compressed_pubkey.bytes()));
            System.out.printf("Signature: %s\n", formatter.formatHex(serialized_signature.bytes()));

            /* It's best practice to try to clear secrets from memory after using them.
             * This is done because some bugs can allow an attacker to leak memory, for
             * example through "out of bounds" array access (see Heartbleed), Or the OS
             * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
             */
            privKey.destroy();
        }

    }

    private static byte[] hash(String messageString) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
        byte[] message = messageString.getBytes();
        digest.update(message, 0, message.length);
        return digest.digest();
    }
}
