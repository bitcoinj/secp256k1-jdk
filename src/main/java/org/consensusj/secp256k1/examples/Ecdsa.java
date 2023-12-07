package org.consensusj.secp256k1.examples;

import org.consensusj.secp256k1.foreign.Secp256k1;

import java.lang.foreign.MemorySegment;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
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
        try (Secp256k1 secp = new Secp256k1()) {
            /* === Key Generation === */

            /* Return a non-zero, in-range private key */
            MemorySegment seckey = secp.ecPrivKeyCreate().orElseThrow();

            /* Public key creation using a valid context with a verified secret key should never fail */
            MemorySegment pubkey = secp.ecPubKeyCreate(seckey).orElseThrow();

            /* Serialize the pubkey in a compressed form(33 bytes). */
            MemorySegment compressed_pubkey = secp.ecPubKeySerialize(pubkey, SECP256K1_EC_COMPRESSED()).orElseThrow();

            /* === Signing === */

            /* Generate an ECDSA signature using the RFC-6979 safe default nonce.
             * Signing with a valid context, verified secret key and the default nonce function should never fail. */
            MemorySegment sig = secp.ecdsaSign(msg_hash, seckey).orElseThrow();

            /* Serialize the signature in a compact form. Should always succeed according to
             the documentation in secp256k1.h. */
            MemorySegment serialized_signature = secp.ecdsaSignatureSerializeCompact(sig).orElseThrow();

            /* === Verification === */

            /* Deserialize the signature. This will return empty if the signature can't be parsed correctly. */
            MemorySegment sig2 = secp.ecdsaSignatureParseCompact(serialized_signature).orElseThrow();
            assert(Arrays.equals(sig.toArray(JAVA_BYTE), sig2.toArray(JAVA_BYTE)));

            /* Deserialize the public key. This will return empty if the public key can't be parsed correctly. */
            MemorySegment pubkey2 = secp.ecPubKeyParse(compressed_pubkey).orElseThrow();
            assert(Arrays.equals(pubkey.toArray(JAVA_BYTE), pubkey2.toArray(JAVA_BYTE)));

            /* Verify a signature. This will return true if it's valid and false if it's not. */
            boolean is_signature_valid = secp.ecdsaVerify(sig, msg_hash, pubkey).orElseThrow();

            System.out.printf("Is the signature valid? %s\n", is_signature_valid);
            System.out.printf("Secret Key: %s\n", formatter.formatHex(seckey.toArray(JAVA_BYTE)));
            System.out.printf("Public Key: %s\n", formatter.formatHex(compressed_pubkey.toArray(JAVA_BYTE)));
            System.out.printf("Signature: %s\n", formatter.formatHex(serialized_signature.toArray(JAVA_BYTE)));
        }

        // Bonus example TBD: use the static ecdsaVerify() method to verify a signature
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
