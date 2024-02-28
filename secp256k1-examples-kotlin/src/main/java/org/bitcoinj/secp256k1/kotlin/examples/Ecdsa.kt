package org.bitcoinj.secp256k1.kotlin.examples

import org.bitcoinj.secp256k1.foreign.Secp256k1Foreign
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*

/**
 * Port of secp256k1 sample `ecdsa.c` to Java
 */
object Ecdsa {
    private val formatter: HexFormat = HexFormat.of()

    /* Instead of signing the message directly, we must sign a 32-byte hash.
     * Here the message is "Hello, world!" and the hash function is SHA-256.
     * See https://bitcoin.stackexchange.com/questions/81115/if-someone-wanted-to-pretend-to-be-satoshi-by-posting-a-fake-signature-to-defrau/81116#81116
     */
    private val msg_hash = hash("Hello, world!")

    @JvmStatic
    fun main(args: Array<String>) {
        println("Running secp256k1-jdk Ecdsa example...")
        Secp256k1Foreign().use { secp ->
            /* === Key Generation === */
            /* Return a non-zero, in-range private key */
            val privKey = secp.ecPrivKeyCreate()

            //P256k1PrivKey privKey = new BouncyPrivKey(BigInteger.ONE);

            /* Public key creation using a valid context with a verified secret key should never fail */
            val pubkey = secp.ecPubKeyCreate(privKey)

            /* Serialize the pubkey in a compressed form(33 bytes). */
            val compressed_pubkey = secp.ecPubKeySerialize(pubkey, 258 /* secp256k1_h.SECP256K1_EC_COMPRESSED() */)

            /* === Signing === */

            /* Generate an ECDSA signature using the RFC-6979 safe default nonce.
             * Signing with a valid context, verified secret key and the default nonce function should never fail. */
            val sig = secp.ecdsaSign(msg_hash, privKey).unwrap()

            /* Serialize the signature in a compact form. Should always succeed according to
             the documentation in secp256k1.h. */
            val serialized_signature = secp.ecdsaSignatureSerializeCompact(sig).unwrap()

            /* === Verification === */

            /* Deserialize the signature. This will return empty if the signature can't be parsed correctly. */
            val sig2 = secp.ecdsaSignatureParseCompact(serialized_signature).unwrap()
            assert(sig.bytes().contentEquals(sig2.bytes()))
            /* Deserialize the public key. This will return empty if the public key can't be parsed correctly. */
            val pubkey2 = secp.ecPubKeyParse(compressed_pubkey).unwrap()
            assert(pubkey.w == pubkey2.w)
            /* Verify a signature. This will return true if it's valid and false if it's not. */
            val is_signature_valid = secp.ecdsaVerify(sig2, msg_hash, pubkey2).unwrap()

            System.out.printf("Is the signature valid? %s\n", is_signature_valid)
            System.out.printf("Secret Key: %s\n", privKey.s.toString(16))
            System.out.printf("Public Key (as ECPoint): %s\n", pubkey)
            System.out.printf("Public Key (Compressed): %s\n", formatter.formatHex(compressed_pubkey.bytes()))
            System.out.printf("Signature: %s\n", formatter.formatHex(serialized_signature.bytes()))

            /* It's best practice to try to clear secrets from memory after using them.
             * This is done because some bugs can allow an attacker to leak memory, for
             * example through "out of bounds" array access (see Heartbleed), Or the OS
             * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
             */
            privKey.destroy()
        }
    }

    private fun hash(messageString: String): ByteArray {
        val digest: MessageDigest
        try {
            digest = MessageDigest.getInstance("SHA-256")
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e) // Can't happen.
        }
        val message = messageString.toByteArray()
        digest.update(message, 0, message.size)
        return digest.digest()
    }
}
