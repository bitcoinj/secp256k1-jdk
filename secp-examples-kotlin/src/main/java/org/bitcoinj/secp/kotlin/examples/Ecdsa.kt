/*
 * Copyright 2023-2025 secp256k1-jdk Developers.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoinj.secp.kotlin.examples

import org.bitcoinj.secp.api.Secp256k1
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*

/**
 * Port of secp256k1 sample `ecdsa.c` to Kotlin
 */
fun main() {
    val formatter: HexFormat = HexFormat.of()

    /* Instead of signing the message directly, we must sign a 32-byte hash.
     * Here the message is "Hello, world!" and the hash function is SHA-256.
     * See https://bitcoin.stackexchange.com/questions/81115/if-someone-wanted-to-pretend-to-be-satoshi-by-posting-a-fake-signature-to-defrau/81116#81116
     */
    val msg_hash = hash("Hello, world!")

    println("Running secp256k1-jdk Ecdsa example...")
    Secp256k1.getByName("ffm").use { secp ->
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
        val sig = secp.ecdsaSign(msg_hash, privKey).get()

        /* Serialize the signature in a compact form. Should always succeed according to
         the documentation in secp256k1.h. */
        val serialized_signature = secp.ecdsaSignatureSerializeCompact(sig).get()

        /* === Verification === */

        /* Deserialize the signature. This will return empty if the signature can't be parsed correctly. */
        val sig2 = secp.ecdsaSignatureParseCompact(serialized_signature).get()
        assert(sig.bytes().contentEquals(sig2.bytes()))
        /* Deserialize the public key. This will return empty if the public key can't be parsed correctly. */
        val pubkey2 = secp.ecPubKeyParse(compressed_pubkey).get()
        assert(pubkey.w == pubkey2.w)
        /* Verify a signature. This will return true if it's valid and false if it's not. */
        val is_signature_valid = secp.ecdsaVerify(sig2, msg_hash, pubkey2).get()

        println("Is the signature valid? $is_signature_valid")
        println("Secret Key: ${privKey.s.toString(16)}")
        println("Public Key (as ECPoint): $pubkey")
        println("Public Key (Compressed): ${formatter.formatHex(compressed_pubkey)}")
        println("Signature: ${formatter.formatHex(serialized_signature.bytes())}")

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
