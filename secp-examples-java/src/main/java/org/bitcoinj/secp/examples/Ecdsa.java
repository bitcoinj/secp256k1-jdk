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
package org.bitcoinj.secp.examples;

import module org.bitcoinj.secp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

/// Java version of [secp256k1](https://github.com/bitcoin-core/secp256k1) example [ecdsa.c](https://github.com/bitcoin-core/secp256k1/blob/master/examples/ecdsa.c).
public class Ecdsa {
    final HexFormat formatter = HexFormat.of();
    /* Instead of signing the message directly, we must sign a 32-byte hash.
     * Here the message is "Hello, world!" and the hash function is SHA-256.
     * See https://bitcoin.stackexchange.com/questions/81115/if-someone-wanted-to-pretend-to-be-satoshi-by-posting-a-fake-signature-to-defrau/81116#81116
     */
    final byte[] msg_hash = hash("Hello, world!");

    void main() {
        IO.println("Running secp256k1-jdk Ecdsa example...");
        /* Use a java try-with-resources to allocate and cleanup -- secp256k1_context_destroy is automatically called */
        try (Secp256k1 secp = Secp256k1.get()) {
            /* === Key Generation === */

            /* Return a non-zero, in-range private key */
            P256k1PrivKey privKey = secp.ecPrivKeyCreate();

            /* Public key creation using a valid context with a verified secret key should never fail */
            P256k1PubKey pubkey = secp.ecPubKeyCreate(privKey);

            /* Serialize the pubkey in a compressed form (33 bytes). */
            byte[] compressed_pubkey = secp.ecPubKeySerialize(pubkey, (int)2L /* secp256k1_h.SECP256K1_EC_COMPRESSED() */);

            /* === Signing === */

            /* Generate an ECDSA signature using the RFC-6979 safe default nonce.
             * Signing with a valid context, verified secret key and the default nonce function should never fail. */
            EcdsaSignature sig = secp.ecdsaSign(msg_hash, privKey).get();

            /* Serialize the signature in a compact form. Should always succeed according to
             the documentation in secp256k1.h. */
            byte[] serialized_signature = secp.ecdsaSignatureSerializeCompact(sig);

            /* === Verification === */

            /* Deserialize the signature. This will return empty if the signature can't be parsed correctly. */
            EcdsaSignature sig2 = secp.ecdsaSignatureParseCompact(serialized_signature).get();
            assert(Arrays.equals(sig.bytes(), sig2.bytes()));

            /* Deserialize the public key. This will return empty if the public key can't be parsed correctly. */
            P256k1PubKey pubkey2 = secp.ecPubKeyParse(compressed_pubkey).get();
            assert(pubkey.getW().equals(pubkey2.getW()));

            /* Verify a signature. This will return true if it's valid and false if it's not. */
            boolean is_signature_valid = secp.ecdsaVerify(sig2, msg_hash, pubkey2).get();

            IO.println("Is the signature valid? " + is_signature_valid);
            IO.println("Secret Key: " + privKey.getS().toString(16));
            IO.println("Public Key (as ECPoint): " + pubkey);
            IO.println("Public Key (Compressed): " + formatter.formatHex(compressed_pubkey));
            IO.println("Signature: " + formatter.formatHex(serialized_signature));

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
