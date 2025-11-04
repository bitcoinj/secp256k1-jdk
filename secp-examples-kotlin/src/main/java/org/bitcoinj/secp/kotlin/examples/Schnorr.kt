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

import org.bitcoinj.secp.SecpXOnlyPubKey
import org.bitcoinj.secp.Secp256k1

fun main() {
    val msg = "Hello, world!"
    val tag = "my_fancy_protocol"

    println("Running secp256k1-jdk Schnorr example...")
    Secp256k1.get().use { secp ->
        /* === Key Generation === */
        /* Return a non-zero, in-range private key */
        val keyPair = secp.ecKeyPairCreate()

        /* Public key creation using a valid context with a verified secret key should never fail */
        val pubkey = secp.ecPubKeyCreate(keyPair)

        val xOnly = pubkey.xOnly()

        val serializedXOnly = xOnly.serialize()

        /* === Signing === */
        val messageHash = secp.taggedSha256(tag, msg)

        val signature = secp.schnorrSigSign32(messageHash, keyPair)

        /* === Verification === */
        val xOnly2 : SecpXOnlyPubKey = SecpXOnlyPubKey.parse(serializedXOnly).get()

        /* Compute the tagged hash on the received message using the same tag as the signer. */
        val messageHash2 = secp.taggedSha256(tag, msg)

        val isValidSignature = secp.schnorrSigVerify(signature, messageHash2, xOnly2).get()

        println("Is the signature valid? $isValidSignature")
        println("Secret Key: ${keyPair.s.toString(16)}")
        println("Public Key (x-only): $xOnly2")
        println("Signature: $signature")

        /* It's best practice to try to clear secrets from memory after using them.
         * This is done because some bugs can allow an attacker to leak memory, for
         * example through "out of bounds" array access (see Heartbleed), Or the OS
         * swapping them to disk. Hence, we overwrite the secret key buffer with zeros. */
        keyPair.destroy()
    }
}
