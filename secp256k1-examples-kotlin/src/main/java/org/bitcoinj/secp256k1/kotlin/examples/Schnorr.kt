/*
 * Copyright 2023-2024 secp256k1-jdk Developers.
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
package org.bitcoinj.secp256k1.kotlin.examples

import org.bitcoinj.secp256k1.api.P256K1XOnlyPubKey
import org.bitcoinj.secp256k1.foreign.Secp256k1Foreign
import java.util.*

/**
 *
 */
object Schnorr {
    private val formatter: HexFormat = HexFormat.of()

    private const val msg = "Hello, world!"
    private const val tag = "my_fancy_protocol"

    @JvmStatic
    fun main(args: Array<String>) {
        println("Running secp256k1-jdk Schnorr example...")
        Secp256k1Foreign().use { secp ->
            /* === Key Generation === */
            /* Return a non-zero, in-range private key */
            val keyPair = secp.ecKeyPairCreate()

            //P256K1KeyPair keyPair = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE));

            /* Public key creation using a valid context with a verified secret key should never fail */
            val pubkey = secp.ecPubKeyCreate(keyPair)

            val xOnly = pubkey.xOnly

            val serializedXOnly = xOnly.getSerialized()

            /* === Signing === */
            val msg_hash = secp.taggedSha256(tag, msg)

            val signature = secp.schnorrSigSign32(msg_hash, keyPair)

            /* === Verification === */
            val xOnly2 : P256K1XOnlyPubKey = P256K1XOnlyPubKey.parse(serializedXOnly).get()

            /* Compute the tagged hash on the received message using the same tag as the signer. */
            val msg_hash2 = secp.taggedSha256(tag, msg)

            val is_signature_valid = secp.schnorrSigVerify(signature, msg_hash2, xOnly2).get()

            System.out.printf("Is the signature valid? %s\n", is_signature_valid)
            System.out.printf("Secret Key: %s\n", keyPair.s.toString(16))
            System.out.printf("Public Key (as ECPoint): %s\n", formatter.formatHex(xOnly2.serialized))
            System.out.printf("Signature: %s\n", formatter.formatHex(signature))

            /* It's best practice to try to clear secrets from memory after using them.
             * This is done because some bugs can allow an attacker to leak memory, for
             * example through "out of bounds" array access (see Heartbleed), Or the OS
             * swapping them to disk. Hence, we overwrite the secret key buffer with zeros. */
            keyPair.destroy()
        }
    }
}
