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

/// Java version of [secp256k1](https://github.com/bitcoin-core/secp256k1) example [schnorr.c](https://github.com/bitcoin-core/secp256k1/blob/master/examples/schnorr.c).
public class Schnorr {
    final String msg = "Hello, world!";
    final String tag = "my_fancy_protocol";

    void main() {
        IO.println("Running secp256k1-jdk Schnorr example...");
        /* Use a java try-with-resources to allocate and cleanup -- secp256k1_context_destroy is automatically called */
        try (Secp256k1 secp = Secp256k1.get()) {
            /* === Key Generation === */

            /* Return a non-zero, in-range private key */
            P256K1KeyPair keyPair = secp.ecKeyPairCreate();
            //P256K1KeyPair keyPair = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE));

            /* Public key creation using a valid context with a verified secret key should never fail */
            P256k1PubKey pubkey = secp.ecPubKeyCreate(keyPair);

            P256K1XOnlyPubKey xOnly = pubkey.xOnly();

            byte[] serializedXOnly = xOnly.serialize();

            /* === Signing === */

            byte[] messageHash = secp.taggedSha256(tag, msg);

            SchnorrSignature signature = secp.schnorrSigSign32(messageHash, keyPair);

            /* === Verification === */

            P256K1XOnlyPubKey xOnly2 = P256K1XOnlyPubKey.parse(serializedXOnly).get();

            /* Compute the tagged hash on the received message using the same tag as the signer. */
            byte[] messageHash2 = secp.taggedSha256(tag, msg);

            boolean isValidSignature = secp.schnorrSigVerify(signature, messageHash2, xOnly2).get();

            IO.println("Is the signature valid? " + isValidSignature);
            IO.println("Secret Key: " + keyPair.getS().toString(16));
            IO.println("Public Key (x-only): " + xOnly2);
            IO.println("Signature: " + signature.formatHex());

            /* It's best practice to try to clear secrets from memory after using them.
             * This is done because some bugs can allow an attacker to leak memory, for
             * example through "out of bounds" array access (see Heartbleed), Or the OS
             * swapping them to disk. Hence, we overwrite the secret key buffer with zeros. */
            keyPair.destroy();
        }
    }
}
