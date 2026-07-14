/*
 * Copyright 2023-2026 secp256k1-jdk Developers.
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
package org.bitcoinj.secp.integration;

import org.bitcoinj.secp.SchnorrSignature;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpKeyPair;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertTrue;


/// Schnorr Signature Test
@ParameterizedClass
@MethodSource("secpImplementations")
public class SchnorrTest implements SecpTestSupport {
    final String msg = "Hello, world!";
    final String tag = "my_fancy_protocol";

    private final Secp256k1 secp;

    /// @param secp injected Secp256k1 implementation to test
    SchnorrTest(Secp256k1 secp) {
        this.secp = secp;
    }

     /// Test to make sure the FFM implementation can Schnorr-sign and verify its own message.
    @Test
    void testSchnorr() {
        SecpKeyPair keyPair = secp.ecKeyPairCreate();
        SecpXOnlyPubKey xOnly = keyPair.publicKey().xOnly();
        byte[] messageHash = secp.taggedSha256(tag, msg);
        SchnorrSignature signature = secp.schnorrSigSign32(messageHash, keyPair);
        boolean isValid = secp.schnorrSigVerify(signature, messageHash, xOnly).get();
        assertTrue(isValid);
    }
}
