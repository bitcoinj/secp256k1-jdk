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
package org.bitcoinj.secp.integration;

import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.EcdsaSignature;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.bitcoinj.secp.integration.SecpTestSupport.hash;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test ECDA Signing and verification.
 */
public class EcdsaTest implements SecpTestSupport {
    private static final byte[] msg_hash = hash("Hello, world!");

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Ecdsa for {0}")
    void testEcdsa(Secp256k1 secp) {
        SecpPrivKey privKey = secp.ecPrivKeyCreate();
        SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);
        EcdsaSignature sig = secp.ecdsaSign(msg_hash, privKey).get();
        boolean validSignature = secp.ecdsaVerify(sig, msg_hash, pubKey).get();
        assertTrue(validSignature);
    }
}
