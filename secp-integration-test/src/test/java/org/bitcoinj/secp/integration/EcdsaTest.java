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

import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.EcdsaSignature;
import org.bitcoinj.secp.bouncy.Bouncy256k1;
import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.bitcoinj.secp.integration.SecpTestSupport.hash;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
        boolean validSignature = secp.ecdsaVerify(sig, msg_hash, pubKey);
        assertTrue(validSignature);
    }

    @Test
    void ecdsaCrossCheck() {
        try (Secp256k1 secp1 = new Secp256k1Foreign(); Secp256k1 secp2 = new Bouncy256k1()) {
            SecpPrivKey secKey1 = secp1.ecPrivKeyCreate();
            SecpPubKey pubKey1 = secp1.ecPubKeyCreate(secKey1);

            SecpPrivKey secKey2 = secKey1;
            SecpPubKey pubKey2 = secp2.ecPubKeyCreate(secKey1);

            assertArrayEquals(pubKey1.serialize(), pubKey2.serialize());

            EcdsaSignature sig1 = secp1.ecdsaSign(msg_hash, secKey1).get();
            EcdsaSignature sig2 = secp2.ecdsaSign(msg_hash, secKey2).get();

            assertArrayEquals(sig1.serializeCompact(), sig2.serializeCompact());

            assertTrue(secp1.ecdsaVerify(sig1, msg_hash, pubKey1));
            assertTrue(secp1.ecdsaVerify(sig2, msg_hash, pubKey2));
            assertTrue(secp2.ecdsaVerify(sig1, msg_hash, pubKey1));
            assertTrue(secp2.ecdsaVerify(sig2, msg_hash, pubKey2));
        }
    }
}
