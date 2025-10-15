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

import org.bitcoinj.secp.api.P256K1Point;
import org.bitcoinj.secp.api.P256k1PrivKey;
import org.bitcoinj.secp.api.P256k1PubKey;
import org.bitcoinj.secp.api.Secp256k1;
import org.bitcoinj.secp.api.Secp256k1Provider;
import org.bitcoinj.secp.api.SignatureData;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 */
public class EcdsaTest {
    private static final byte[] msg_hash = hash("Hello, world!");

    public static Stream<Secp256k1> secpImplementations() {
        var providerList = List.of("ffm", "bouncy-castle");
        return Secp256k1Provider
                .findAll(p -> providerList.contains(p.name()))
                .map(Secp256k1Provider::get);
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Ecdsa for {0}")
    void testEcdsa(Secp256k1 secp) {
        P256k1PrivKey privKey = secp.ecPrivKeyCreate();;
        P256k1PubKey pubKey = secp.ecPubKeyCreate(privKey);
        SignatureData sig = secp.ecdsaSign(msg_hash, privKey).get();
        boolean validSignature = secp.ecdsaVerify(sig, msg_hash, pubKey).get();
        assertTrue(validSignature);
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
