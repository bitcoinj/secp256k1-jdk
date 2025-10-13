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

import org.bitcoinj.secp.api.SPPrivKey;
import org.bitcoinj.secp.api.SPPubKey;
import org.bitcoinj.secp.api.SPResult;
import org.bitcoinj.secp.api.Secp256k1;
import org.bitcoinj.secp.bouncy.Bouncy256k1;
import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

// TODO: Use test vectors from: https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdh_secp256k1_test.json ??
public class EcdhTest {
    @Test
    void ecdhSmokeTest() {
        try (Secp256k1 secp = new Secp256k1Foreign()) {
            SPPrivKey secKey = SPPrivKey.of(BigInteger.ONE);
            SPPubKey pubKey = secp.ecPubKeyCreate(secKey);
            SPResult<byte[]> result = secp.ecdh(pubKey, secKey);
            Assertions.assertNotNull(result);
            Assertions.assertInstanceOf(SPResult.Ok.class, result);
            Assertions.assertEquals(32, result.get().length);
        }
    }

    @Test
    void ecdhSameTest() {
        try (Secp256k1 secp = new Secp256k1Foreign()) {
            SPPrivKey secKey1 = secp.ecPrivKeyCreate();
            SPPubKey pubKey1 = secp.ecPubKeyCreate(secKey1);

            SPPrivKey secKey2 = secp.ecPrivKeyCreate();
            SPPubKey pubKey2 = secp.ecPubKeyCreate(secKey2);

            // Compute shared secret with secKey1
            SPResult<byte[]> result1 = secp.ecdh(pubKey2, secKey1);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SPResult.Ok.class, result1);
            Assertions.assertEquals(32, result1.get().length);

            // Compute shared secret with secKey2
            SPResult<byte[]> result2 = secp.ecdh(pubKey1, secKey2);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SPResult.Ok.class, result2);
            Assertions.assertEquals(32, result2.get().length);

            // The separately computed shared secrets should be equal
            Assertions.assertArrayEquals(result1.get(), result2.get());
        }
    }

    @Test
    void ecdhSmokeTestBouncy() {
        try (Secp256k1 secp = new Bouncy256k1()) {
            SPPrivKey secKey = SPPrivKey.of(BigInteger.ONE);
            SPPubKey pubKey = secp.ecPubKeyCreate(secKey);
            SPResult<byte[]> result = secp.ecdh(pubKey, secKey);
            Assertions.assertNotNull(result);
            Assertions.assertInstanceOf(SPResult.Ok.class, result);
            Assertions.assertEquals(32, result.get().length);
        }
    }

    @Test
    void ecdhSameTestBouncy() {
        try (Secp256k1 secp = new Bouncy256k1()) {
            SPPrivKey secKey1 = secp.ecPrivKeyCreate();
            SPPubKey pubKey1 = secp.ecPubKeyCreate(secKey1);

            SPPrivKey secKey2 = secp.ecPrivKeyCreate();
            SPPubKey pubKey2 = secp.ecPubKeyCreate(secKey2);

            // Compute shared secret with secKey1
            SPResult<byte[]> result1 = secp.ecdh(pubKey2, secKey1);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SPResult.Ok.class, result1);
            Assertions.assertEquals(32, result1.get().length);

            // Compute shared secret with secKey2
            SPResult<byte[]> result2 = secp.ecdh(pubKey1, secKey2);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SPResult.Ok.class, result2);
            Assertions.assertEquals(32, result2.get().length);

            // The separately computed shared secrets should be equal
            Assertions.assertArrayEquals(result1.get(), result2.get());
        }
    }

    @Test
    void ecdhResultCompare() {
        try (Secp256k1Foreign secp1 = new Secp256k1Foreign(); Bouncy256k1 secp2 = new Bouncy256k1()) {
            SPPrivKey secKey = SPPrivKey.of(BigInteger.ONE);
            SPPubKey pubKey = secp1.ecPubKeyCreate(secKey);
            SPResult<byte[]> result1 = secp1.ecdh(pubKey, secKey);
            SPResult<byte[]> result2 = secp2.ecdh(pubKey, secKey);
            Assertions.assertArrayEquals(result1.get(), result2.get());
        }
    }

    @Test
    void ecdhSameTestCrossCheck() {
        try (Secp256k1 secp1 = new Secp256k1Foreign(); Secp256k1 secp2 = new Bouncy256k1()) {
            SPPrivKey secKey1 = secp1.ecPrivKeyCreate();
            SPPubKey pubKey1 = secp1.ecPubKeyCreate(secKey1);

            SPPrivKey secKey2 = secp2.ecPrivKeyCreate();
            SPPubKey pubKey2 = secp2.ecPubKeyCreate(secKey2);

            // Compute shared secret with secKey1 and secp1 (implementation 1)
            SPResult<byte[]> result1 = secp1.ecdh(pubKey2, secKey1);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SPResult.Ok.class, result1);
            Assertions.assertEquals(32, result1.get().length);

            // Compute shared secret with secKey2 and secp2 (implementation 2)
            SPResult<byte[]> result2 = secp2.ecdh(pubKey1, secKey2);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SPResult.Ok.class, result2);
            Assertions.assertEquals(32, result2.get().length);

            // The separately computed shared secrets should be equal
            Assertions.assertArrayEquals(result1.get(), result2.get());
        }
    }
}
