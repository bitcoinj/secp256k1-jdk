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

import org.bitcoinj.secp.EcdhSharedSecret;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpResult;
import org.bitcoinj.secp.Secp256k1;
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
            SecpPrivKey secKey = SecpPrivKey.of(BigInteger.ONE);
            SecpPubKey pubKey = secp.ecPubKeyCreate(secKey);
            SecpResult<EcdhSharedSecret> result = secp.ecdh(pubKey, secKey);
            Assertions.assertNotNull(result);
            Assertions.assertInstanceOf(SecpResult.Ok.class, result);
            Assertions.assertEquals(32, result.get().bytes().length);
        }
    }

    @Test
    void ecdhSameTest() {
        try (Secp256k1 secp = new Secp256k1Foreign()) {
            SecpPrivKey secKey1 = secp.ecPrivKeyCreate();
            SecpPubKey pubKey1 = secp.ecPubKeyCreate(secKey1);

            SecpPrivKey secKey2 = secp.ecPrivKeyCreate();
            SecpPubKey pubKey2 = secp.ecPubKeyCreate(secKey2);

            // Compute shared secret with secKey1
            SecpResult<EcdhSharedSecret> result1 = secp.ecdh(pubKey2, secKey1);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SecpResult.Ok.class, result1);
            Assertions.assertEquals(32, result1.get().bytes().length);

            // Compute shared secret with secKey2
            SecpResult<EcdhSharedSecret> result2 = secp.ecdh(pubKey1, secKey2);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SecpResult.Ok.class, result2);
            Assertions.assertEquals(32, result2.get().bytes().length);

            // The separately computed shared secrets should be equal
            Assertions.assertEquals(result1.get(), result2.get());
        }
    }

    @Test
    void ecdhSmokeTestBouncy() {
        try (Secp256k1 secp = new Bouncy256k1()) {
            SecpPrivKey secKey = SecpPrivKey.of(BigInteger.ONE);
            SecpPubKey pubKey = secp.ecPubKeyCreate(secKey);
            SecpResult<EcdhSharedSecret> result = secp.ecdh(pubKey, secKey);
            Assertions.assertNotNull(result);
            Assertions.assertInstanceOf(SecpResult.Ok.class, result);
            Assertions.assertEquals(32, result.get().bytes().length);
        }
    }

    @Test
    void ecdhSameTestBouncy() {
        try (Secp256k1 secp = new Bouncy256k1()) {
            SecpPrivKey secKey1 = secp.ecPrivKeyCreate();
            SecpPubKey pubKey1 = secp.ecPubKeyCreate(secKey1);

            SecpPrivKey secKey2 = secp.ecPrivKeyCreate();
            SecpPubKey pubKey2 = secp.ecPubKeyCreate(secKey2);

            // Compute shared secret with secKey1
            SecpResult<EcdhSharedSecret> result1 = secp.ecdh(pubKey2, secKey1);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SecpResult.Ok.class, result1);
            Assertions.assertEquals(32, result1.get().bytes().length);

            // Compute shared secret with secKey2
            SecpResult<EcdhSharedSecret> result2 = secp.ecdh(pubKey1, secKey2);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SecpResult.Ok.class, result2);
            Assertions.assertEquals(32, result2.get().bytes().length);

            // The separately computed shared secrets should be equal
            Assertions.assertEquals(result1.get(), result2.get());
        }
    }

    @Test
    void ecdhResultCompare() {
        try (Secp256k1Foreign secp1 = new Secp256k1Foreign(); Bouncy256k1 secp2 = new Bouncy256k1()) {
            SecpPrivKey secKey = SecpPrivKey.of(BigInteger.ONE);
            SecpPubKey pubKey = secp1.ecPubKeyCreate(secKey);
            SecpResult<EcdhSharedSecret> result1 = secp1.ecdh(pubKey, secKey);
            SecpResult<EcdhSharedSecret> result2 = secp2.ecdh(pubKey, secKey);
            Assertions.assertEquals(result1.get(), result2.get());
        }
    }

    @Test
    void ecdhSameTestCrossCheck() {
        try (Secp256k1 secp1 = new Secp256k1Foreign(); Secp256k1 secp2 = new Bouncy256k1()) {
            SecpPrivKey secKey1 = secp1.ecPrivKeyCreate();
            SecpPubKey pubKey1 = secp1.ecPubKeyCreate(secKey1);

            SecpPrivKey secKey2 = secp2.ecPrivKeyCreate();
            SecpPubKey pubKey2 = secp2.ecPubKeyCreate(secKey2);

            // Compute shared secret with secKey1 and secp1 (implementation 1)
            SecpResult<EcdhSharedSecret> result1 = secp1.ecdh(pubKey2, secKey1);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SecpResult.Ok.class, result1);
            Assertions.assertEquals(32, result1.get().bytes().length);

            // Compute shared secret with secKey2 and secp2 (implementation 2)
            SecpResult<EcdhSharedSecret> result2 = secp2.ecdh(pubKey1, secKey2);
            Assertions.assertNotNull(result1);
            Assertions.assertInstanceOf(SecpResult.Ok.class, result2);
            Assertions.assertEquals(32, result2.get().bytes().length);

            // The separately computed shared secrets should be equal
            Assertions.assertEquals(result1.get(), result2.get());
        }
    }
}
