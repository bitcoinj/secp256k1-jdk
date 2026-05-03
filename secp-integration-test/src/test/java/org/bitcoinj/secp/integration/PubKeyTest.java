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

import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.Secp256k1;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.HexFormat;

import static org.bitcoinj.secp.integration.SecpTestSupport.parseHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 */
public class PubKeyTest implements SecpTestSupport {
    byte[] ONE_SERIALIZED = parseHex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    byte[] GOOD_X_ONLY = parseHex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    byte[] BAD_X_ONLY = parseHex("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34");

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Pubkeys for {0}")
    void testPubKeys(Secp256k1 secp) {
        SecpPrivKey privKey = SecpPrivKey.of(BigInteger.ONE);
        SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);
        assertNotNull(pubKey);
        assertEquals("Secp256k1", pubKey.getAlgorithm());
        byte[] pubKeyUncompressed = pubKey.serialize(false);
        System.out.println(HexFormat.of().formatHex(pubKeyUncompressed));
        assertArrayEquals(ONE_SERIALIZED, pubKeyUncompressed);

        SecpPoint.Uncompressed uPoint = pubKey.point();
        SecpPoint.Compressed cPoint = uPoint.compress();
        SecpPoint.Uncompressed roundTripPoint = secp.ecPointUncompress(cPoint);

        assertEquals(uPoint, roundTripPoint);
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test X-Only parsing for {0}")
    void testXOnlyParse(Secp256k1 secp) {
        assertTrue(secp.xOnlyPubKeyParse(GOOD_X_ONLY).isOk());
        assertFalse(secp.xOnlyPubKeyParse(BAD_X_ONLY).isOk());
    }
}
