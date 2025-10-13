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

import org.bitcoinj.secp.api.SPPoint;
import org.bitcoinj.secp.api.SPPrivKey;
import org.bitcoinj.secp.api.SPPubKey;
import org.bitcoinj.secp.api.Secp256k1;
import org.bitcoinj.secp.api.Secp256k1Provider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 */
public class PubKeyTest {
    byte[] ONE_SERIALIZED = HexFormat.of().parseHex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

    public static Stream<Secp256k1> secpImplementations() {
        return Secp256k1Provider.all().map(Secp256k1Provider::get);
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Pubkeys for {0}")
    void testPubKeys(Secp256k1 secp) {
        SPPrivKey privKey = SPPrivKey.of(BigInteger.ONE);
        SPPubKey pubKey = secp.ecPubKeyCreate(privKey);
        assertNotNull(pubKey);
        assertEquals("Secp256k1", pubKey.getAlgorithm());
        byte[] pubKeyUncompressed = pubKey.getUncompressed();
        System.out.println(HexFormat.of().formatHex(pubKeyUncompressed));
        assertArrayEquals(ONE_SERIALIZED, pubKeyUncompressed);

        SPPoint.Uncompressed uPoint = pubKey.point();
        SPPoint.Compressed cPoint = uPoint.compress();
        SPPoint.Uncompressed roundTripPoint = secp.ecPointUncompress(cPoint);

        assertEquals(uPoint, roundTripPoint);
    }
}
