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
package org.bitcoinj.secp.integration;

import org.bitcoinj.secp.api.P256K1Point;
import org.bitcoinj.secp.api.P256k1PrivKey;
import org.bitcoinj.secp.api.P256k1PubKey;
import org.bitcoinj.secp.api.Secp256k1;
import org.bitcoinj.secp.api.Secp256k1Provider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.Arrays;
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
public class PubKeyTest {
    byte[] ONE_SERIALIZED = HexFormat.of().parseHex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    public static Stream<Secp256k1> secpImplementations() {
        return secpProviders().map(Secp256k1Provider::get);
    }

    public static Stream<Secp256k1Provider> secpProviders() {
        var providerList = List.of("ffm", "bouncy-castle");
        return Secp256k1Provider.findAll(p -> providerList.contains(p.name()));
    }

    @MethodSource("secpProviders")
    @ParameterizedTest(name = "Provider: {0}")
    void checkProviders(Secp256k1Provider provider) {
        System.out.println("Provider " + provider.name());
        assertTrue(provider.name().length() > 1);
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Implementation for {0}")
    void checkImplementations(Secp256k1 secp) {
        System.out.println("Implementation " + secp.toString());
        assertNotNull(secp);
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Pubkeys for {0}")
    void testPubKeys(Secp256k1 secp) {
        P256k1PrivKey privKey = P256k1PrivKey.of(BigInteger.ONE);
        P256k1PubKey pubKey = secp.ecPubKeyCreate(privKey);
        assertNotNull(pubKey);
        assertEquals("Secp256k1", pubKey.getAlgorithm());
        byte[] pubKeyUncompressed = pubKey.getUncompressed();
        System.out.println(HexFormat.of().formatHex(pubKeyUncompressed));
        assertArrayEquals(ONE_SERIALIZED, pubKeyUncompressed);

        P256K1Point.Uncompressed uPoint = pubKey.getPoint();
        P256K1Point.Compressed cPoint = uPoint.compress();
        P256K1Point.Uncompressed roundTripPoint = secp.ecPointUncompress(cPoint);

        assertEquals(uPoint, roundTripPoint);
    }

}
