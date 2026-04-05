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
package org.bitcoinj.secp.integration.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Test the HexFormat utility in our internal module. Compare with the JDK 16+ implementation.
 */
public class HexFormatTest {
    public record Pair(String hex, byte[] bytes) {}
    public static final org.bitcoinj.secp.internal.HexFormat HEX_FORMAT = new org.bitcoinj.secp.internal.HexFormat();
    public static final List<Pair> VALID_PAIRS = Map.of(
                "",     b(),
                "00",   b(0x00),
                "7F",   b(0x7F),
                "80",   b(0x80),
                "8000", b(0x80, 0x00),
                "FF",   b(0xFF),
                "FFFF", b(0xFF, 0xFF)
            ).entrySet().stream()
            .map(e -> new Pair(e.getKey(), e.getValue()))
            .toList();
    public static final List<String> INVALID_HEX_STRINGS = List.of(
            "0",
            "000",
            "G",
            "GG",
            "?",
            "??");

    @FieldSource("VALID_PAIRS")
    @ParameterizedTest(name = "n: {0}")
    void testFormat(Pair p) {
        Assertions.assertEquals(p.hex, HEX_FORMAT.formatHex(p.bytes));
    }

    @FieldSource("INVALID_HEX_STRINGS")
    @ParameterizedTest(name = "n: {0}")
    void testInvalidParse(String s) {
        // Test parsing both uppercase and lowercase hex
        Assertions.assertThrows(IllegalArgumentException.class, () -> HEX_FORMAT.parseHex(s));
        Assertions.assertThrows(IllegalArgumentException.class, () -> HEX_FORMAT.parseHex(s.toLowerCase()));
    }

    @FieldSource("VALID_PAIRS")
    @ParameterizedTest(name = "n: {0}")
    void testParse(Pair p) {
        // Test parsing both uppercase and lowercase hex
        Assertions.assertArrayEquals(p.bytes, HEX_FORMAT.parseHex(p.hex));
        Assertions.assertArrayEquals(p.bytes, HEX_FORMAT.parseHex(p.hex.toLowerCase()));
    }

    @FieldSource("VALID_PAIRS")
    @ParameterizedTest(name = "n: {0}")
    void testJDKFormat(Pair p) {
        // Test the JDK implementation for comparison
        // Note: output of JDK formatHex is expected to be lower-case.
        Assertions.assertEquals(p.hex.toLowerCase(), HexFormat.of().formatHex(p.bytes));
    }

    @FieldSource("VALID_PAIRS")
    @ParameterizedTest(name = "n: {0}")
    void testJDKParse(Pair p) {
        // Test the JDK implementation for comparison
        // Test parsing both uppercase and lowercase hex
        Assertions.assertArrayEquals(p.bytes, HexFormat.of().parseHex(p.hex));
        Assertions.assertArrayEquals(p.bytes, HexFormat.of().parseHex(p.hex.toLowerCase()));
    }

    @FieldSource("INVALID_HEX_STRINGS")
    @ParameterizedTest(name = "n: {0}")
    void testJDKInvalidParse(String s) {
        // Test parsing both uppercase and lowercase hex
        Assertions.assertThrows(IllegalArgumentException.class, () -> HexFormat.of().parseHex(s));
        Assertions.assertThrows(IllegalArgumentException.class, () -> HexFormat.of().parseHex(s.toLowerCase()));
    }

    /** helper method for specifying {@code byte[]} values */
    private static byte[] b(int... bytes) {
        byte[] result = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) result[i] = (byte) bytes[i];
        return result;
    }
}
