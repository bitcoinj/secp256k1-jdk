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

import com.opencsv.CSVReaderBuilder;
import com.opencsv.exceptions.CsvException;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpResult;
import org.bitcoinj.secp.SecpScalar;
import org.bitcoinj.secp.SecpXOnlyPubKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.bitcoinj.secp.internal.SchnorrSignatureImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HexFormat;
import java.util.List;

/// Tests decoding the ElligatorSwift encoding of public keys
/// from a [CSV](https://github.com/bitcoin/bips/blob/master/bip-0324/ellswift_decode_test_vectors.csv)
/// of test vectors provided in [BIP-0327](https://github.com/bitcoin/bips/tree/master/bip-0324).
/// Based on the provided [Python reference](https://github.com/bitcoin/bips/blob/master/bip-0324/reference.py).
public class BIP327TestVectorTests implements SecpTestSupport {

    private record TestVector(byte[] ellswift, SecpFieldElement x, String comment){ }

    private final Secp256k1Foreign secp = new Secp256k1Foreign();

    static final List<TestVector> VECTORS = parseCSV();

    /// For each vector, verify that the `secp` instance decodes the Ellswift encoding
    /// into a public key with an x-coorinate matching the one in the [TestVector] argument.
    /// @param vec TestVector to be tested.
    @ParameterizedTest
    @FieldSource("VECTORS")
    void ellSwiftDecodeTest(TestVector vec) {
        SecpPubKey pubKey = secp.ellswiftDecode(vec.ellswift);

        Assertions.assertArrayEquals(vec.x.serialize(), pubKey.x().serialize());
    }

    private static List<TestVector> parseCSV() {
        try (var in = BIP327TestVectorTests.class.getResourceAsStream("/ellswift_decode_test_vectors.csv");
             var reader = new InputStreamReader(in)) {
            return new CSVReaderBuilder(reader)
                    .withSkipLines(1)
                    .build()
                    .readAll()
                    .stream()
                    .map(BIP327TestVectorTests::parseVector)
                    .toList();
        } catch (IOException | CsvException e) {
            throw new RuntimeException(e);
        }
    }

    private static TestVector parseVector(String[] f) {
        return new TestVector(
                parseHex(f[0]),                         // ellswift
                SecpFieldElement.of(parseHex(f[1])),    // private key
                f[2]                                    // comment
        );
    }

    private static byte[] parseHex(String hex) {
        return HexFormat.of().parseHex(hex);
    }
}

