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
import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpPubKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/// Tests decoding the ElligatorSwift encoding of public keys
/// from a [CSV](https://github.com/bitcoin/bips/blob/master/bip-0324/ellswift_decode_test_vectors.csv)
/// of test vectors provided in [BIP-0327](https://github.com/bitcoin/bips/tree/master/bip-0324).
/// Based on the provided [Python reference](https://github.com/bitcoin/bips/blob/master/bip-0324/reference.py).
public class BIP327TestVectorTests implements SecpTestSupport {

    private record DecodeTestVector(byte[] ellswift, SecpFieldElement x, String comment){ }
    private record EncodeTestVector(SecpPubKey pubkey, byte[] aux_rand, byte[] ellswift){ }

    private static final Secp256k1Foreign secp = new Secp256k1Foreign();

    static final List<DecodeTestVector> DECODE_VECTORS = parseDecodeCSV();
    static final List<EncodeTestVector> ENCODE_VECTORS = parseEncodeCSV();

    /// For each vector, verify that the `secp` instance decodes the Ellswift encoding
    /// into a public key with an x-coorinate matching the one in the [DecodeTestVector] argument.
    /// @param vec TestVector to be tested.
    @ParameterizedTest
    @FieldSource("DECODE_VECTORS")
    void ellSwiftDecodeTest(DecodeTestVector vec) {
        SecpPubKey pubKey = secp.ellswiftDecode(vec.ellswift);

        Assertions.assertArrayEquals(vec.x.serialize(), pubKey.x().serialize());
    }

    @ParameterizedTest
    @FieldSource("ENCODE_VECTORS")
    void ellSwiftEncodeTest(EncodeTestVector vec) {
        byte[] encoded = secp.ellswiftEncode(vec.pubkey,  vec.aux_rand);

        Assertions.assertArrayEquals(vec.ellswift, encoded);
    }

    private static List<DecodeTestVector> parseDecodeCSV() {
        try (var in = BIP327TestVectorTests.class.getResourceAsStream("/ellswift_decode_test_vectors.csv");
             var reader = new InputStreamReader(in)) {
            return new CSVReaderBuilder(reader)
                    .withSkipLines(1)
                    .build()
                    .readAll()
                    .stream()
                    .map(BIP327TestVectorTests::parseDecodeVector)
                    .toList();
        } catch (IOException | CsvException e) {
            throw new RuntimeException(e);
        }
    }

    private static List<EncodeTestVector> parseEncodeCSV() {
        try (var in = BIP327TestVectorTests.class.getResourceAsStream("/ellswift_encode_test_vectors.csv");
             var reader = new InputStreamReader(in)) {
            return new CSVReaderBuilder(reader)
                    .withSkipLines(1)
                    .build()
                    .readAll()
                    .stream()
                    .map(BIP327TestVectorTests::parseEncodeVector)
                    .toList();
        } catch (IOException | CsvException e) {
            throw new RuntimeException(e);
        }
    }

    private static DecodeTestVector parseDecodeVector(String[] f) {
        return new DecodeTestVector(
                parseHex(f[0]),                         // ellswift
                SecpFieldElement.of(parseHex(f[1])),    // private key
                f[2]                                    // comment
        );
    }
    private static EncodeTestVector parseEncodeVector(String[] f) {
        return new EncodeTestVector(
                secp.ecPubKeyParse(parseHex(f[0])).get(),   // public key
                parseHex(f[1]),                             // auxiliary random
                parseHex(f[2])                              // ellswift encoding
        );
    }

    private static byte[] parseHex(String hex) {
        return HexFormat.of().parseHex(hex);
    }
}

