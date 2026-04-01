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
import org.bitcoinj.secp.SchnorrSignature;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpResult;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.ffm.Secp256k1Foreign;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

/// Tests public key generation from a private key and Schnorr signing and verification
/// from a [CSV](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv)
/// of test vectors provided in [BIP-0340](https://github.com/bitcoin/bips/tree/master/bip-0340).
/// Based on the provided [Python reference](https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py).
@ParameterizedClass
@MethodSource("secpSchnorrImplementations")
public class BIP340TestVectorTests implements SecpTestSupport {

    /// Represents a single test vector in test-vectors.csv. Binary values
    /// represented as hex strings in the CSV are represented as `byte[]`
    /// in this record.
    ///
    /// @param index the index of the corresponding row
    /// @param privKey a private key as a length 32 byte array
    /// @param pubKey the corresponding x-only public key as a length 32 byte array
    /// @param auxRand auxiliary randomness for reproducible signatures as a length 32 byte array
    /// @param message the message hash to be signed or verified as a variable length byte array
    /// @param signature the resultant, potentially invalid, signature
    /// @param verificationResult true if verification should pass, false otherwise
    /// @param comment note on specific vector
    private record TestVector(int index, byte[] privKey, byte[] pubKey, byte[] auxRand, byte[] message, byte[] signature, boolean verificationResult, String comment){ }

    private final Secp256k1 secp;

    /// Tests for BIP-340 Test Vectors
    /// @param secp injected Secp256k1 implementation to test
    BIP340TestVectorTests(Secp256k1 secp) {
        this.secp = secp;
    }

    // Currently, Bouncy Castle does not implement Schnorr signing,
    // and this will be replaced by `secpImplementations` once it does.
    static Stream<Secp256k1> secpSchnorrImplementations() {
        return SecpTestSupport.secpImplementations()
                .filter(Secp256k1Foreign.class::isInstance);
    }

    static final List<TestVector> ALL_VECTORS = parseCSV();

    /// For each vector in the subset containing valid signatures on 32-byte messages,
    /// verify that the `secp` instance generates the exact, byte-for-byte signature
    /// in the [TestVector] argument.
    /// @param vec TestVector to be tested.
    @ParameterizedTest
    @FieldSource("SIGN32_VECTORS")
    void schnorrSigSign32(TestVector vec) {
        var privKey = SecpPrivKey.of(vec.privKey);

        var actualSignature = secp.schnorrSigSign32(vec.message, privKey, vec.auxRand);

        assertArrayEquals(vec.signature, actualSignature.bytes());
    }

    /// For each vector in the subset containing valid public keys and valid signatures,
    /// verify that the `secp` instance signature verification result matches the
    /// expected verification result given by the [TestVector] argument.
    /// @param vec TestVector to be tested.
    @ParameterizedTest
    @FieldSource("SIGNVERIFY_VECTORS")
    void schnorrSigVerify(TestVector vec) {
        var pubKey = secp.xOnlyPubKeyParse(vec.pubKey).get();
        var signature = SchnorrSignature.of(vec.signature);

        boolean actualResult = secp.schnorrSigVerify(signature, vec.message, pubKey).get();

        assertEquals(vec.verificationResult, actualResult);
    }

    /// For each vector in the subset containing private keys, verify that the `secp`
    /// instance generates the exact, byte-for-byte public key in the [TestVector]
    /// argument.
    /// @param vec TestVector to be tested.
    @ParameterizedTest
    @FieldSource("PUBKEYCREATE_VECTORS")
    void pubKeyGenFromPrivKey(TestVector vec) {
        var privKey = SecpPrivKey.of(vec.privKey);

        var actualPub = secp.ecPubKeyCreate(privKey).xOnly();

        assertArrayEquals(vec.pubKey, actualPub.serialize());
    }

    /// For each vector in the subset containing invalid public keys, verify that
    /// the `secp` instance will return an error when parsing the invalid public
    /// key given in the [TestVector] argument.
    /// @param vec TestVector to be tested.
    @ParameterizedTest
    @FieldSource("INVALIDPUBKEY_VECTORS")
    void pubKeyParseFromInvalidBytes(TestVector vec) {
        SecpResult<SecpXOnlyPubKey> result = secp.xOnlyPubKeyParse(vec.pubKey);

        assertEquals(0, result.errorCode());
    }

    /// For each vector in the subset containing invalid signatures, verify that
    /// an error is thrown when attempting to parse the signatures given in the
    /// [TestVector] argument.
    /// @param vec TestVector to be tested.
    @ParameterizedTest
    @FieldSource("INVALIDSIGNATURE_VECTORS")
    void schnorrSigFromInvalidBytes(TestVector vec) {
        assertThrows(IllegalArgumentException.class, () -> SchnorrSignature.of(vec.signature));
    }

    static final List<TestVector> SIGN32_VECTORS = ALL_VECTORS.stream()
            .filter(vec -> vec.privKey.length > 0 && vec.message.length == 32)
            .toList();
    static final List<TestVector> SIGNVERIFY_VECTORS = ALL_VECTORS.stream()
            .filter(vec -> vec.message.length > 0
                    && vec.index != 5 && vec.index != 12 && vec.index != 13 && vec.index != 14)
            .toList();
    static final List<TestVector> PUBKEYCREATE_VECTORS = ALL_VECTORS.stream()
            .filter(vec -> vec.privKey.length > 0)
            .toList();
    static final List<TestVector> INVALIDPUBKEY_VECTORS = ALL_VECTORS.stream()
            .filter(vec -> vec.index == 5 || vec.index == 14)
            .toList();
    static final List<TestVector> INVALIDSIGNATURE_VECTORS = ALL_VECTORS.stream()
            .filter(vec -> vec.index == 12 || vec.index == 13)
            .toList();

    private static List<TestVector> parseCSV() {
        try (var in = BIP340TestVectorTests.class.getResourceAsStream("/test-vectors.csv");
             var reader = new InputStreamReader(in)) {
            return new CSVReaderBuilder(reader)
                    .withSkipLines(1)
                    .build()
                    .readAll()
                    .stream()
                    .map(BIP340TestVectorTests::parseVector)
                    .toList();
        } catch (IOException | CsvException e) {
            throw new RuntimeException(e);
        }
    }

    private static TestVector parseVector(String[] f) {
        return new TestVector(
                Integer.parseInt(f[0]),     // index
                parseHex(f[1]),             // private key
                parseHex(f[2]),             // public key
                parseHex(f[3]),             // auxiliary random number
                parseHex(f[4]),             // message
                parseHex(f[5]),             // signature
                f[6].equals("TRUE"),        // verification result
                f[7]                        // comment
        );
    }

    private static byte[] parseHex(String hex) {
        return HexFormat.of().parseHex(hex);
    }
}
