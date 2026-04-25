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

import org.bitcoinj.secp.EcdsaSignature;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;

import static org.bitcoinj.secp.integration.SecpTestSupport.parseHex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// secp256k1-jdk integration tests for low-R ECDSA signing.
///
/// Bitcoin Core [PR #13666](https://github.com/bitcoin/bitcoin/pull/13666) introduced low-r ECDSA signature grinding.
/// This has been the default behavior since [release 0.17](https://bitcoincore.org/en/releases/0.17.0/) and several other
/// libraries and wallets have implemented the same (or similar) algorithms. There is no BIP (yet!) with official
/// test vectors (yet!), but the Bitcoin Core C++ implementation serves as a reference implementation.
///
/// [Bitcoin Optech](https://bitcoinops.org) has a [Low-r grinding](https://bitcoinops.org/en/topics/low-r-grinding/) topic
/// with additional information and links to a few other implementations.
@ParameterizedClass
@MethodSource("secpImplementations")
public class EcdsaLowRTest implements SecpTestSupport {

    /// Test Vector Record
    /// @param message 32-byte message (hash) to sign
    /// @param privKey private key for signing
    /// @param signature expected signature
    record LowRVector(byte[] message, byte[] privKey, byte[] signature) {
        static LowRVector parse(String message, String privKey, String signature) {
            return new LowRVector(parseHex(message), parseHex(privKey), parseHex(signature));
        }
    }

    /// test vector from [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1/pull/259/files)
    static List<LowRVector> vectors = List.of(LowRVector.parse(
            "887d04bb1cf1b1554f1b268dfe62d13064ca67ae45348d50d1392ce2d13418ac",
            "57f0148f94d13095cfda539d0da0d1541304b678d8b36e243980aab4e1b7cead",
            "047dd4d049db02b430d24c41c7925b2725bcd5a85393513bdec04b4dc363632b1054d0180094122b380f4cfa391e6296244da773173e78fc745c1b9c79f7b713"
    ));

    private final Secp256k1 secp;

    /// Tests for Low-R ECDSA Signing
    /// @param secp injected Secp256k1 implementation to test
    EcdsaLowRTest(Secp256k1 secp) {
        this.secp = secp;
    }

    /// Parameterized low-R signing test (currently only a single test vector)
    /// @param vec test vector
    @FieldSource("vectors")
    @ParameterizedTest(name = "Test Ecdsa for {0}")
    void testEcdsaLowR(LowRVector vec) {
        SecpPrivKey privKey = SecpPrivKey.of(vec.privKey);
        SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);

        // Sign
        EcdsaSignature sig = secp.ecdsaSignLowR(vec.message, privKey).get();

        // Signature should be bit-for-bit identical with signature in test vector
        assertArrayEquals(vec.signature, sig.serializeCompact());

        // Verify and check for low-r
        boolean validSignature = secp.ecdsaVerify(sig, vec.message, pubKey).get();

        assertTrue(validSignature);
        assertTrue(sig.hasLowR());
    }
}
