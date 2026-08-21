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

import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.EcdsaSignature;
import org.bitcoinj.secp.bouncy.Bouncy256k1;
import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.bitcoinj.secp.internal.EcdsaSignatureImpl;
import org.bitcoinj.secp.internal.UInt256;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;

import static org.bitcoinj.secp.integration.SecpTestSupport.hash;
import static org.bitcoinj.secp.integration.SecpTestSupport.parseHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test ECDA Signing and verification.
 */
public class EcdsaTest implements SecpTestSupport {
    private static final byte[] MSG_HASH = hash("Hello, world!");

    private static final byte[] TEST_PRIVKEY = hash("secp256k1-jdk ECDSA canonicalization test key");
    /// This message was selected such that a high-s signature would be produced under TEST_PRIVKEY. Specifically, a
    /// high-s signature would be produced by the `sign` algorithm defined by BIP-461 given the message and private key
    /// (and `extra` = b''). Both FFM and BC implementations effectively implement `sign`, just with low-*s* normalization.
    private static final byte[] HIGH_S_MSG_HASH = hash("high-s");
    /// High-s signature generated from MSG_HASH (not HIGH_S_MSG_HASH) and TEST_PRIVKEY, but with a negated *s*.
    private static final byte[] HIGH_S_SIG = parseHex("A2377BF9BFCC5A3E1E0E62EAC08F8F99B5FE37330AAA4CDADDA565C6FE2CF568D267903C02788014B75BA39F3BC534B67623AD2CBF64A578A593B9CB95535A74");

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Ecdsa for {0}")
    void testEcdsa(Secp256k1 secp) {
        SecpPrivKey privKey = secp.ecPrivKeyCreate();
        SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);
        EcdsaSignature sig = secp.ecdsaSign(MSG_HASH, privKey).get();
        boolean validSignature = secp.ecdsaVerify(sig, MSG_HASH, pubKey).get();
        assertTrue(validSignature);
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Ecdsa for {0}")
    void testEcdsaLowR(Secp256k1 secp) {
        SecpPrivKey privKey = secp.ecPrivKeyCreate();
        SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);
        EcdsaSignature sig = secp.ecdsaSignLowR(MSG_HASH, privKey).get();
        boolean validSignature = secp.ecdsaVerify(sig, MSG_HASH, pubKey).get();
        assertTrue(validSignature);
        assertTrue(sig.hasLowR());
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Ecdsa for {0}")
    void testEcdsaCanonicalSign(Secp256k1 secp) {
        SecpPrivKey privKey = secp.ecPrivKeyImport(TEST_PRIVKEY);
        SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);

        EcdsaSignature sig = secp.ecdsaSign(HIGH_S_MSG_HASH, privKey).get();

        boolean validSignature = secp.ecdsaVerify(sig, HIGH_S_MSG_HASH, pubKey).get();

        assertTrue(validSignature);
        assertTrue(sig.hasLowS());
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Ecdsa for {0}")
    void testEcdsaVerifyHighSFails(Secp256k1 secp) {
        SecpPrivKey privKey = secp.ecPrivKeyImport(TEST_PRIVKEY);
        SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);

        EcdsaSignature sigHighS = secp.ecdsaSignatureParseCompact(HIGH_S_SIG).get();
        assertFalse(sigHighS.hasLowS());

        boolean validSignature1 = secp.ecdsaVerify(sigHighS, MSG_HASH, pubKey).get();
        assertFalse(validSignature1);

        EcdsaSignature sigLowS = sigHighS.normalize();
        assertTrue(sigLowS.hasLowS());

        boolean validSignature2 = secp.ecdsaVerify(sigLowS, MSG_HASH, pubKey).get();
        assertTrue(validSignature2);
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Ecdsa for {0}")
    void testEcdsaSignatureToString(Secp256k1 secp) {
        byte[] sigBytes = new EcdsaSignatureImpl(BigInteger.ONE, BigInteger.TEN).serializeCompact();
        EcdsaSignature sig = secp.ecdsaSignatureParseCompact(sigBytes).get();
        String string = sig.toString();
        IO.println("toString() is: " + string);
        assertTrue(string.contains("r=00"));
        assertTrue(string.contains("s=00"));
        assertTrue(string.contains("0001,"));
        assertTrue(string.contains("000A]"));
    }

    @Test
    void ecdsaCrossCheck() {
        try (Secp256k1 secp1 = new Secp256k1Foreign(); Secp256k1 secp2 = new Bouncy256k1()) {
            SecpPrivKey secKey = secp1.ecPrivKeyCreate();
            SecpPubKey pubKey1 = secp1.ecPubKeyCreate(secKey);
            SecpPubKey pubKey2 = secp2.ecPubKeyCreate(secKey);

            assertArrayEquals(pubKey1.serialize(), pubKey2.serialize());

            EcdsaSignature sig1 = secp1.ecdsaSign(MSG_HASH, secKey).get();
            EcdsaSignature sig2 = secp2.ecdsaSign(MSG_HASH, secKey).get();

            assertArrayEquals(sig1.serializeCompact(), sig2.serializeCompact());

            assertTrue(secp1.ecdsaVerify(sig1, MSG_HASH, pubKey1).get());
            assertTrue(secp1.ecdsaVerify(sig2, MSG_HASH, pubKey2).get());
            assertTrue(secp2.ecdsaVerify(sig1, MSG_HASH, pubKey1).get());
            assertTrue(secp2.ecdsaVerify(sig2, MSG_HASH, pubKey2).get());
        }
    }


    @Test
    void ecdsaCrossCheckLowR() {
        try (Secp256k1 secp1 = new Secp256k1Foreign(); Secp256k1 secp2 = new Bouncy256k1()) {
            SecpPrivKey secKey = secp1.ecPrivKeyCreate();
            SecpPubKey pubKey1 = secp1.ecPubKeyCreate(secKey);
            SecpPubKey pubKey2 = secp2.ecPubKeyCreate(secKey);

            assertArrayEquals(pubKey1.serialize(), pubKey2.serialize());

            EcdsaSignature sig1 = secp1.ecdsaSignLowR(MSG_HASH, secKey).get();
            EcdsaSignature sig2 = secp2.ecdsaSignLowR(MSG_HASH, secKey).get();

            assertArrayEquals(sig1.serializeCompact(), sig2.serializeCompact());

            assertTrue(secp1.ecdsaVerify(sig1, MSG_HASH, pubKey1).get());
            assertTrue(secp1.ecdsaVerify(sig2, MSG_HASH, pubKey2).get());
            assertTrue(secp2.ecdsaVerify(sig1, MSG_HASH, pubKey1).get());
            assertTrue(secp2.ecdsaVerify(sig2, MSG_HASH, pubKey2).get());
        }
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test parseCompact for {0}")
    void testParseCompact(Secp256k1 secp) {
        byte[] sigBytes = parseHex("252EC55A0CB7CD96F3BA47D7B3E16876C75F00CCF85B5F0CA5C51A8058BA9E7640F5D8DF25ADED2A4EA8DD7B2CA4CD3D8A3187D6FEF24A9C7111B9F9B4E0CFAE");
        EcdsaSignature signature = secp.ecdsaSignatureParseCompact(sigBytes).get();
        assertArrayEquals(sigBytes, signature.serializeCompact());
    }

    // Test interop with a signature from elsewhere (from a bitcoinj test)
    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Test Ecdsa for {0}")
    void testInterop(Secp256k1 secp) {
        SecpPrivKey privKey = secp.ecPrivKeyImport(parseHex("180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19"));
        SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);
        byte[] sigBytes = parseHex(
                "3046022100dffbc26774fc841bbe1c1362fd643609c6e42dcb274763476d87af2c0597e89e022100c59e3c13b96b316cae9fa0ab0260612c7a133a6fe2b3445b6bf80b3123bf274d");
        EcdsaSignature sig = secp.ecdsaSignatureParseDer(sigBytes).get();
        EcdsaSignature canonicalSig = new EcdsaSignatureImpl(sig.rBigInteger(), canonicalize(sig.sBigInteger()));
        IO.println("Ecdsa Signature: " + sig);
        boolean valid = secp.ecdsaVerify(canonicalSig, UInt256.ZERO_VALUE, pubKey).get();
        assertTrue(valid);
    }

    BigInteger canonicalize(BigInteger s) {
        return s.compareTo(Secp256k1.HALF_CURVE_ORDER.toBigInteger()) <= 0
                ? s
                : Secp256k1.N.subtract(s);
    }
}
