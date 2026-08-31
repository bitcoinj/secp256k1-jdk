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
package org.bitcoinj.secp.ffm;

import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.internal.SecpScalarImpl;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Unit tests of [SecpPrivKeyNative]
public class SecpPrivKeyNativeTest {

    @Test
    void constructOne() {
        var onePrivKey = new SecpPrivKeyNative(BigInteger.ONE);
        assertEquals(BigInteger.ONE, onePrivKey.getS());

        var onePrivKeyClone = new SecpPrivKeyNative(onePrivKey.segment());
        assertEquals(BigInteger.ONE, onePrivKeyClone.getS());

        onePrivKeyClone.destroy();
        assertTrue(onePrivKeyClone.isDestroyed());
        assertFalse(onePrivKey.isDestroyed());
    }

    @Test
    void constructAndDestroy() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            SecpPrivKey privKey = secp.ecPrivKeyCreate();
            assertFalse(privKey.isDestroyed());
            privKey.destroy();
            assertTrue(privKey.isDestroyed());

            assertThrows(IllegalStateException.class, privKey::getS);
            assertThrows(IllegalStateException.class, () -> ((SecpPrivKeyNative)privKey).segment());
        }
    }

    @Test
    void multiplyTestOne() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            SecpPrivKey onePrivKey = new SecpPrivKeyNative(BigInteger.ONE);
            SecpPubKey pubKey = secp.ecPubKeyCreate(onePrivKey);
            SecpPubKey check = secp.ecPubKeyTweakMul(Secp256k1.G, onePrivKey.getS());
            assertEquals(pubKey.x(), check.x());
            assertEquals(pubKey.y(), check.y());
        }
    }

    @Test
    void multiplyTest() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            SecpPrivKey privKey = secp.ecPrivKeyCreate();
            SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);
            SecpPubKey check = secp.ecPubKeyTweakMul(Secp256k1.G, privKey.getS());
            assertEquals(pubKey.x(), check.x());
            assertEquals(pubKey.y(), check.y());
        }
    }

}
