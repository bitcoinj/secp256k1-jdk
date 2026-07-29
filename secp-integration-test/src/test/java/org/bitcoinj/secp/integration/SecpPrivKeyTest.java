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

import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Integration tests of SecpPrivKey implementations
@ParameterizedClass
@MethodSource("secpImplementations")
public class SecpPrivKeyTest implements SecpTestSupport {
    private final Secp256k1 secp;

    /// `@ParameterizedClass` constructor
    /// @param secp injected Secp256k1 implementation to test
    SecpPrivKeyTest(Secp256k1 secp) {
        this.secp = secp;
    }

    @Test
    void constructTest() {
        SecpPrivKey privKey = secp.ecPrivKeyCreate();

        assertEquals("Secp256k1", privKey.getAlgorithm());
        assertEquals("Big-endian", privKey.getFormat());
        assertEquals(Secp256k1.EC_PARAMS, privKey.getParams());

        SecpPubKey pubKey = secp.ecPubKeyCreate(privKey);
        SecpPubKey check = secp.ecPubKeyTweakMul(Secp256k1.G, privKey.getS());

        assertEquals(pubKey.x(), check.x());
        assertEquals(pubKey.y(), check.y());
    }

    @Test
    void constructAndDestroy() {
        SecpPrivKey privKey = secp.ecPrivKeyCreate();

        assertFalse(privKey.isDestroyed());

        privKey.destroy();

        assertTrue(privKey.isDestroyed());
        assertThrows(IllegalStateException.class, privKey::getEncoded);
        assertThrows(IllegalStateException.class, privKey::getS);

        privKey.destroy();      // Destroy is idempotent
    }
}
