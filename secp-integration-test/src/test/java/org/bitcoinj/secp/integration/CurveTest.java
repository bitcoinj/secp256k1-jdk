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

import org.bitcoinj.secp.P256k1PrivKey;
import org.bitcoinj.secp.P256k1PubKey;
import org.bitcoinj.secp.Secp256k1;
import org.junit.jupiter.api.Test;

import static org.bitcoinj.secp.Secp256k1.ProviderId.LIBSECP256K1_FFM;
import static org.bitcoinj.secp.Secp256k1.ProviderId.BOUNCY_CASTLE;

import java.math.BigInteger;
import java.security.spec.ECPoint;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 */
public class CurveTest {
    static final ECPoint G = Secp256k1.EC_PARAMS.getGenerator();

    @Test
    void pubKeyCalc() {
        try (var secp = Secp256k1.getById(LIBSECP256K1_FFM); var bouncy = Secp256k1.getById(BOUNCY_CASTLE)) {
            P256k1PrivKey privkey = P256k1PrivKey.of(BigInteger.ONE);

            // Create pubkeys with both implementations
            P256k1PubKey pubkey_secp = secp.ecPubKeyCreate(privkey);
            P256k1PubKey pubkey_bouncy = bouncy.ecPubKeyCreate(privkey);

            // A private key of `1` should result in a public key of `G`
            assertEquals(G, pubkey_secp.getW());
            assertEquals(G, pubkey_bouncy.getW());
            assertEquals(pubkey_secp.getW(), pubkey_bouncy.getW());
        }
    }
}
