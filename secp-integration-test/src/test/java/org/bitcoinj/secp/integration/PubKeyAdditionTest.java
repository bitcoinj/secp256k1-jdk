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

import org.bitcoinj.secp.api.SPPubKey;
import org.bitcoinj.secp.api.SPPrivKey;
import org.bitcoinj.secp.api.Secp256k1;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

/**
 *
 */
public class PubKeyAdditionTest {
    @Test
    void pubKeyAdditionTestTwo() {
        try (Secp256k1 secp = Secp256k1.getByName("bouncy-castle")) {
            SPPubKey pubKey = secp.ecKeyPairCreate(SPPrivKey.of(BigInteger.ONE)).getPublic();
            SPPubKey added = secp.ecPubKeyCombine(pubKey, pubKey);
            SPPubKey multiplied = secp.ecPubKeyTweakMul(pubKey, BigInteger.valueOf(2));
            Assertions.assertEquals(added.getW(), multiplied.getW());
        }
    }
}
