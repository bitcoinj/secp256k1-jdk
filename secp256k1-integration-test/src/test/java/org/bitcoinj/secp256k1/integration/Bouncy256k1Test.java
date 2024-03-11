/*
 * Copyright 2023-2024 secp256k1-jdk Developers.
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
package org.bitcoinj.secp256k1.integration;

import org.bitcoinj.secp256k1.api.P256k1PubKey;
import org.bitcoinj.secp256k1.bouncy.Bouncy256k1;
import org.bitcoinj.secp256k1.bouncy.BouncyPrivKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

/**
 *
 */
public class Bouncy256k1Test {
    @Test
    void pubKeyAdditionTestTwo() {
        try (Bouncy256k1 secp = new Bouncy256k1()) {
            P256k1PubKey pubKey = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE)).getPublic();
            P256k1PubKey added = secp.ecPubKeyCombine(pubKey, pubKey);
            P256k1PubKey multiplied = secp.ecPubKeyTweakMul(pubKey, BigInteger.valueOf(2));
            Assertions.assertEquals(added.getW(), multiplied.getW());
        }
    }
}
