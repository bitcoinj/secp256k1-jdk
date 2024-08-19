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
package org.bitcoinj.secp.integration;

import org.bitcoinj.secp.api.P256k1PubKey;
import org.bitcoinj.secp.bouncy.BouncyPrivKey;
import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

/**
 *
 */
public class Secp256k1ForeignTest {
    @Test
    void pubKeyAdditionTestOne() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            P256k1PubKey pubKey = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE)).getPublic();
            P256k1PubKey added = secp.ecPubKeyCombine(pubKey);
            P256k1PubKey multiplied = secp.ecPubKeyTweakMul(pubKey, BigInteger.valueOf(1));
            Assertions.assertEquals(added.getW(), multiplied.getW());
        }
    }

    @Test
    void pubKeyAdditionTestTwo() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            P256k1PubKey pubKey = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE)).getPublic();
            P256k1PubKey added = secp.ecPubKeyCombine(pubKey, pubKey);
            P256k1PubKey multiplied = secp.ecPubKeyTweakMul(pubKey, BigInteger.valueOf(2));
            Assertions.assertEquals(added.getW(), multiplied.getW());
        }
    }

}
