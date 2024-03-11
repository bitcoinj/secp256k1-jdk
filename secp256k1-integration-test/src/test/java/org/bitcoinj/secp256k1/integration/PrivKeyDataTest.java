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

import org.bitcoinj.secp256k1.api.P256k1PrivKey;
import org.bitcoinj.secp256k1.bouncy.BouncyPrivKey;
import org.bitcoinj.secp256k1.eggcc.EggPrivKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

/**
 *
 */
public class PrivKeyDataTest {
    @Test
    void testBouncyPriv() {
        P256k1PrivKey priv = new BouncyPrivKey(BigInteger.ONE);

        BigInteger privInt = priv.getS();
        Assertions.assertEquals(BigInteger.ONE, privInt);
    }

    @Test
    void testEggPriv() {
        P256k1PrivKey priv = new EggPrivKey(BigInteger.ONE);

        BigInteger privInt = priv.getS();
        Assertions.assertEquals(BigInteger.ONE, privInt);
    }

}
