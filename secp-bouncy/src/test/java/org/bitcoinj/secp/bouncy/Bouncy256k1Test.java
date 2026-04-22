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
package org.bitcoinj.secp.bouncy;

import org.bitcoinj.secp.Secp256k1;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static java.math.BigInteger.ONE;
import static org.bitcoinj.secp.Secp256k1.N;
import static org.bitcoinj.secp.bouncy.Bouncy256k1.HALF_CURVE_ORDER;

public class Bouncy256k1Test {
    Bouncy256k1 secp = new Bouncy256k1();

    final static List<Map.Entry<BigInteger, BigInteger>> canonPairs = Map.of(
        ONE, ONE,
        HALF_CURVE_ORDER.subtract(ONE), HALF_CURVE_ORDER.subtract(ONE),
        HALF_CURVE_ORDER, HALF_CURVE_ORDER,
        HALF_CURVE_ORDER.add(ONE), HALF_CURVE_ORDER,
        N.subtract(ONE), ONE
    ).entrySet().stream().toList();

    @ParameterizedTest
    @FieldSource("canonPairs")
    void testCanonicalize(Map.Entry<BigInteger, BigInteger> pair) {
        BigInteger canonicalized = secp.canonicalize(pair.getKey());
        Assertions.assertEquals(pair.getValue(), canonicalized);
    }
}
