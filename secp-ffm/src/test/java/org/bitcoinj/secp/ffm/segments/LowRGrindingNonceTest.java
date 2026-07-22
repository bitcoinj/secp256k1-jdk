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
package org.bitcoinj.secp.ffm.segments;

import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Basic test of {@link LowRGrindingNonce}
 */
public class LowRGrindingNonceTest {
    static final byte[] exp_nonce0 = new byte[32];
    static final byte[] exp_nonce1 = HexFormat.of().parseHex("01" + "00".repeat(31));

    @Test
    void basicTest() {
        try (var arena = Arena.ofShared()) {
            MemorySegment nonce = LowRGrindingNonce.allocate(arena);
            LowRGrindingNonce.setCounter(nonce, 0);
            byte[] nonce0 = nonce.toArray(ValueLayout.JAVA_BYTE);
            assertArrayEquals(exp_nonce0, nonce0, "");
            LowRGrindingNonce.setCounter(nonce, 1);
            byte[] nonce1 = nonce.toArray(ValueLayout.JAVA_BYTE);
            assertArrayEquals(exp_nonce1, nonce1, "");
        }
    }
}
