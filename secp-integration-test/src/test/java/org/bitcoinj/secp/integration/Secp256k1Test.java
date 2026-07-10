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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;

/// Construction and close tests
@ParameterizedClass
@MethodSource("secpImplementations")
public class Secp256k1Test implements SecpTestSupport {
    private final Secp256k1 secp;

    /// Construct test with parameterized instance
    /// @param secp injected Secp256k1 implementation to test
    Secp256k1Test(Secp256k1 secp) {
        this.secp = secp;
    }

    @Test
    public void testClose() {
        secp.close();
    }

    @Test
    public void testIdempotentClose() {
        secp.close();
        secp.close();   // 2nd close should be a no-op, and not throw
    }
}
