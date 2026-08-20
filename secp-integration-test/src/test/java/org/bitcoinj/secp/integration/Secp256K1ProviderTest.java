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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 */
public class Secp256K1ProviderTest implements SecpTestSupport {
    @MethodSource("secpProviders")
    @ParameterizedTest(name = "Provider: {0}")
    void checkProviders(Secp256k1.Provider provider) {
        // All providers in this test must have an ID
        Optional<Secp256k1.ProviderId> id = provider.id();
        assertTrue(id.isPresent());
        assertTrue(Arrays.asList(Secp256k1.ProviderId.values()).contains(id.get()));
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Implementation for {0}")
    void checkImplementations(Secp256k1 secp) {
        assertNotNull(secp);
    }
}
