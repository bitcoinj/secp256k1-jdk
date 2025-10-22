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

import org.bitcoinj.secp.api.Secp256k1;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.bitcoinj.secp.api.Secp256k1.ProviderId.BOUNCY_CASTLE;
import static org.bitcoinj.secp.api.Secp256k1.ProviderId.LIBSECP256K1_FFM;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 */
public class Secp256K1ProviderTest {
    public static Stream<Secp256k1> secpImplementations() {
        return secpProviders().map(Secp256k1.Provider::get);
    }

    public static Stream<Secp256k1.Provider> secpProviders() {
        var providerList = List.of(LIBSECP256K1_FFM.id(), BOUNCY_CASTLE.id());
        return Secp256k1.Provider.findAll(p -> providerList.contains(p.name()));
    }

    @MethodSource("secpProviders")
    @ParameterizedTest(name = "Provider: {0}")
    void checkProviders(Secp256k1.Provider provider) {
        System.out.println("Provider " + provider.name());
        assertTrue(provider.name().length() > 1);
    }

    @MethodSource("secpImplementations")
    @ParameterizedTest(name = "Implementation for {0}")
    void checkImplementations(Secp256k1 secp) {
        System.out.println("Implementation " + secp);
        assertNotNull(secp);
    }

}
