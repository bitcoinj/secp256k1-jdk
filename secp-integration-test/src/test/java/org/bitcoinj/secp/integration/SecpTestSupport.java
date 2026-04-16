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

import org.bitcoinj.secp.Secp256k1;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.stream.Stream;

/**
 * Support methods for {@link org.bitcoinj.secp.integration}
 */
public interface SecpTestSupport {
    /**
     * SHA-256 hash utility functions
     * @param messageString string to hash
     * @return SHA-256 of input string
     */
    static byte[] hash(String messageString) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(messageString.getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }

    /**
     * Return all {@link Secp256k1.Provider}s.
     * @return stream of all providers
     */
    static Stream<Secp256k1.Provider> secpProviders() {
        return Secp256k1.all();
    }

    /**
     * Return an instance of {@link Secp256k1} for all known providers.
     * @return stream of all providers
     */
    static Stream<Secp256k1> secpImplementations() {
        return Secp256k1.all().map(Secp256k1.Provider::get);
    }

    static byte[] parseHex(String hex) {
        return HexFormat.of().parseHex(hex);
    }
}
