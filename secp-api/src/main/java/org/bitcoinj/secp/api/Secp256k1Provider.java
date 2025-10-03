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
package org.bitcoinj.secp.api;

import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 *
 */
public interface Secp256k1Provider {
    /**
     * Implementations must implement this method to return a unique name
     * @return A unique name for this Secp256k1 implementation
     */
    String name();

    /**
     * @return A Secp256k1 instance
     */
    Secp256k1 get();

    /**
     * Find a Secp256k1Provider by name
     *
     * @param name Name (e.g. "ffm" or "bouncy-castle")
     * @return an Secp256k1Provider instance
     * @throws NoSuchElementException if not found
     */
    static Secp256k1Provider byName(String name) {
        return findFirst(provider -> provider.name().equals(name))
                .orElseThrow(() -> new NoSuchElementException("Provider " + name + " not found."));
    }

    /**
     * Find default Secp256k1Provider
     *
     * @return an Secp256k1Provider instance
     * @throws NoSuchElementException if not found
     */
    static Secp256k1Provider find() {
        return findFirst(Secp256k1Provider::defaultFilter)
                .orElseThrow(() -> new NoSuchElementException("Default Provider not found."));
    }

    /**
     * Find a Secp256k1Provider using a custom predicate
     * @param filter predicate for finding a provider
     * @return the <b>first</b> provider matching the predicate, if any
     */
    static Optional<Secp256k1Provider> findFirst(Predicate<Secp256k1Provider> filter) {
        return findAll(filter).findFirst();
    }

    static Stream<Secp256k1Provider> all() {
        return findAll(p -> true);
    }

    static Stream<Secp256k1Provider> findAll(Predicate<Secp256k1Provider> filter) {
        ServiceLoader<Secp256k1Provider> loader = ServiceLoader.load(Secp256k1Provider.class);
        return StreamSupport.stream(loader.spliterator(), false)
                .filter(filter);
    }

    /**
     * Find the default provider. This is currently the "ffm" provider.
     * @param provider a candidate provider
     * @return true if it should be "found"
     */
    /* private */ static boolean defaultFilter(Secp256k1Provider provider) {
        return provider.name().equals("ffm");
    }
}
