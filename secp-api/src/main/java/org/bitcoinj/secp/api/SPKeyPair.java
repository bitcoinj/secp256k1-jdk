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
package org.bitcoinj.secp.api;

import org.bitcoinj.secp.api.internal.SPKeyPairImpl;

/**
 * A single object containing a private key and its derived public key.
 */
public interface SPKeyPair extends SPPrivKey {
    /**
     * Get the public key
     * @return public key
     */
    SPPubKey getPublic();

    /**
     * Create a keypair from a private key and its matching public key
     * @param privKey private key
     * @param pubKey matching public key
     * @return key pair
     */
    static SPKeyPair of(SPPrivKey privKey, SPPubKey pubKey) {
        return new SPKeyPairImpl(privKey, pubKey);
    }
}
