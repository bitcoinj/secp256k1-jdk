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
package org.bitcoinj.secp.bouncy;

import org.bitcoinj.secp.api.P256K1KeyPair;

/**
 *
 */
public class BouncyKeyPair implements P256K1KeyPair {

    private final BouncyPrivKey privKey;
    private final BouncyPubKey pubKey;

    public BouncyKeyPair(BouncyPrivKey privKey, BouncyPubKey pubKey) {
        this.privKey = privKey;
        this.pubKey = pubKey;

    }
    @Override
    public BouncyPubKey getPublic() {
        return pubKey;
    }
    
    @Override
    public byte[] getEncoded() {
        return privKey.getEncoded();
    }

    @Override
    public void destroy() {
    }
}
