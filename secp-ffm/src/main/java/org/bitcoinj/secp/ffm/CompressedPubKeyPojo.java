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
package org.bitcoinj.secp.ffm;

import org.bitcoinj.secp.api.CompressedPubKeyData;

/**
 *
 */
public class CompressedPubKeyPojo implements CompressedPubKeyData {
    private final byte[] bytes;

    public CompressedPubKeyPojo(byte[] compressedPubKey) {
        bytes = new byte[compressedPubKey.length];
        System.arraycopy(compressedPubKey, 0, bytes, 0, compressedPubKey.length);
    }
    
    public byte[] bytes() {
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, bytes.length);
        return copy;
    }
}
