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
package org.bitcoinj.secp.internal;

import org.bitcoinj.secp.ByteArray;
import org.bitcoinj.secp.EcdhSharedSecret;

import java.util.Arrays;

/**
 * A secp256k1 ECDH shared secret, stored as a {@link ByteArray}.
 */
public class EcdhSharedSecretImpl  implements EcdhSharedSecret {
    private final byte[] bytes;

    public EcdhSharedSecretImpl(byte[] bytes) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
    }

    @Override
    public byte[] bytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof EcdhSharedSecretImpl && Arrays.equals(bytes(), ((EcdhSharedSecretImpl) o).bytes());
    }
}
