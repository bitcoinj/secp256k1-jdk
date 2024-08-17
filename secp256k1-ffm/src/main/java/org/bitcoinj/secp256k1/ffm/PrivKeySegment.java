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
package org.bitcoinj.secp256k1.ffm;

import org.bitcoinj.secp256k1.api.P256k1PrivKey;

import java.lang.foreign.MemorySegment;

/**
 *
 */
/* package */ class PrivKeySegment  implements P256k1PrivKey {
    final MemorySegment segment;

    PrivKeySegment(MemorySegment segment) {
        this.segment = segment;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    @Override
    public void destroy() {
        // TODO: TBD!
    }

    MemorySegment segment() {
        return segment;
    }
}