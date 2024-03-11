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
package org.bitcoinj.secp256k1.foreign;

import org.bitcoinj.secp256k1.api.CompressedSignatureData;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 *
 */
public class CompressedSignaturePojo implements CompressedSignatureData {
    private final byte[] bytes;

    public CompressedSignaturePojo(byte[] compressedPubKey) {
        bytes = new byte[compressedPubKey.length];
        System.arraycopy(compressedPubKey, 0, bytes, 0, compressedPubKey.length);
    }

    CompressedSignaturePojo(MemorySegment pubKey) {
        // Make defensive copy, so we are effectively immutable
        bytes = pubKey.toArray(ValueLayout.JAVA_BYTE);
    }


    public byte[] bytes() {
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, bytes.length);
        return copy;
    }
}
