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

import org.bitcoinj.secp.api.P256k1PrivKey;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * TODO: Verify validity at creation time
 */
public class PrivKeyPojo extends P256k1PrivKey.P256k1PrivKeyDefault {
    /**
     * Package private to ensure it is only created from a valid private key
     * @param privKey memory-segment with a libsecp256k1 private key
     */
    PrivKeyPojo(MemorySegment privKey) {
        // Make defensive copy, so we are effectively immutable
        super(privKey.toArray(ValueLayout.JAVA_BYTE));
    }

    PrivKeyPojo(byte[] bytes) {
        // Make defensive copy, so we are effectively immutable
        super(bytes.clone());
    }
}
