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

/**
 * Abstract Base Class for creating ByteArray Implementations
 */
public abstract class ByteArrayBase implements ByteArray {
    public static final HexFormat HEX_FORMAT = new HexFormat();

    /**
     * Utility method to format hex bytes as string
     * @param bytes bytes to format
     * @return hex-formatted String
     */
    public static String toHexString(byte[] bytes) {
        return HEX_FORMAT.formatHex(bytes);
    }

    @Override
    public abstract byte[] bytes();
}
