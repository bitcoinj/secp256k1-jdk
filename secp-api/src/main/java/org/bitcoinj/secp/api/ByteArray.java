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

import org.bitcoinj.secp.api.internal.ByteUtils;
import org.bitcoinj.secp.api.internal.HexFormat;

import java.util.Arrays;

/**
 * An effectively-immutable byte array.
 */
public interface ByteArray extends Comparable<ByteArray> {
    HexFormat HEX_FORMAT = new HexFormat();

    /**
     * @return the bytes as an array
     */
    byte[] bytes();

    /**
     * @return the bytes as a hex-formatted string
     */
    default String formatHex() {
        return HEX_FORMAT.formatHex(bytes());
    }

    /**
     * {@inheritDoc}
     * <p>For {@link ByteArray} this is a byte-by-byte, unsigned comparison.
     * @param o {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    default int compareTo(ByteArray o) {
        return ByteUtils.arrayUnsignedComparator().compare(bytes(), o.bytes());
    }

    /**
     * Utility method to format hex bytes as string
     * @param bytes bytes to format
     * @return hex-formatted String
     */
    static String toHexString(byte[] bytes) {
        return HEX_FORMAT.formatHex(bytes);
    }
}