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

import java.util.Comparator;

/**
 *
 */
public class ByteUtils {
    static final HexFormat HEX_FORMAT = new HexFormat();
    // In Java 9+, this can be replaced with Arrays.compareUnsigned()
    /**
     * Compare byte arrays treating each byte as unsigned.
     * @param a byte array to compare
     * @param b byte array to compare
     * @return a negative integer if {@code a < b}, zero if {@code a == b},
     * or a positive integer if {@code a > b}
     */
    public static int compareUnsigned(byte[] a, byte[] b) {
        int minLength = Math.min(a.length, b.length);
        for (int i = 0; i < minLength; i++) {
            int result = compareUnsigned(a[i], b[i]);
            if (result != 0) {
                return result;
            }
        }
        return a.length - b.length;
    }

    private static int compareUnsigned(byte a, byte b) {
        return Byte.toUnsignedInt(a) - Byte.toUnsignedInt(b);
    }

    /**
     * Utility method to format hex bytes as string
     * @param bytes bytes to format
     * @return hex-formatted String
     */
    public static String toHexString(byte[] bytes) {
        return HEX_FORMAT.formatHex(bytes);
    }
}
