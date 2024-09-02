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
package org.bitcoinj.secp.api.internal;

import java.util.Comparator;

/**
 *
 */
public class ByteUtils {
    /**
     * Provides a byte array comparator.
     * @return A comparator for byte[]
     */
    public static Comparator<byte[]> arrayUnsignedComparator() {
        return ARRAY_UNSIGNED_COMPARATOR;
    }

    // In Java 9, this can be replaced with Arrays.compareUnsigned()
    private static final Comparator<byte[]> ARRAY_UNSIGNED_COMPARATOR = (a, b) -> {
        int minLength = Math.min(a.length, b.length);
        for (int i = 0; i < minLength; i++) {
            int result = compareUnsigned(a[i], b[i]);
            if (result != 0) {
                return result;
            }
        }
        return a.length - b.length;
    };

    private static int compareUnsigned(byte a, byte b) {
        return Byte.toUnsignedInt(a) - Byte.toUnsignedInt(b);
    }
}
