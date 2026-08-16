/*
 * Copyright 2023-2026 secp256k1-jdk Developers.
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

import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpScalar;

import java.math.BigInteger;
import java.util.Arrays;

/**
 *
 */
public class ByteUtils {
    static final HexFormat HEX_FORMAT = new HexFormat();

    /**
     * Utility method to format hex bytes as string
     * @param bytes bytes to format
     * @return hex-formatted String
     */
    public static String toHexString(byte[] bytes) {
        return HEX_FORMAT.formatHex(bytes);
    }

    /**
     * Copy integer as 32 unsigned big-endian bytes. This method deliberately does no range-checking
     * (other than the built-in array bounds-checking.) For range-checking use {@link UInt256#checkInRange},
     * {@link SecpScalar#checkInRange(BigInteger)}, or {@link SecpFieldElement#checkInRange(BigInteger)}
     * @param i integer
     * @param bytes destination array
     * @param offset destination offset
     */
    public static void copyAsUnsigned32Bytes(BigInteger i, byte[] bytes, int offset) {
        byte[] minBytes = i.toByteArray(); // return minimum, signed bytes
        if (minBytes.length == 32) {
            System.arraycopy(minBytes, 0, bytes, offset, 32);
        } else {
            int destPos = minBytes.length == 33 ? offset : offset + 32 - minBytes.length;
            Arrays.fill(bytes, offset, destPos, (byte)0);           // Fill leading zeros
            System.arraycopy(minBytes,                              // src
                    minBytes.length == 33 ? 1 : 0,                  // src pos (skip sign byte if present)
                    bytes,                                          // dest
                    destPos,                                        // dest pos
                    minBytes.length == 33 ? 32 : minBytes.length);  // num bytes to copy
        }
    }
}
