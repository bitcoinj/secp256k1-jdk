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
package org.bitcoinj.secp.ffm.segments;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/// Memory layout for working with Low-R grinding nonces. A 32-byte segment with a 4-byte, little-endian
/// counter at offset zero.
public interface LowRGrindingNonce {
    ValueLayout.OfInt COUNT_LAYOUT = ValueLayout.JAVA_INT.withOrder(ByteOrder.LITTLE_ENDIAN);
    StructLayout LAYOUT = MemoryLayout.structLayout(
            COUNT_LAYOUT.withName("counter"),     // 4 bytes
            MemoryLayout.sequenceLayout(28, ValueLayout.JAVA_BYTE).withName("remaining")   // 28 bytes
    );

    /// Allocate a low-R grinding nonce. Note that {@link Arena#allocate(MemoryLayout)} will initialize the
    /// segment to zeros, so in {@link LowRGrindingNonce#setCounter(MemorySegment, int)} we only need to write the counter.
    /// @param arena arena to allocate from
    /// @return a memory segment containing the nonce
    static MemorySegment allocate(Arena arena) {
        return arena.allocate(LAYOUT);
    }

    /// Set the counter area of the low-R grinding nonce with the given counter value. This assumes the rest
    /// of the segment is filled with zero bytes.
    /// @param nonce The nonce to set
    /// @param counter The iteration counter
    static void setCounter(MemorySegment nonce, int counter) {
        nonce.set(COUNT_LAYOUT, 0, counter);
    }
}
