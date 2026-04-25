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

/**
 * Memory layout for working with Low-R grinding nonces. A 32-byte segment with a 4-byte, little-endian
 * counter at offset zero.
 */
public class LowRGrindingNonce {
    static final ValueLayout.OfInt COUNT_LAYOUT = ValueLayout.JAVA_INT.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final StructLayout LAYOUT = MemoryLayout.structLayout(
            COUNT_LAYOUT.withName("counter"),     // 4 bytes
            MemoryLayout.sequenceLayout(28, ValueLayout.JAVA_BYTE).withName("remaining")   // 28 bytes
    );
    static private final long COUNT_OFFSET = LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("counter"));

    private final MemorySegment segment;
    private int counter;

    private LowRGrindingNonce(MemorySegment segment) {
        this.segment = segment;
        this.counter = 0;
    }

    public static LowRGrindingNonce zero(Arena arena) {
        return new LowRGrindingNonce(arena.allocate(LAYOUT.byteSize()));
    }

    public void increment() {
        segment.set(COUNT_LAYOUT, COUNT_OFFSET, ++counter);
    }

    public MemorySegment segment() {
        return segment;
    }

    public byte[] bytes() {
        return segment.toArray(ValueLayout.JAVA_BYTE);
    }
}
