// Generated by jextract

package org.consensusj.secp256k1;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
/**
 * {@snippet :
 * int (*secp256k1_nonce_function_default)(unsigned char*,unsigned char*,unsigned char*,unsigned char*,void*,unsigned int);
 * }
 */
public interface secp256k1_nonce_function_default {

    int apply(java.lang.foreign.MemorySegment nonce32, java.lang.foreign.MemorySegment msg32, java.lang.foreign.MemorySegment key32, java.lang.foreign.MemorySegment algo16, java.lang.foreign.MemorySegment data, int attempt);
    static MemorySegment allocate(secp256k1_nonce_function_default fi, Arena scope) {
        return RuntimeHelper.upcallStub(constants$6.const$3, fi, constants$0.const$2, scope);
    }
    static secp256k1_nonce_function_default ofAddress(MemorySegment addr, Arena arena) {
        MemorySegment symbol = addr.reinterpret(arena, null);
        return (java.lang.foreign.MemorySegment _nonce32, java.lang.foreign.MemorySegment _msg32, java.lang.foreign.MemorySegment _key32, java.lang.foreign.MemorySegment _algo16, java.lang.foreign.MemorySegment _data, int _attempt) -> {
            try {
                return (int)constants$0.const$4.invokeExact(symbol, _nonce32, _msg32, _key32, _algo16, _data, _attempt);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


