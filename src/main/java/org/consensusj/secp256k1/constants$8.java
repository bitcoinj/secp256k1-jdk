// Generated by jextract

package org.consensusj.secp256k1;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$8 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$8() {}
    static final MethodHandle const$0 = RuntimeHelper.downcallHandle(
        "secp256k1_ec_privkey_negate",
        constants$7.const$2
    );
    static final MethodHandle const$1 = RuntimeHelper.downcallHandle(
        "secp256k1_ec_pubkey_negate",
        constants$7.const$2
    );
    static final MethodHandle const$2 = RuntimeHelper.downcallHandle(
        "secp256k1_ec_seckey_tweak_add",
        constants$4.const$5
    );
    static final MethodHandle const$3 = RuntimeHelper.downcallHandle(
        "secp256k1_ec_privkey_tweak_add",
        constants$4.const$5
    );
    static final MethodHandle const$4 = RuntimeHelper.downcallHandle(
        "secp256k1_ec_pubkey_tweak_add",
        constants$4.const$5
    );
    static final MethodHandle const$5 = RuntimeHelper.downcallHandle(
        "secp256k1_ec_seckey_tweak_mul",
        constants$4.const$5
    );
}


