// Generated by jextract

package org.consensusj.secp256k1;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class secp256k1_h  {

    public static final OfByte C_CHAR = JAVA_BYTE;
    public static final OfShort C_SHORT = JAVA_SHORT;
    public static final OfInt C_INT = JAVA_INT;
    public static final OfLong C_LONG = JAVA_LONG;
    public static final OfLong C_LONG_LONG = JAVA_LONG;
    public static final OfFloat C_FLOAT = JAVA_FLOAT;
    public static final OfDouble C_DOUBLE = JAVA_DOUBLE;
    public static final AddressLayout C_POINTER = RuntimeHelper.POINTER;
    /**
     * {@snippet :
     * #define SECP256K1_TAG_PUBKEY_EVEN 2
     * }
     */
    public static int SECP256K1_TAG_PUBKEY_EVEN() {
        return (int)2L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_TAG_PUBKEY_ODD 3
     * }
     */
    public static int SECP256K1_TAG_PUBKEY_ODD() {
        return (int)3L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_TAG_PUBKEY_UNCOMPRESSED 4
     * }
     */
    public static int SECP256K1_TAG_PUBKEY_UNCOMPRESSED() {
        return (int)4L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_TAG_PUBKEY_HYBRID_EVEN 6
     * }
     */
    public static int SECP256K1_TAG_PUBKEY_HYBRID_EVEN() {
        return (int)6L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_TAG_PUBKEY_HYBRID_ODD 7
     * }
     */
    public static int SECP256K1_TAG_PUBKEY_HYBRID_ODD() {
        return (int)7L;
    }
    /**
     * {@snippet :
     * typedef long ptrdiff_t;
     * }
     */
    public static final OfLong ptrdiff_t = JAVA_LONG;
    /**
     * {@snippet :
     * typedef unsigned long size_t;
     * }
     */
    public static final OfLong size_t = JAVA_LONG;
    /**
     * {@snippet :
     * typedef int wchar_t;
     * }
     */
    public static final OfInt wchar_t = JAVA_INT;
    public static MemoryLayout secp256k1_context_static$LAYOUT() {
        return RuntimeHelper.POINTER;
    }
    public static VarHandle secp256k1_context_static$VH() {
        return constants$0.const$5;
    }
    public static MemorySegment secp256k1_context_static$SEGMENT() {
        return RuntimeHelper.requireNonNull(constants$1.const$0,"secp256k1_context_static");
    }
    /**
     * Getter for variable:
     * {@snippet :
     * struct secp256k1_context_struct* secp256k1_context_static;
     * }
     */
    public static MemorySegment secp256k1_context_static$get() {
        return (java.lang.foreign.MemorySegment) constants$0.const$5.get(RuntimeHelper.requireNonNull(constants$1.const$0, "secp256k1_context_static"));
    }
    /**
     * Setter for variable:
     * {@snippet :
     * struct secp256k1_context_struct* secp256k1_context_static;
     * }
     */
    public static void secp256k1_context_static$set(MemorySegment x) {
        constants$0.const$5.set(RuntimeHelper.requireNonNull(constants$1.const$0, "secp256k1_context_static"), x);
    }
    public static MemoryLayout secp256k1_context_no_precomp$LAYOUT() {
        return RuntimeHelper.POINTER;
    }
    public static VarHandle secp256k1_context_no_precomp$VH() {
        return constants$0.const$5;
    }
    public static MemorySegment secp256k1_context_no_precomp$SEGMENT() {
        return RuntimeHelper.requireNonNull(constants$1.const$1,"secp256k1_context_no_precomp");
    }
    /**
     * Getter for variable:
     * {@snippet :
     * struct secp256k1_context_struct* secp256k1_context_no_precomp;
     * }
     */
    public static MemorySegment secp256k1_context_no_precomp$get() {
        return (java.lang.foreign.MemorySegment) constants$0.const$5.get(RuntimeHelper.requireNonNull(constants$1.const$1, "secp256k1_context_no_precomp"));
    }
    /**
     * Setter for variable:
     * {@snippet :
     * struct secp256k1_context_struct* secp256k1_context_no_precomp;
     * }
     */
    public static void secp256k1_context_no_precomp$set(MemorySegment x) {
        constants$0.const$5.set(RuntimeHelper.requireNonNull(constants$1.const$1, "secp256k1_context_no_precomp"), x);
    }
    public static MethodHandle secp256k1_selftest$MH() {
        return RuntimeHelper.requireNonNull(constants$1.const$3,"secp256k1_selftest");
    }
    /**
     * {@snippet :
     * void secp256k1_selftest();
     * }
     */
    public static void secp256k1_selftest() {
        var mh$ = secp256k1_selftest$MH();
        try {
            mh$.invokeExact();
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_context_create$MH() {
        return RuntimeHelper.requireNonNull(constants$1.const$5,"secp256k1_context_create");
    }
    /**
     * {@snippet :
     * struct secp256k1_context_struct* secp256k1_context_create(unsigned int flags);
     * }
     */
    public static MemorySegment secp256k1_context_create(int flags) {
        var mh$ = secp256k1_context_create$MH();
        try {
            return (java.lang.foreign.MemorySegment)mh$.invokeExact(flags);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_context_clone$MH() {
        return RuntimeHelper.requireNonNull(constants$2.const$1,"secp256k1_context_clone");
    }
    /**
     * {@snippet :
     * struct secp256k1_context_struct* secp256k1_context_clone(struct secp256k1_context_struct* ctx);
     * }
     */
    public static MemorySegment secp256k1_context_clone(MemorySegment ctx) {
        var mh$ = secp256k1_context_clone$MH();
        try {
            return (java.lang.foreign.MemorySegment)mh$.invokeExact(ctx);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_context_destroy$MH() {
        return RuntimeHelper.requireNonNull(constants$2.const$3,"secp256k1_context_destroy");
    }
    /**
     * {@snippet :
     * void secp256k1_context_destroy(struct secp256k1_context_struct* ctx);
     * }
     */
    public static void secp256k1_context_destroy(MemorySegment ctx) {
        var mh$ = secp256k1_context_destroy$MH();
        try {
            mh$.invokeExact(ctx);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_context_set_illegal_callback$MH() {
        return RuntimeHelper.requireNonNull(constants$3.const$2,"secp256k1_context_set_illegal_callback");
    }
    /**
     * {@snippet :
     * void secp256k1_context_set_illegal_callback(struct secp256k1_context_struct* ctx, void (*fun)(char*,void*), void* data);
     * }
     */
    public static void secp256k1_context_set_illegal_callback(MemorySegment ctx, MemorySegment fun, MemorySegment data) {
        var mh$ = secp256k1_context_set_illegal_callback$MH();
        try {
            mh$.invokeExact(ctx, fun, data);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_context_set_error_callback$MH() {
        return RuntimeHelper.requireNonNull(constants$3.const$4,"secp256k1_context_set_error_callback");
    }
    /**
     * {@snippet :
     * void secp256k1_context_set_error_callback(struct secp256k1_context_struct* ctx, void (*fun)(char*,void*), void* data);
     * }
     */
    public static void secp256k1_context_set_error_callback(MemorySegment ctx, MemorySegment fun, MemorySegment data) {
        var mh$ = secp256k1_context_set_error_callback$MH();
        try {
            mh$.invokeExact(ctx, fun, data);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_scratch_space_create$MH() {
        return RuntimeHelper.requireNonNull(constants$3.const$6,"secp256k1_scratch_space_create");
    }
    /**
     * {@snippet :
     * struct secp256k1_scratch_space_struct* secp256k1_scratch_space_create(struct secp256k1_context_struct* ctx, unsigned long size);
     * }
     */
    public static MemorySegment secp256k1_scratch_space_create(MemorySegment ctx, long size) {
        var mh$ = secp256k1_scratch_space_create$MH();
        try {
            return (java.lang.foreign.MemorySegment)mh$.invokeExact(ctx, size);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_scratch_space_destroy$MH() {
        return RuntimeHelper.requireNonNull(constants$4.const$0,"secp256k1_scratch_space_destroy");
    }
    /**
     * {@snippet :
     * void secp256k1_scratch_space_destroy(struct secp256k1_context_struct* ctx, struct secp256k1_scratch_space_struct* scratch);
     * }
     */
    public static void secp256k1_scratch_space_destroy(MemorySegment ctx, MemorySegment scratch) {
        var mh$ = secp256k1_scratch_space_destroy$MH();
        try {
            mh$.invokeExact(ctx, scratch);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_pubkey_parse$MH() {
        return RuntimeHelper.requireNonNull(constants$4.const$2,"secp256k1_ec_pubkey_parse");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_pubkey_parse(struct secp256k1_context_struct* ctx, struct secp256k1_pubkey* pubkey, unsigned char* input, unsigned long inputlen);
     * }
     */
    public static int secp256k1_ec_pubkey_parse(MemorySegment ctx, MemorySegment pubkey, MemorySegment input, long inputlen) {
        var mh$ = secp256k1_ec_pubkey_parse$MH();
        try {
            return (int)mh$.invokeExact(ctx, pubkey, input, inputlen);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_pubkey_serialize$MH() {
        return RuntimeHelper.requireNonNull(constants$4.const$4,"secp256k1_ec_pubkey_serialize");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_pubkey_serialize(struct secp256k1_context_struct* ctx, unsigned char* output, unsigned long* outputlen, struct secp256k1_pubkey* pubkey, unsigned int flags);
     * }
     */
    public static int secp256k1_ec_pubkey_serialize(MemorySegment ctx, MemorySegment output, MemorySegment outputlen, MemorySegment pubkey, int flags) {
        var mh$ = secp256k1_ec_pubkey_serialize$MH();
        try {
            return (int)mh$.invokeExact(ctx, output, outputlen, pubkey, flags);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_pubkey_cmp$MH() {
        return RuntimeHelper.requireNonNull(constants$4.const$6,"secp256k1_ec_pubkey_cmp");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_pubkey_cmp(struct secp256k1_context_struct* ctx, struct secp256k1_pubkey* pubkey1, struct secp256k1_pubkey* pubkey2);
     * }
     */
    public static int secp256k1_ec_pubkey_cmp(MemorySegment ctx, MemorySegment pubkey1, MemorySegment pubkey2) {
        var mh$ = secp256k1_ec_pubkey_cmp$MH();
        try {
            return (int)mh$.invokeExact(ctx, pubkey1, pubkey2);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ecdsa_signature_parse_compact$MH() {
        return RuntimeHelper.requireNonNull(constants$5.const$0,"secp256k1_ecdsa_signature_parse_compact");
    }
    /**
     * {@snippet :
     * int secp256k1_ecdsa_signature_parse_compact(struct secp256k1_context_struct* ctx, struct secp256k1_ecdsa_signature* sig, unsigned char* input64);
     * }
     */
    public static int secp256k1_ecdsa_signature_parse_compact(MemorySegment ctx, MemorySegment sig, MemorySegment input64) {
        var mh$ = secp256k1_ecdsa_signature_parse_compact$MH();
        try {
            return (int)mh$.invokeExact(ctx, sig, input64);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ecdsa_signature_parse_der$MH() {
        return RuntimeHelper.requireNonNull(constants$5.const$1,"secp256k1_ecdsa_signature_parse_der");
    }
    /**
     * {@snippet :
     * int secp256k1_ecdsa_signature_parse_der(struct secp256k1_context_struct* ctx, struct secp256k1_ecdsa_signature* sig, unsigned char* input, unsigned long inputlen);
     * }
     */
    public static int secp256k1_ecdsa_signature_parse_der(MemorySegment ctx, MemorySegment sig, MemorySegment input, long inputlen) {
        var mh$ = secp256k1_ecdsa_signature_parse_der$MH();
        try {
            return (int)mh$.invokeExact(ctx, sig, input, inputlen);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ecdsa_signature_serialize_der$MH() {
        return RuntimeHelper.requireNonNull(constants$5.const$3,"secp256k1_ecdsa_signature_serialize_der");
    }
    /**
     * {@snippet :
     * int secp256k1_ecdsa_signature_serialize_der(struct secp256k1_context_struct* ctx, unsigned char* output, unsigned long* outputlen, struct secp256k1_ecdsa_signature* sig);
     * }
     */
    public static int secp256k1_ecdsa_signature_serialize_der(MemorySegment ctx, MemorySegment output, MemorySegment outputlen, MemorySegment sig) {
        var mh$ = secp256k1_ecdsa_signature_serialize_der$MH();
        try {
            return (int)mh$.invokeExact(ctx, output, outputlen, sig);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ecdsa_signature_serialize_compact$MH() {
        return RuntimeHelper.requireNonNull(constants$5.const$4,"secp256k1_ecdsa_signature_serialize_compact");
    }
    /**
     * {@snippet :
     * int secp256k1_ecdsa_signature_serialize_compact(struct secp256k1_context_struct* ctx, unsigned char* output64, struct secp256k1_ecdsa_signature* sig);
     * }
     */
    public static int secp256k1_ecdsa_signature_serialize_compact(MemorySegment ctx, MemorySegment output64, MemorySegment sig) {
        var mh$ = secp256k1_ecdsa_signature_serialize_compact$MH();
        try {
            return (int)mh$.invokeExact(ctx, output64, sig);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ecdsa_verify$MH() {
        return RuntimeHelper.requireNonNull(constants$5.const$5,"secp256k1_ecdsa_verify");
    }
    /**
     * {@snippet :
     * int secp256k1_ecdsa_verify(struct secp256k1_context_struct* ctx, struct secp256k1_ecdsa_signature* sig, unsigned char* msghash32, struct secp256k1_pubkey* pubkey);
     * }
     */
    public static int secp256k1_ecdsa_verify(MemorySegment ctx, MemorySegment sig, MemorySegment msghash32, MemorySegment pubkey) {
        var mh$ = secp256k1_ecdsa_verify$MH();
        try {
            return (int)mh$.invokeExact(ctx, sig, msghash32, pubkey);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ecdsa_signature_normalize$MH() {
        return RuntimeHelper.requireNonNull(constants$6.const$0,"secp256k1_ecdsa_signature_normalize");
    }
    /**
     * {@snippet :
     * int secp256k1_ecdsa_signature_normalize(struct secp256k1_context_struct* ctx, struct secp256k1_ecdsa_signature* sigout, struct secp256k1_ecdsa_signature* sigin);
     * }
     */
    public static int secp256k1_ecdsa_signature_normalize(MemorySegment ctx, MemorySegment sigout, MemorySegment sigin) {
        var mh$ = secp256k1_ecdsa_signature_normalize$MH();
        try {
            return (int)mh$.invokeExact(ctx, sigout, sigin);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MemoryLayout secp256k1_nonce_function_rfc6979$LAYOUT() {
        return RuntimeHelper.POINTER;
    }
    public static VarHandle secp256k1_nonce_function_rfc6979$VH() {
        return constants$0.const$5;
    }
    public static MemorySegment secp256k1_nonce_function_rfc6979$SEGMENT() {
        return RuntimeHelper.requireNonNull(constants$6.const$2,"secp256k1_nonce_function_rfc6979");
    }
    /**
     * Getter for variable:
     * {@snippet :
     * int (*secp256k1_nonce_function_rfc6979)(unsigned char*,unsigned char*,unsigned char*,unsigned char*,void*,unsigned int);
     * }
     */
    public static MemorySegment secp256k1_nonce_function_rfc6979$get() {
        return (java.lang.foreign.MemorySegment) constants$0.const$5.get(RuntimeHelper.requireNonNull(constants$6.const$2, "secp256k1_nonce_function_rfc6979"));
    }
    /**
     * Setter for variable:
     * {@snippet :
     * int (*secp256k1_nonce_function_rfc6979)(unsigned char*,unsigned char*,unsigned char*,unsigned char*,void*,unsigned int);
     * }
     */
    public static void secp256k1_nonce_function_rfc6979$set(MemorySegment x) {
        constants$0.const$5.set(RuntimeHelper.requireNonNull(constants$6.const$2, "secp256k1_nonce_function_rfc6979"), x);
    }
    public static secp256k1_nonce_function_rfc6979 secp256k1_nonce_function_rfc6979 () {
        return secp256k1_nonce_function_rfc6979.ofAddress(secp256k1_nonce_function_rfc6979$get(), Arena.global());
    }
    public static MemoryLayout secp256k1_nonce_function_default$LAYOUT() {
        return RuntimeHelper.POINTER;
    }
    public static VarHandle secp256k1_nonce_function_default$VH() {
        return constants$0.const$5;
    }
    public static MemorySegment secp256k1_nonce_function_default$SEGMENT() {
        return RuntimeHelper.requireNonNull(constants$6.const$4,"secp256k1_nonce_function_default");
    }
    /**
     * Getter for variable:
     * {@snippet :
     * int (*secp256k1_nonce_function_default)(unsigned char*,unsigned char*,unsigned char*,unsigned char*,void*,unsigned int);
     * }
     */
    public static MemorySegment secp256k1_nonce_function_default$get() {
        return (java.lang.foreign.MemorySegment) constants$0.const$5.get(RuntimeHelper.requireNonNull(constants$6.const$4, "secp256k1_nonce_function_default"));
    }
    /**
     * Setter for variable:
     * {@snippet :
     * int (*secp256k1_nonce_function_default)(unsigned char*,unsigned char*,unsigned char*,unsigned char*,void*,unsigned int);
     * }
     */
    public static void secp256k1_nonce_function_default$set(MemorySegment x) {
        constants$0.const$5.set(RuntimeHelper.requireNonNull(constants$6.const$4, "secp256k1_nonce_function_default"), x);
    }
    public static secp256k1_nonce_function_default secp256k1_nonce_function_default () {
        return secp256k1_nonce_function_default.ofAddress(secp256k1_nonce_function_default$get(), Arena.global());
    }
    public static MethodHandle secp256k1_ecdsa_sign$MH() {
        return RuntimeHelper.requireNonNull(constants$7.const$1,"secp256k1_ecdsa_sign");
    }
    /**
     * {@snippet :
     * int secp256k1_ecdsa_sign(struct secp256k1_context_struct* ctx, struct secp256k1_ecdsa_signature* sig, unsigned char* msghash32, unsigned char* seckey, int (*noncefp)(unsigned char*,unsigned char*,unsigned char*,unsigned char*,void*,unsigned int), void* ndata);
     * }
     */
    public static int secp256k1_ecdsa_sign(MemorySegment ctx, MemorySegment sig, MemorySegment msghash32, MemorySegment seckey, MemorySegment noncefp, MemorySegment ndata) {
        var mh$ = secp256k1_ecdsa_sign$MH();
        try {
            return (int)mh$.invokeExact(ctx, sig, msghash32, seckey, noncefp, ndata);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_seckey_verify$MH() {
        return RuntimeHelper.requireNonNull(constants$7.const$3,"secp256k1_ec_seckey_verify");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_seckey_verify(struct secp256k1_context_struct* ctx, unsigned char* seckey);
     * }
     */
    public static int secp256k1_ec_seckey_verify(MemorySegment ctx, MemorySegment seckey) {
        var mh$ = secp256k1_ec_seckey_verify$MH();
        try {
            return (int)mh$.invokeExact(ctx, seckey);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_pubkey_create$MH() {
        return RuntimeHelper.requireNonNull(constants$7.const$4,"secp256k1_ec_pubkey_create");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_pubkey_create(struct secp256k1_context_struct* ctx, struct secp256k1_pubkey* pubkey, unsigned char* seckey);
     * }
     */
    public static int secp256k1_ec_pubkey_create(MemorySegment ctx, MemorySegment pubkey, MemorySegment seckey) {
        var mh$ = secp256k1_ec_pubkey_create$MH();
        try {
            return (int)mh$.invokeExact(ctx, pubkey, seckey);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_seckey_negate$MH() {
        return RuntimeHelper.requireNonNull(constants$7.const$5,"secp256k1_ec_seckey_negate");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_seckey_negate(struct secp256k1_context_struct* ctx, unsigned char* seckey);
     * }
     */
    public static int secp256k1_ec_seckey_negate(MemorySegment ctx, MemorySegment seckey) {
        var mh$ = secp256k1_ec_seckey_negate$MH();
        try {
            return (int)mh$.invokeExact(ctx, seckey);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_privkey_negate$MH() {
        return RuntimeHelper.requireNonNull(constants$8.const$0,"secp256k1_ec_privkey_negate");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_privkey_negate(struct secp256k1_context_struct* ctx, unsigned char* seckey);
     * }
     */
    public static int secp256k1_ec_privkey_negate(MemorySegment ctx, MemorySegment seckey) {
        var mh$ = secp256k1_ec_privkey_negate$MH();
        try {
            return (int)mh$.invokeExact(ctx, seckey);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_pubkey_negate$MH() {
        return RuntimeHelper.requireNonNull(constants$8.const$1,"secp256k1_ec_pubkey_negate");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_pubkey_negate(struct secp256k1_context_struct* ctx, struct secp256k1_pubkey* pubkey);
     * }
     */
    public static int secp256k1_ec_pubkey_negate(MemorySegment ctx, MemorySegment pubkey) {
        var mh$ = secp256k1_ec_pubkey_negate$MH();
        try {
            return (int)mh$.invokeExact(ctx, pubkey);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_seckey_tweak_add$MH() {
        return RuntimeHelper.requireNonNull(constants$8.const$2,"secp256k1_ec_seckey_tweak_add");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_seckey_tweak_add(struct secp256k1_context_struct* ctx, unsigned char* seckey, unsigned char* tweak32);
     * }
     */
    public static int secp256k1_ec_seckey_tweak_add(MemorySegment ctx, MemorySegment seckey, MemorySegment tweak32) {
        var mh$ = secp256k1_ec_seckey_tweak_add$MH();
        try {
            return (int)mh$.invokeExact(ctx, seckey, tweak32);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_privkey_tweak_add$MH() {
        return RuntimeHelper.requireNonNull(constants$8.const$3,"secp256k1_ec_privkey_tweak_add");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_privkey_tweak_add(struct secp256k1_context_struct* ctx, unsigned char* seckey, unsigned char* tweak32);
     * }
     */
    public static int secp256k1_ec_privkey_tweak_add(MemorySegment ctx, MemorySegment seckey, MemorySegment tweak32) {
        var mh$ = secp256k1_ec_privkey_tweak_add$MH();
        try {
            return (int)mh$.invokeExact(ctx, seckey, tweak32);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_pubkey_tweak_add$MH() {
        return RuntimeHelper.requireNonNull(constants$8.const$4,"secp256k1_ec_pubkey_tweak_add");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_pubkey_tweak_add(struct secp256k1_context_struct* ctx, struct secp256k1_pubkey* pubkey, unsigned char* tweak32);
     * }
     */
    public static int secp256k1_ec_pubkey_tweak_add(MemorySegment ctx, MemorySegment pubkey, MemorySegment tweak32) {
        var mh$ = secp256k1_ec_pubkey_tweak_add$MH();
        try {
            return (int)mh$.invokeExact(ctx, pubkey, tweak32);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_seckey_tweak_mul$MH() {
        return RuntimeHelper.requireNonNull(constants$8.const$5,"secp256k1_ec_seckey_tweak_mul");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_seckey_tweak_mul(struct secp256k1_context_struct* ctx, unsigned char* seckey, unsigned char* tweak32);
     * }
     */
    public static int secp256k1_ec_seckey_tweak_mul(MemorySegment ctx, MemorySegment seckey, MemorySegment tweak32) {
        var mh$ = secp256k1_ec_seckey_tweak_mul$MH();
        try {
            return (int)mh$.invokeExact(ctx, seckey, tweak32);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_privkey_tweak_mul$MH() {
        return RuntimeHelper.requireNonNull(constants$9.const$0,"secp256k1_ec_privkey_tweak_mul");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_privkey_tweak_mul(struct secp256k1_context_struct* ctx, unsigned char* seckey, unsigned char* tweak32);
     * }
     */
    public static int secp256k1_ec_privkey_tweak_mul(MemorySegment ctx, MemorySegment seckey, MemorySegment tweak32) {
        var mh$ = secp256k1_ec_privkey_tweak_mul$MH();
        try {
            return (int)mh$.invokeExact(ctx, seckey, tweak32);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_pubkey_tweak_mul$MH() {
        return RuntimeHelper.requireNonNull(constants$9.const$1,"secp256k1_ec_pubkey_tweak_mul");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_pubkey_tweak_mul(struct secp256k1_context_struct* ctx, struct secp256k1_pubkey* pubkey, unsigned char* tweak32);
     * }
     */
    public static int secp256k1_ec_pubkey_tweak_mul(MemorySegment ctx, MemorySegment pubkey, MemorySegment tweak32) {
        var mh$ = secp256k1_ec_pubkey_tweak_mul$MH();
        try {
            return (int)mh$.invokeExact(ctx, pubkey, tweak32);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_context_randomize$MH() {
        return RuntimeHelper.requireNonNull(constants$9.const$2,"secp256k1_context_randomize");
    }
    /**
     * {@snippet :
     * int secp256k1_context_randomize(struct secp256k1_context_struct* ctx, unsigned char* seed32);
     * }
     */
    public static int secp256k1_context_randomize(MemorySegment ctx, MemorySegment seed32) {
        var mh$ = secp256k1_context_randomize$MH();
        try {
            return (int)mh$.invokeExact(ctx, seed32);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_ec_pubkey_combine$MH() {
        return RuntimeHelper.requireNonNull(constants$9.const$3,"secp256k1_ec_pubkey_combine");
    }
    /**
     * {@snippet :
     * int secp256k1_ec_pubkey_combine(struct secp256k1_context_struct* ctx, struct secp256k1_pubkey* out, struct secp256k1_pubkey** ins, unsigned long n);
     * }
     */
    public static int secp256k1_ec_pubkey_combine(MemorySegment ctx, MemorySegment out, MemorySegment ins, long n) {
        var mh$ = secp256k1_ec_pubkey_combine$MH();
        try {
            return (int)mh$.invokeExact(ctx, out, ins, n);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    public static MethodHandle secp256k1_tagged_sha256$MH() {
        return RuntimeHelper.requireNonNull(constants$9.const$5,"secp256k1_tagged_sha256");
    }
    /**
     * {@snippet :
     * int secp256k1_tagged_sha256(struct secp256k1_context_struct* ctx, unsigned char* hash32, unsigned char* tag, unsigned long taglen, unsigned char* msg, unsigned long msglen);
     * }
     */
    public static int secp256k1_tagged_sha256(MemorySegment ctx, MemorySegment hash32, MemorySegment tag, long taglen, MemorySegment msg, long msglen) {
        var mh$ = secp256k1_tagged_sha256$MH();
        try {
            return (int)mh$.invokeExact(ctx, hash32, tag, taglen, msg, msglen);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
    /**
     * {@snippet :
     * #define NULL 0
     * }
     */
    public static MemorySegment NULL() {
        return constants$10.const$0;
    }
    /**
     * {@snippet :
     * #define SECP256K1_FLAGS_TYPE_MASK 255
     * }
     */
    public static int SECP256K1_FLAGS_TYPE_MASK() {
        return (int)255L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_FLAGS_TYPE_CONTEXT 1
     * }
     */
    public static int SECP256K1_FLAGS_TYPE_CONTEXT() {
        return (int)1L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_FLAGS_TYPE_COMPRESSION 2
     * }
     */
    public static int SECP256K1_FLAGS_TYPE_COMPRESSION() {
        return (int)2L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY 256
     * }
     */
    public static int SECP256K1_FLAGS_BIT_CONTEXT_VERIFY() {
        return (int)256L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_FLAGS_BIT_CONTEXT_SIGN 512
     * }
     */
    public static int SECP256K1_FLAGS_BIT_CONTEXT_SIGN() {
        return (int)512L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY 1024
     * }
     */
    public static int SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY() {
        return (int)1024L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_FLAGS_BIT_COMPRESSION 256
     * }
     */
    public static int SECP256K1_FLAGS_BIT_COMPRESSION() {
        return (int)256L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_CONTEXT_NONE 1
     * }
     */
    public static int SECP256K1_CONTEXT_NONE() {
        return (int)1L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_CONTEXT_VERIFY 257
     * }
     */
    public static int SECP256K1_CONTEXT_VERIFY() {
        return (int)257L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_CONTEXT_SIGN 513
     * }
     */
    public static int SECP256K1_CONTEXT_SIGN() {
        return (int)513L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_CONTEXT_DECLASSIFY 1025
     * }
     */
    public static int SECP256K1_CONTEXT_DECLASSIFY() {
        return (int)1025L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_EC_COMPRESSED 258
     * }
     */
    public static int SECP256K1_EC_COMPRESSED() {
        return (int)258L;
    }
    /**
     * {@snippet :
     * #define SECP256K1_EC_UNCOMPRESSED 2
     * }
     */
    public static int SECP256K1_EC_UNCOMPRESSED() {
        return (int)2L;
    }
}


