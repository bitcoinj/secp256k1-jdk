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
package org.bitcoinj.secp.ffm;

import org.bitcoinj.secp.EcdhSharedSecret;
import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpKeyPair;
import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpResult;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SchnorrSignature;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.EcdsaSignature;
import org.bitcoinj.secp.ffm.segments.LowRGrindingNonce;
import org.bitcoinj.secp.internal.EcdhSharedSecretImpl;
import org.bitcoinj.secp.internal.EcdsaSignatureImpl;
import org.bitcoinj.secp.internal.SecpKeyPairImpl;
import org.bitcoinj.secp.internal.SecpPointUncompressed;
import org.bitcoinj.secp.internal.SecpPubKeyImpl;
import org.bitcoinj.secp.ffm.jextract.secp256k1_ecdsa_signature;
import org.bitcoinj.secp.ffm.jextract.secp256k1_h;
import org.bitcoinj.secp.ffm.jextract.secp256k1_keypair;
import org.bitcoinj.secp.ffm.jextract.secp256k1_pubkey;
import org.bitcoinj.secp.ffm.jextract.secp256k1_xonly_pubkey;
import org.bitcoinj.secp.internal.SchnorrSignatureImpl;
import org.bitcoinj.secp.internal.SecpScalarImpl;
import org.bitcoinj.secp.internal.SecpXOnlyPubKeyImpl;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.bitcoinj.secp.SecpResult.OK;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.C_POINTER;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.SECP256K1_EC_UNCOMPRESSED;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.secp256k1_ellswift_xdh_hash_function_bip324;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.secp256k1_schnorrsig_sign32;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.secp256k1_xonly_pubkey_serialize;

/// Implementation of [Secp256k1] using the `secp256k1` C-language library and the Java Foreign Function & Memory API.
///
/// ## Memory management
///
/// Every API method that needs off-heap (native) memory creates a temporary, thread-scoped "confined" [Arena] (via
/// [Arena#ofConfined()]) for the duration of that call, so all native allocations are deterministically released
/// (via [Arena#close()]]) when the call returns.
///
/// We use `ta` as the name for these `t`emporary/`t`hread arenas.
///
/// Helper methods never create an arena of their own -- they take a [SegmentAllocator] so that the caller
/// retains control over the lifetime of everything that is allocated on its behalf. Any [MemorySegment]
/// returned by a helper is therefore only valid until the caller's arena is closed.
///
/// The only native resource with a lifetime longer than a single call is the `secp256k1_context`, which is
/// allocated and freed by the C library itself (see [#close()]).
public class Secp256k1Foreign implements AutoCloseable, Secp256k1 {
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final MemorySegment ctx;
    static final MemorySegment secp256k1StaticContext = secp256k1_h.secp256k1_context_static();
    private static final MemorySegment NULL = MemorySegment.ofAddress(0L);
    private final SecureRandom secureRandom;

    /// TBD: Static verify method that doesn't require a class instance.
    public static boolean ecdsaVerify(MemorySegment sig, MemorySegment msg_hash, MemorySegment pubkey) {
    /* Bonus example: if all we need is signature verification (and no key
       generation or signing), we don't need to use a context created via
       secp256k1_context_create(). We can simply use the static (i.e., global)
       context secp256k1_context_static. See its description in
       include/secp256k1.h for details. */
        int is_sig_valid = secp256k1_h.secp256k1_ecdsa_verify(secp256k1_h.secp256k1_context_static(), sig, msg_hash, pubkey);
        return is_sig_valid == 1;
    }

    public Secp256k1Foreign() {
        this(secp256k1_h.SECP256K1_CONTEXT_NONE(), true); // Randomize automatically by default
    }

    public Secp256k1Foreign(int flags, boolean randomize) {
        // TODO: Verify using cryptographic random number generator properly
        // We initialize a new `SecureRandom` per instance for the following reasons:
        // 1. Per-instance allocation avoids the static being contained in GraalVM
        //    native-image instances (GraalVM may special-case this) or being cloned when the
        //    containing process is cloned (may occur with containers, etc.)
        // 2. On certain JDK/OS configurations it's possible `SecureRandom.getInstanceStrong()`
        //    can cause a delay. It's better to incur this
        // 3. Some implementations of `SecureRandom` may have locking contention
        //    that could show up in a multi-threaded environment
        // 4. Per-instance allocation allows for override for testing or custom
        //    configurations, though this will require adding new constructors.
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            // This should never happen. The Javadoc for getInstanceStrong() says
            // "Every implementation of the Java platform is required to support
            // at least one strong SecureRandom implementation."
            throw new RuntimeException("No strong SecureRandom available", e);
        }

        /* Before we can call actual API functions, we need to create a "context". */
        ctx = secp256k1_h.secp256k1_context_create(flags);

        if (randomize) {
            /* Randomizing the context is recommended to protect against side-channel
             * leakage See `secp256k1_context_randomize` in secp256k1.h for more
             * information about it. This should never fail. */
            try (Arena ta = Arena.ofConfined()) {
                MemorySegment random = fill_random(ta, 32);
                int return_val = secp256k1_h.secp256k1_context_randomize(ctx, random);
                // zero and free random segment?
                random.fill((byte) 0x00);   // The seed has been copied into `ctx`, zero it before freeing
                if (return_val != 1) throw new RuntimeException("context_randomize failed");
            }
        }
    }

    @Override
    public void close() {
        // Use AtomicBoolean to implement idempotent close as recommended for AutoClosable
        if (closed.compareAndSet(false, true)) {
            secp256k1_h.secp256k1_context_destroy(ctx);
        }
    }

    @Override
    public SecpPrivKey ecPrivKeyCreate() {
        try (Arena ta = Arena.ofConfined()) {
            /* If the secret key is zero or out of range (bigger than secp256k1's
             * order), we try to sample a new key. Note that the probability of this
             * happening is negligible. */
            MemorySegment privKeySeg;
            do {
                privKeySeg = fill_random(ta, 32);
            } while (secp256k1_h.secp256k1_ec_seckey_verify(ctx, privKeySeg) != 1);
            SecpPrivKey privKey = SecpPrivKey.of(privKeySeg.toArray(JAVA_BYTE));
            privKeySeg.fill((byte) 0x00);
            return privKey;
        }
    }

    @Override
    public SecpPubKey ecPubKeyCreate(SecpPrivKey privkey) {
        try (Arena ta = Arena.ofConfined()) {
// Should we verify the key here for safety? (Probably)
            MemorySegment privkeySegment = ta.allocateFrom(JAVA_BYTE, privkey.getEncoded());
            MemorySegment pubKey = ecPubKeyCreate(ta, privkeySegment);
            privkeySegment.fill((byte) 0x00);
            // Return serialized pubkey
            return toSecpPubKey(ta, pubKey);
        }
    }

    MemorySegment ecPubKeyCreate(SegmentAllocator alloc, MemorySegment privkeySegment) {
        /* Public key creation using a valid context with a verified private key should never fail */
        MemorySegment pubkey = secp256k1_pubkey.allocate(alloc);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_create(ctx, pubkey, privkeySegment);
        assert(return_val == 1);
        return pubkey;
    }

    /// Convert a pubKey [MemorySegment] to a [SecpPubKeyImpl]
    private SecpPubKeyImpl toSecpPubKey(SegmentAllocator alloc, MemorySegment pubKeySegment) {
        MemorySegment serialized_pubkey = pubKeySerializeSegment(alloc, pubKeySegment, SECP256K1_EC_UNCOMPRESSED());
        return new SecpPubKeyImpl(serializedPubKeyToPoint(serialized_pubkey));
    }

    /// Convert a serialized, uncompressed pubKey [MemorySegment] to a [SecpPointUncompressed]
    static private SecpPointUncompressed serializedPubKeyToPoint(MemorySegment serializedPubKeySegment) {
        // Extract x and y, create an [SecpPointUncompressed] and return it
        byte[] xBytes = serializedPubKeySegment.asSlice(1, 32).toArray(JAVA_BYTE);
        byte[] yBytes = serializedPubKeySegment.asSlice(33, 32).toArray(JAVA_BYTE);
        // TODO: How to handle point at infinity?
        return new SecpPointUncompressed(SecpFieldElement.of(xBytes), SecpFieldElement.of(yBytes));
    }

    @Override
    public SecpKeyPair ecKeyPairCreate() {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment keyPairSeg = secp256k1_keypair.allocate(ta);
            /* If the secret key is zero or out of range (bigger than secp256k1's
             * order), we try to sample a new key. Note that the probability of this
             * happening is negligible. */
            MemorySegment privKeySeg;
            do {
                privKeySeg = fill_random(ta, 32);
            } while (secp256k1_h.secp256k1_keypair_create(ctx, keyPairSeg, privKeySeg) != 1);
            // TODO: Parse keyPairSeg into standard SecpKeyPairImpl
            SecpKeyPair keyPair = toKeyPair(ta, keyPairSeg);
            privKeySeg.fill((byte) 0x00);
            keyPairSeg.fill((byte) 0x00);
            return keyPair;
        }
    }

    @Override
    public SecpKeyPair ecKeyPairCreate(SecpPrivKey privKey) {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment keyPairSeg = secp256k1_keypair.allocate(ta);
            MemorySegment privKeySeg = ta.allocateFrom(JAVA_BYTE, privKey.getEncoded());
            int return_val = secp256k1_h.secp256k1_keypair_create(ctx, keyPairSeg, privKeySeg);
            privKeySeg.fill((byte) 0x00);
            assert(return_val == 1);
            // TODO: Parse keyPairSeg into standard SecpKeyPairImpl
            SecpKeyPair keyPair = toKeyPair(ta, keyPairSeg);
            keyPairSeg.fill((byte) 0x00);
            return keyPair;
        }
    }

    @Override
    public SecpPubKey ecPubKeyTweakMul(SecpPoint.Uncompressed pubKey, BigInteger scalarMultiplier) {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment pubKeySeg = pubKeyParse(ta, pubKey).get();
            byte[] tweakBytes = SecpScalarImpl.integerTo32Bytes(scalarMultiplier);
            MemorySegment tweakSeg = ta.allocateFrom(JAVA_BYTE, tweakBytes);
            int return_val = secp256k1_h.secp256k1_ec_pubkey_tweak_mul(ctx, pubKeySeg, tweakSeg);
            if (return_val != 1) {
                throw new IllegalStateException("Tweak_mul failed");
            }
            return toSecpPubKey(ta, pubKeySeg);
        }
    }

    @Override
    public SecpPubKey ecPubKeyCombine(SecpPoint.Uncompressed key1, SecpPoint.Uncompressed key2) {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment resultKeySeg = secp256k1_pubkey.allocate(ta);
            MemorySegment ins = ta.allocate(C_POINTER, 2);
            ins.setAtIndex(C_POINTER, 0, pubKeyParse(ta, key1).get());
            ins.setAtIndex(C_POINTER, 1, pubKeyParse(ta, key2).get());
            int return_val = secp256k1_h.secp256k1_ec_pubkey_combine(ctx, resultKeySeg, ins, 2);
            if (return_val != 1) {
                throw new IllegalStateException("secp256k1_ec_pubkey_combine failed");
            }
            return toSecpPubKey(ta, resultKeySeg);
        }
    }

    public SecpPubKey ecPubKeyCombine(SecpPubKey key1) {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment resultKeySeg = secp256k1_pubkey.allocate(ta);
            MemorySegment ins = ta.allocate(C_POINTER, 1);
            ins.setAtIndex(C_POINTER, 0, pubKeyParse(ta, key1).get());
            int return_val = secp256k1_h.secp256k1_ec_pubkey_combine(ctx, resultKeySeg, ins, 1);
            if (return_val != 1) {
                throw new IllegalStateException("secp256k1_ec_pubkey_combine failed");
            }
            return toSecpPubKey(ta, resultKeySeg);
        }
    }


    /// Since `PubKeyData` is serializable without using the native lib, this method
    /// serialized without a native call.
    /// @param pubKey
    /// @param flags
    /// @return
    @Override
    public byte[] ecPubKeySerialize(SecpPubKey pubKey, int flags) {
        boolean compressed = switch(flags) {
            case 2 -> false;           // SECP256K1_EC_UNCOMPRESSED())
            case 258 -> true;         // SECP256K1_EC_COMPRESSED())
            default -> throw new IllegalArgumentException();
        };
        return pubKey.serialize(compressed);
    }

    /// Create a serialized pubKey from an internal format pubKey
    /// @param alloc allocator to create segments with
    /// @param pubKeySegment pubKey in internal format
    /// @param flags flags for serialization
    /// @return serialized pubKey
    MemorySegment pubKeySerializeSegment(SegmentAllocator alloc, MemorySegment pubKeySegment, int flags) {
        int byteSize = switch(flags) {
            case 2 -> 65;           // SECP256K1_EC_UNCOMPRESSED())
            case 258 -> 33;         // SECP256K1_EC_COMPRESSED())
            default -> throw new IllegalArgumentException();
        };
        MemorySegment serialized_pubkey = alloc.allocate(byteSize);
        MemorySegment lenSegment = alloc.allocate(secp256k1_h.size_t);
        lenSegment.set(secp256k1_h.size_t, 0, serialized_pubkey.byteSize());
        int return_val = secp256k1_h.secp256k1_ec_pubkey_serialize(secp256k1StaticContext,
                serialized_pubkey,
                lenSegment,
                pubKeySegment,
                flags);
        assert(return_val == 1);
        /* Should be the same size as the size of the output. */
        assert(lenSegment.get(secp256k1_h.size_t, 0) == serialized_pubkey.byteSize());
        return  serialized_pubkey;
    }

    @Override
    public SecpResult<SecpPubKey> ecPubKeyParse(byte[] inputData) {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment input = ta.allocateFrom(JAVA_BYTE, inputData);
            MemorySegment pubkey = secp256k1_pubkey.allocate(ta);
            int return_val = secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, input, input.byteSize());
            return SecpResult.checked(return_val, () -> toSecpPubKey(ta, pubkey));
        }
    }

    @Override
    public SecpResult<SecpXOnlyPubKey> xOnlyPubKeyParse(byte[] inputData) {
        if (inputData.length != 32) throw new IllegalArgumentException("length != 32");
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment input = ta.allocateFrom(JAVA_BYTE, inputData);
            MemorySegment xOnly = secp256k1_xonly_pubkey.allocate(ta);
            int return_val = secp256k1_h.secp256k1_xonly_pubkey_parse(ctx, xOnly, input);
            if (return_val != 1) return SecpResult.err(return_val);
            // Surprisingly, secp256k1_xonly_pubkey is 64 opaque bytes, so we need to serialize to get 32 bytes
            MemorySegment serializedXOnly = ta.allocate(32);
            secp256k1_xonly_pubkey_serialize(ctx, serializedXOnly, xOnly);  // Always returns 1
            return SecpResult.ok(SecpXOnlyPubKeyImpl.ofVerifiedBytes(serializedXOnly.toArray(JAVA_BYTE)));
        }
    }

    /// Parse a pubKey into the 64-byte internal format.
    /// @param alloc allocator to create segments with
    /// @param pubKeyData the pubKey to parse
    /// @return a result containing a segment (valid for the lifetime of `alloc`) in internal format
    private SecpResult<MemorySegment> pubKeyParse(SegmentAllocator alloc, SecpPoint.Uncompressed pubKeyData) {
        MemorySegment input = alloc.allocateFrom(JAVA_BYTE, pubKeyData.serialize()); // 65 byte, uncompressed format
        MemorySegment pubkey = secp256k1_pubkey.allocate(alloc);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, input, input.byteSize());
        return SecpResult.checked(return_val, () -> pubkey);
    }

    @Override
    public SecpResult<EcdsaSignature> ecdsaSign(byte[] msg_hash_data, SecpPrivKey privKey) {
        checkArg(msg_hash_data.length == 32, "Message must be 32-byte (hash)");
        try (Arena ta = Arena.ofConfined()) {
            /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
             * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
             * Signing with a valid context, verified secret key
             * and the default nonce function should never fail. */
            MemorySegment msg_hash = ta.allocateFrom(JAVA_BYTE, msg_hash_data);
            MemorySegment sig = secp256k1_ecdsa_signature.allocate(ta);          // internal signature format
            MemorySegment serSigSeg = secp256k1_ecdsa_signature.allocate(ta);    // serialized signature format
            MemorySegment privKeySeg = ta.allocateFrom(JAVA_BYTE, privKey.getEncoded());
            int return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, privKeySeg, NULL, NULL);
            privKeySeg.fill((byte) 0x00);
            secp256k1_h.secp256k1_ecdsa_signature_serialize_compact(ctx, serSigSeg, sig);
            return SecpResult.checked(return_val, () -> new EcdsaSignatureImpl(serSigSeg.toArray(JAVA_BYTE)));
        }
    }

    /// ECDSA signing with Low-R grinding. Will potentially sign multiple times until a low-R signature is generated.
    /// @param msg_hash_data hashed message data
    /// @param privKey private key
    /// @return A result, which on success contains a valid signature with a low R value.
    @Override
    public SecpResult<EcdsaSignature> ecdsaSignLowR(byte[] msg_hash_data, SecpPrivKey privKey) {
        checkArg(msg_hash_data.length == 32, "Message must be 32-byte (hash)");
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment msg_hash = ta.allocateFrom(JAVA_BYTE, msg_hash_data);
            MemorySegment privKeySeg = ta.allocateFrom(JAVA_BYTE, privKey.getEncoded());
            MemorySegment sig = secp256k1_ecdsa_signature.allocate(ta);  // internal signature format
            MemorySegment serSigSeg = secp256k1_ecdsa_signature.allocate(ta);  // serialized signature format
            MemorySegment nonce = null;
            int count = 0;
            int return_val;
            do {
                // Sign the message, producing a signature in `sig`
                if (count == 0) {
                    return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, privKeySeg, NULL, NULL);
                } else {
                    if (nonce == null) {
                        nonce = LowRGrindingNonce.allocate(ta);
                    }
                    LowRGrindingNonce.setCounter(nonce, count);
                    return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, privKeySeg, NULL, nonce);
                }
                count++;
                secp256k1_h.secp256k1_ecdsa_signature_serialize_compact(ctx, serSigSeg, sig);
            } while (return_val == OK && !hasLowR(serSigSeg)); // Retry until we get an error or low-R
            privKeySeg.fill((byte) 0x00);
            return SecpResult.checked(return_val, () -> new EcdsaSignatureImpl(serSigSeg.toArray(JAVA_BYTE)));
        }
    }

    /// Check whether a signature has a low-R value. Since the serialized format is big-endian,
    /// we simply get the first {@code byte} and check its sign.
    /// @param serializedSignatureSegment a serialized, compact low-R signature in a memory segment
    /// @return true if a valid, low-R signature
    private static boolean hasLowR(MemorySegment serializedSignatureSegment) {
        return serializedSignatureSegment.get(JAVA_BYTE, 0) >= 0;
    }

    @Override
    public byte[] ecdsaSignatureSerializeCompact(EcdsaSignature sig) {
        return sig.serializeCompact();
    }

    @Override
    public SecpResult<EcdsaSignature> ecdsaSignatureParseCompact(byte[] serialized_signature) {
        // Use secp256k1_ecdsa_signature_parse_compact to validate the bytes,
        // but pass serialized signature (in big-endian format) to the EcdsaSignatureImpl constructor.
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment sig = secp256k1_ecdsa_signature.allocate(ta);
            int return_val = secp256k1_h.secp256k1_ecdsa_signature_parse_compact(ctx, sig, ta.allocateFrom(JAVA_BYTE, serialized_signature));
            return SecpResult.checked(return_val, () -> new EcdsaSignatureImpl(serialized_signature));
        }
    }

    @Override
    public SecpResult<Boolean> ecdsaVerify(EcdsaSignature sig, byte[] msg_hash_data, SecpPubKey pubKey) {
        checkArg(msg_hash_data.length == 32, "Message must be 32-byte (hash)");
        try (Arena ta = Arena.ofConfined()) {
            /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
             * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
             * Signing with a valid context, verified secret key
             * and the default nonce function should never fail. */
            MemorySegment msg_hash = ta.allocateFrom(JAVA_BYTE, msg_hash_data);
            SecpResult<MemorySegment> parsedPubKey = pubKeyParse(ta, pubKey);
            MemorySegment serSigSeg = ta.allocateFrom(JAVA_BYTE, sig.serializeCompact());
            MemorySegment sigSeg = secp256k1_ecdsa_signature.allocate(ta);   // internal format
            secp256k1_h.secp256k1_ecdsa_signature_parse_compact(ctx, sigSeg, serSigSeg);
            if (parsedPubKey instanceof SecpResult.Err<MemorySegment> err) return SecpResult.err(err.code());
            int return_val = secp256k1_h.secp256k1_ecdsa_verify(ctx,
                    sigSeg,
                    msg_hash,
                    parsedPubKey.get());
            return SecpResult.ok(return_val == 1);
        }
    }

    @Override
    public byte[] taggedSha256(byte[] tag, byte[] message) {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment hash32 = ta.allocate(32);
            MemorySegment tagSeg = ta.allocateFrom(JAVA_BYTE, tag);
            MemorySegment msgSeg = ta.allocateFrom(JAVA_BYTE, message);
            int return_val = secp256k1_h.secp256k1_tagged_sha256(ctx, hash32, tagSeg, tag.length, msgSeg, message.length);
            assert(return_val == 1);
            return hash32.toArray(JAVA_BYTE);
        }
    }

    @Override
    public SchnorrSignature schnorrSigSign32(byte[] messageHash, SecpPrivKey privKey) {
        checkArg(messageHash.length == 32, "Message must be 32-byte (hash)");
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment auxiliary_rand = fill_random(ta, 32);
            return schnorrSigSign32(ta, messageHash, privKey, auxiliary_rand);
        }
    }

    /// schnorrSigSign32 using provided randomness. This is not part of the API and is intended for testing.
    /// @param messageHash message hash
    /// @param privKey private key
    /// @param auxiliaryRandom auxiliary randomness (typically from a test vector)
    /// @return the signature
    public SchnorrSignature schnorrSigSign32(byte[] messageHash, SecpPrivKey privKey, byte[] auxiliaryRandom) {
        checkArg(messageHash.length == 32, "Message must be 32-byte (hash)");
        checkArg(auxiliaryRandom.length == 32, "auxiliaryRandom must be 32-byte)");
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment auxiliary_rand = ta.allocateFrom(JAVA_BYTE, auxiliaryRandom);
            return schnorrSigSign32(ta, messageHash, privKey, auxiliary_rand);
        }
    }

    private SchnorrSignature schnorrSigSign32(SegmentAllocator alloc, byte[] messageHash, SecpPrivKey privKey, MemorySegment auxiliary_rand) {
        MemorySegment sig = alloc.allocate(64);
        MemorySegment msg_hash = alloc.allocateFrom(JAVA_BYTE, messageHash);
        MemorySegment keyPairSeg = privKeyToSegment(alloc, privKey);
        int return_val = secp256k1_schnorrsig_sign32(ctx, sig, msg_hash, keyPairSeg, auxiliary_rand);
        keyPairSeg.fill((byte) 0x00);   // Contains the private key
        assert(return_val == 1);
        return new SchnorrSignatureImpl(sig.toArray(JAVA_BYTE));
    }

    /// Create a `secp256k1_keypair` segment from a [SecpPrivKey]
    /// @param alloc allocator to create segments with
    /// @param privKey private key
    /// @return a segment (valid for the lifetime of `alloc`) containing a key pair
    private MemorySegment privKeyToSegment(SegmentAllocator alloc, SecpPrivKey privKey) {
        byte[] privBytes = privKey.getEncoded();
        MemorySegment privSeg = alloc.allocateFrom(JAVA_BYTE, privBytes);
        MemorySegment keyPairSeg = secp256k1_keypair.allocate(alloc);
        secp256k1_h.secp256k1_keypair_create(ctx, keyPairSeg, privSeg);
        privSeg.fill((byte) 0x00);
        return keyPairSeg;
    }

    /// Construct a [SecpKeyPair]
    /// @param alloc allocator to create segments with
    /// @param keyPairSegment a segment containing a key pair
    /// @return key pair
    private SecpKeyPair toKeyPair(SegmentAllocator alloc, MemorySegment keyPairSegment) {
        MemorySegment pubKeySegment = secp256k1_pubkey.allocate(alloc);
        int return_val = secp256k1_h.secp256k1_keypair_pub(ctx, pubKeySegment, keyPairSegment);
        assert(return_val == 1);
        SecpPubKey pubKey = toSecpPubKey(alloc, pubKeySegment);
        MemorySegment privKeySegment = alloc.allocate(32);
        int return_val2 = secp256k1_h.secp256k1_keypair_sec(ctx, privKeySegment, keyPairSegment);
        assert(return_val2 == 1);
        SecpPrivKey privKey = SecpPrivKey.of(privKeySegment.toArray(JAVA_BYTE));
        privKeySegment.fill((byte) 0x00);
        return new SecpKeyPairImpl(privKey, pubKey);
    }

    @Override
    public SecpResult<Boolean> schnorrSigVerify(SchnorrSignature signature, byte[] msg_hash, SecpXOnlyPubKey pubKey) {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment sigSegment = ta.allocateFrom(JAVA_BYTE, signature.bytes());
            MemorySegment msgSegment = ta.allocateFrom(JAVA_BYTE, msg_hash);
            MemorySegment pubKeySegment = ta.allocateFrom(JAVA_BYTE, pubKey.serialize()); // 32-byte
            MemorySegment pubKeySegmentOpaque = secp256k1_xonly_pubkey.allocate(ta); // 64-byte opaque
            int r = secp256k1_h.secp256k1_xonly_pubkey_parse(ctx, pubKeySegmentOpaque, pubKeySegment);
            if (r != 1) return SecpResult.err(r);
            int return_val = secp256k1_h.secp256k1_schnorrsig_verify(ctx, sigSegment, msgSegment, msg_hash.length, pubKeySegmentOpaque);
            return SecpResult.ok(return_val == 1);
        }
    }

    @Override
    public SecpResult<EcdhSharedSecret> ecdh(SecpPubKey pubKey, SecpPrivKey privKey) {
        try (Arena ta = Arena.ofConfined()) {
            SecpResult<MemorySegment> parsedPubKey = pubKeyParse(ta, pubKey);
            if (parsedPubKey instanceof SecpResult.Err<MemorySegment> err) return SecpResult.err(err.code());
            MemorySegment pubKeySeg = parsedPubKey.get();  // Get pubkey in 64-byte internal format
            MemorySegment privKeySeg = ta.allocateFrom(JAVA_BYTE, privKey.getEncoded());
            MemorySegment output = ta.allocate(32);
            int success = secp256k1_h.secp256k1_ecdh(ctx, output, pubKeySeg, privKeySeg, NULL, NULL);
            privKeySeg.fill((byte) 0x00);
            return SecpResult.checked(success, () -> new EcdhSharedSecretImpl(output.toArray(JAVA_BYTE)));
        }
    }

    @Override
    public byte[] ellswiftEncode(SecpPubKey pubKey) {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment pubKeySeg = pubKeyParse(ta, pubKey).get();
            MemorySegment auxiliaryRandom = fill_random(ta, 32);

            MemorySegment ellSwiftPubKey = ta.allocate(64);

            int ret = secp256k1_h.secp256k1_ellswift_encode(ctx, ellSwiftPubKey, pubKeySeg, auxiliaryRandom);
            assert(ret == 1);

            return ellSwiftPubKey.toArray(JAVA_BYTE);
        }
    }

    @Override
    public SecpPubKey ellswiftDecode(byte[] encodedPubKey) {
        checkArg(encodedPubKey.length == 64, "The byte array length must be 64 bytes");
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment encodedPubKeySeg = ta.allocateFrom(JAVA_BYTE, encodedPubKey);

            MemorySegment decodedPubKeySeg = secp256k1_pubkey.allocate(ta);

            int ret = secp256k1_h.secp256k1_ellswift_decode(ctx, decodedPubKeySeg, encodedPubKeySeg);
            assert(ret == 1);

            return toSecpPubKey(ta, decodedPubKeySeg);
        }
    }

    @Override
    public byte[] ellswiftCreate(SecpPrivKey privKey) {
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment privKeySeg = ta.allocateFrom(JAVA_BYTE, privKey.getEncoded());
            MemorySegment auxiliaryRandomSeg = fill_random(ta, 32);

            MemorySegment ellswiftPubKey = ta.allocate(64);

            int ret = secp256k1_h.secp256k1_ellswift_create(ctx, ellswiftPubKey, privKeySeg, auxiliaryRandomSeg);

            privKeySeg.fill((byte) 0x00);
            assert(ret == 1);

            return ellswiftPubKey.toArray(JAVA_BYTE);
        }
    }

    @Override
    public byte[] ellswiftXDH(byte[] encodedPubKey0, byte[] encodedPubKey1, SecpPrivKey privKey, int party) {
        checkArg(encodedPubKey0.length == 64 && encodedPubKey1.length == 64, "The byte array length must be 64 bytes");
        checkArg(party == 0 || party == 1, "The party must be either 0 or 1");
        try (Arena ta = Arena.ofConfined()) {
            MemorySegment encodedPubKeySeg1 = ta.allocateFrom(JAVA_BYTE, encodedPubKey0);
            MemorySegment encodedPubKeySeg2 = ta.allocateFrom(JAVA_BYTE, encodedPubKey1);
            MemorySegment privKeySeg = ta.allocateFrom(JAVA_BYTE, privKey.getEncoded());

            MemorySegment sharedSecret = ta.allocate(32);

            int ret = secp256k1_h.secp256k1_ellswift_xdh(ctx, sharedSecret, encodedPubKeySeg1, encodedPubKeySeg2, privKeySeg, party, secp256k1_ellswift_xdh_hash_function_bip324(), MemorySegment.NULL);
            assert(ret == 1);

            return sharedSecret.toArray(JAVA_BYTE);
        }
    }

    @Override
    public String toString() {
        return "Secp256k1/" + ProviderId.LIBSECP256K1_FFM;
    }

    /// @param allocator allocator to create segment with
    /// @param size size in bytes of random data
    /// @return A newly-allocated memory segment full of random data
    private MemorySegment fill_random(SegmentAllocator allocator, int size) {
        byte[] data = new byte[size];
        try {
            secureRandom.nextBytes(data);
            return allocator.allocateFrom(JAVA_BYTE, data);
        } finally {
            Arrays.fill(data, (byte) 0);
        }
    }

    private static void checkArg(boolean condition, String string) {
        if (!condition) {
            throw new IllegalArgumentException(string);
        }
    }
}
