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
import org.bitcoinj.secp.SecpScalar;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SchnorrSignature;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.EcdsaSignature;
import org.bitcoinj.secp.ffm.jextract.secp256k1_musig_aggnonce;
import org.bitcoinj.secp.ffm.jextract.secp256k1_musig_keyagg_cache;
import org.bitcoinj.secp.ffm.jextract.secp256k1_musig_partial_sig;
import org.bitcoinj.secp.ffm.jextract.secp256k1_musig_pubnonce;
import org.bitcoinj.secp.ffm.jextract.secp256k1_musig_secnonce;
import org.bitcoinj.secp.ffm.jextract.secp256k1_musig_session;
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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.bitcoinj.secp.SecpResult.OK;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.C_POINTER;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.SECP256K1_EC_UNCOMPRESSED;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.secp256k1_musig_pubkey_agg;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.secp256k1_schnorrsig_sign32;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.secp256k1_xonly_pubkey_serialize;

/**
 * Implementation of {@link Secp256k1} using the {@code secp256k1} C-language library and the Java Foreign Function &amp; Memory API.
 */
public class Secp256k1Foreign implements AutoCloseable, Secp256k1 {
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final Arena arena;
    private final MemorySegment ctx;
    /* package */ static final Arena globalArena = Arena.ofAuto();
    /* package */ static final MemorySegment secp256k1StaticContext = secp256k1_h.secp256k1_context_static();
    private static final MemorySegment NULL = MemorySegment.ofAddress(0L);
    private static final SecureRandom secureRandom;
    static {
        // TODO: Verify using cryptographic random number generator properly
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            // This should never happen. The Javadoc for getInstanceStrong() says
            // "Every implementation of the Java platform is required to support
            // at least one strong SecureRandom implementation."
            throw new RuntimeException("No strong SecureRandom available", e);
        }
    }

    public record KeyAggCache(SecpPubKey aggKey, MemorySegment cache) {}

    public record MusigNonce(MusigPubNonce pubNonce, MemorySegment secNonce) { }

    public record MusigPubNonce(MemorySegment pubNonce, byte[] serialized) {}

    public MusigPubNonce parsePubNonce(byte[] serialized) {
        checkArg(serialized.length == 66, "serialized pubNonce must be 66 bytes");
        MemorySegment in = arena.allocateFrom(JAVA_BYTE, serialized);
        MemorySegment pn = secp256k1_musig_pubnonce.allocate(arena);
        if (secp256k1_h.secp256k1_musig_pubnonce_parse(ctx, pn, in) != 1)
            throw new IllegalStateException("pubnonce_parse failed");
        return new MusigPubNonce(pn, serialized);
    }

    public record MusigAggNonce(MemorySegment aggNonce, byte[] serialized) {}

    public MusigAggNonce parseAggNonce(byte[] serialized) {
        // Check ACTUAL expected length
        checkArg(serialized.length == 66, "serialized MusigNonce must be 66 bytes");
        MemorySegment serialSeg = arena.allocateFrom(JAVA_BYTE, serialized);
        MemorySegment aggNonceSeg = secp256k1_musig_aggnonce.allocate(arena);
        secp256k1_h.secp256k1_musig_aggnonce_parse(ctx, aggNonceSeg, serialSeg);

        return new MusigAggNonce(aggNonceSeg, serialized);
    }

    public record PartialSig(SecpScalar scalar, MemorySegment segment, byte[] serialized) {}

    public PartialSig parsePartialSig(byte[] serialized) {
        checkArg(serialized.length == 32, "serialized PartialSig must be 32 bytes");
        SecpScalar scalar = new SecpScalarImpl(serialized);
        MemorySegment serialSeg = arena.allocateFrom(JAVA_BYTE, serialized);
        MemorySegment segment = arena.allocate(36);
        secp256k1_h.secp256k1_musig_partial_sig_parse(ctx, segment, serialSeg);
        return new PartialSig(scalar, segment, serialized);
    }

    /**
     * TBD: Static verify method that doesn't require a class instance.
     */
    public static boolean ecdsaVerify(MemorySegment sig, MemorySegment msg_hash, MemorySegment pubkey) {
        //MemorySegment msg_hash = arena.allocateArray(JAVA_BYTE, msg_hash_data);
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
        arena = Arena.ofShared();
        /* Before we can call actual API functions, we need to create a "context". */
        ctx = secp256k1_h.secp256k1_context_create(flags);

        if (randomize) {
            /* Randomizing the context is recommended to protect against side-channel
             * leakage See `secp256k1_context_randomize` in secp256k1.h for more
             * information about it. This should never fail. */
            MemorySegment random = fill_random(arena, 32);
            int return_val = secp256k1_h.secp256k1_context_randomize(ctx, random);
            // zero and free random segment?
            if (return_val != 1) throw new RuntimeException("context_randomize failed");
        }
    }

    @Override
    public void close() {
        // TODO: Zero out any buffers that contain any secrets (keys or randomizations)
        // Use AtomicBoolean to implement idempotent close as recommended for AutoClosable
        if (closed.compareAndSet(false, true)) {
            secp256k1_h.secp256k1_context_destroy(ctx);
            arena.close();
        }
    }

    @Override
    public SecpPrivKey ecPrivKeyCreate() {
        /* If the secret key is zero or out of range (bigger than secp256k1's
         * order), we try to sample a new key. Note that the probability of this
         * happening is negligible. */
        MemorySegment privKeySeg;
        do {
            privKeySeg = fill_random(arena, 32);
        } while (secp256k1_h.secp256k1_ec_seckey_verify(ctx, privKeySeg) != 1);
        SecpPrivKey privKey = SecpPrivKey.of(privKeySeg.toArray(JAVA_BYTE));
        privKeySeg.fill((byte) 0x00);
        return privKey;
    }

    @Override
    public SecpPubKey ecPubKeyCreate(SecpPrivKey privkey) {
        // Should we verify the key here for safety? (Probably)
        MemorySegment privkeySegment = arena.allocateFrom(JAVA_BYTE, privkey.getEncoded());
        MemorySegment pubKey = ecPubKeyCreate(privkeySegment);
        privkeySegment.fill((byte) 0x00);
        // Return serialized pubkey
        return toSecpPubKey(pubKey);
    }

    /* package */ MemorySegment ecPubKeyCreate(MemorySegment privkeySegment) {
        /* Public key creation using a valid context with a verified private key should never fail */
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_create(ctx, pubkey, privkeySegment);
        assert(return_val == 1);
        return pubkey;
    }

    /// Convert a pubKey [MemorySegment] to a [SecpPubKeyImpl]
    static private SecpPubKeyImpl toSecpPubKey(MemorySegment pubKeySegment) {
        MemorySegment serialized_pubkey = pubKeySerializeSegment(pubKeySegment, SECP256K1_EC_UNCOMPRESSED());
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
        MemorySegment keyPairSeg = secp256k1_keypair.allocate(arena);
        /* If the secret key is zero or out of range (bigger than secp256k1's
         * order), we try to sample a new key. Note that the probability of this
         * happening is negligible. */
        MemorySegment privKeySeg;
        do {
            privKeySeg = fill_random(arena, 32);
        } while (secp256k1_h.secp256k1_keypair_create(ctx, keyPairSeg, privKeySeg) != 1);
        // TODO: Parse keyPairSeg into standard SecpKeyPairImpl
        SecpKeyPair keyPair = toKeyPair(keyPairSeg);
        keyPairSeg.fill((byte) 0x00);
        return keyPair;
    }

    @Override
    public SecpKeyPair ecKeyPairCreate(SecpPrivKey privKey) {
        MemorySegment keyPairSeg = secp256k1_keypair.allocate(arena);
        MemorySegment privKeySeg = arena.allocateFrom(JAVA_BYTE, privKey.getEncoded());
        int return_val = secp256k1_h.secp256k1_keypair_create(ctx, keyPairSeg, privKeySeg);
        assert(return_val == 1);
        // TODO: Parse keyPairSeg into standard SecpKeyPairImpl
        SecpKeyPair keyPair = toKeyPair(keyPairSeg);
        keyPairSeg.fill((byte) 0x00);
        return keyPair;
    }

    @Override
    public SecpPubKey ecPubKeyTweakMul(SecpPoint.Uncompressed pubKey, BigInteger scalarMultiplier) {
        MemorySegment pubKeySeg = pubKeyParse(pubKey).get();
        byte[] tweakBytes = SecpScalarImpl.integerTo32Bytes(scalarMultiplier);
        MemorySegment tweakSeg = arena.allocateFrom(JAVA_BYTE, tweakBytes);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_tweak_mul(ctx, pubKeySeg, tweakSeg);
        if (return_val != 1) {
            throw new IllegalStateException("Tweak_mul failed");
        }
        return toSecpPubKey(pubKeySeg);
    }

    @Override
    public SecpPubKey ecPubKeyCombine(SecpPoint.Uncompressed key1, SecpPoint.Uncompressed key2) {
        MemorySegment resultKeySeg = secp256k1_pubkey.allocate(arena);
        MemorySegment ins = arena.allocate(C_POINTER, 2);
        ins.setAtIndex(C_POINTER, 0, pubKeyParse(key1).get());
        ins.setAtIndex(C_POINTER, 1, pubKeyParse(key2).get());
        int return_val = secp256k1_h.secp256k1_ec_pubkey_combine(ctx, resultKeySeg, ins, 2);
        if (return_val != 1) {
            throw new IllegalStateException("secp256k1_ec_pubkey_combine failed");
        }
        return toSecpPubKey(resultKeySeg);
    }

    public SecpPubKey ecPubKeyCombine(SecpPubKey key1) {
        MemorySegment resultKeySeg = secp256k1_pubkey.allocate(arena);
        MemorySegment ins = arena.allocate(C_POINTER, 1);
        ins.setAtIndex(C_POINTER, 0, pubKeyParse(key1).get());
        int return_val = secp256k1_h.secp256k1_ec_pubkey_combine(ctx, resultKeySeg, ins, 1);
        if (return_val != 1) {
            throw new IllegalStateException("secp256k1_ec_pubkey_combine failed");
        }
        return toSecpPubKey(resultKeySeg);
    }


    /**
     * Since {@code PubKeyData} is serializable without using the native lib, this method
     * serialized without a native call.
     * @param pubKey
     * @param flags
     * @return
     */
    @Override
    public byte[] ecPubKeySerialize(SecpPubKey pubKey, int flags) {
        boolean compressed = switch(flags) {
            case 2 -> false;           // SECP256K1_EC_UNCOMPRESSED())
            case 258 -> true;         // SECP256K1_EC_COMPRESSED())
            default -> throw new IllegalArgumentException();
        };
        return pubKey.serialize(compressed);
    }

    /* package */ static MemorySegment pubKeySerializeSegment(MemorySegment pubKeySegment, int flags) {
        int byteSize = switch(flags) {
            case 2 -> 65;           // SECP256K1_EC_UNCOMPRESSED())
            case 258 -> 33;         // SECP256K1_EC_COMPRESSED())
            default -> throw new IllegalArgumentException();
        };
        MemorySegment serialized_pubkey = globalArena.allocate(byteSize);
        MemorySegment lenSegment = globalArena.allocate(secp256k1_h.size_t);
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
        MemorySegment input = arena.allocateFrom(JAVA_BYTE, inputData);
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, input, input.byteSize());
        return SecpResult.checked(return_val, () -> toSecpPubKey(pubkey));
    }

    @Override
    public SecpResult<SecpXOnlyPubKey> xOnlyPubKeyParse(byte[] inputData) {
        if (inputData.length != 32) throw new IllegalArgumentException("length != 32");
        MemorySegment input = arena.allocateFrom(JAVA_BYTE, inputData);
        MemorySegment xOnly = secp256k1_xonly_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_xonly_pubkey_parse(ctx, xOnly, input);
        if (return_val != 1) return SecpResult.err(return_val);
        // Surprisingly, secp256k1_xonly_pubkey is 64 opaque bytes, so we need to serialize to get 32 bytes
        MemorySegment serializedXOnly = arena.allocate(32);
        secp256k1_xonly_pubkey_serialize(ctx, serializedXOnly, xOnly);  // Always returns 1
        return SecpResult.ok(SecpXOnlyPubKeyImpl.ofVerifiedBytes(serializedXOnly.toArray(JAVA_BYTE)));
    }

    private SecpResult<MemorySegment> pubKeyParse(SecpPoint.Uncompressed pubKeyData) {
        MemorySegment input = arena.allocateFrom(JAVA_BYTE, pubKeyData.serialize()); // 65 byte, uncompressed format
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, input, input.byteSize());
        return SecpResult.checked(return_val, () -> pubkey);
    }

    @Override
    public SecpResult<EcdsaSignature> ecdsaSign(byte[] msg_hash_data, SecpPrivKey privKey) {
        checkArg(msg_hash_data.length == 32, "Message must be 32-byte (hash)");
        /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
         * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
         * Signing with a valid context, verified secret key
         * and the default nonce function should never fail. */
        MemorySegment msg_hash = arena.allocateFrom(JAVA_BYTE, msg_hash_data);
        MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);          // internal signature format
        MemorySegment serSigSeg = secp256k1_ecdsa_signature.allocate(arena);    // serialized signature format
        MemorySegment privKeySeg = arena.allocateFrom(JAVA_BYTE, privKey.getEncoded());
        int return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, privKeySeg, NULL, NULL);
        privKeySeg.fill((byte) 0x00);
        secp256k1_h.secp256k1_ecdsa_signature_serialize_compact(ctx, serSigSeg, sig);
        return SecpResult.checked(return_val, () -> new EcdsaSignatureImpl(serSigSeg.toArray(JAVA_BYTE)));
    }

    /**
     * ECDSA signing with Low-R grinding. Will potentially sign multiple times until a low-R signature is generated.
     * @param msg_hash_data hashed message data
     * @param privKey private key
     * @return A result, which on success contains a valid signature with a low R value.
     */
    @Override
    public SecpResult<EcdsaSignature> ecdsaSignLowR(byte[] msg_hash_data, SecpPrivKey privKey) {
        checkArg(msg_hash_data.length == 32, "Message must be 32-byte (hash)");
        MemorySegment msg_hash = arena.allocateFrom(JAVA_BYTE, msg_hash_data);
        MemorySegment privKeySeg = arena.allocateFrom(JAVA_BYTE, privKey.getEncoded());
        MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);  // internal signature format
        MemorySegment serSigSeg = secp256k1_ecdsa_signature.allocate(arena);  // serialized signature format
        LowRGrindingNonce nonce = LowRGrindingNonce.zero(arena);
        int count = 0;
        int return_val;
        do {
            // Sign the message, producing a signature in `sig`
            if (count++ == 0) {
                return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, privKeySeg, NULL, NULL);
            } else {
                return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, privKeySeg, NULL, nonce.segment());
            }
            secp256k1_h.secp256k1_ecdsa_signature_serialize_compact(ctx, serSigSeg, sig);
            nonce.increment();                      // Increment the counter field in the nonce
        } while (return_val == OK && !hasLowR(serSigSeg)); // Retry until we get an error or low-R
        privKeySeg.fill((byte) 0x00);
        return SecpResult.checked(return_val, () -> new EcdsaSignatureImpl(serSigSeg.toArray(JAVA_BYTE)));
    }

    private static boolean hasLowR(MemorySegment serSigSeg) {
        byte highByte = serSigSeg.toArray(JAVA_BYTE)[0];
        return highByte >= 0;
    }

    @Override
    public byte[] ecdsaSignatureSerializeCompact(EcdsaSignature sig) {
        return sig.serializeCompact();
    }

    @Override
    public SecpResult<EcdsaSignature> ecdsaSignatureParseCompact(byte[] serialized_signature) {
        // Use secp256k1_ecdsa_signature_parse_compact to validate the bytes,
        // but pass serialized signature (in big-endian format) to the EcdsaSignatureImpl constructor.
        MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ecdsa_signature_parse_compact(ctx, sig, arena.allocateFrom(JAVA_BYTE, serialized_signature));
        return SecpResult.checked(return_val, () -> new EcdsaSignatureImpl(serialized_signature));
    }

    @Override
    public SecpResult<Boolean> ecdsaVerify(EcdsaSignature sig, byte[] msg_hash_data, SecpPubKey pubKey) {
        checkArg(msg_hash_data.length == 32, "Message must be 32-byte (hash)");
        /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
         * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
         * Signing with a valid context, verified secret key
         * and the default nonce function should never fail. */
        MemorySegment msg_hash = arena.allocateFrom(JAVA_BYTE, msg_hash_data);
        SecpResult<MemorySegment> parsedPubKey = pubKeyParse(pubKey);
        MemorySegment serSigSeg =  arena.allocateFrom(JAVA_BYTE, sig.serializeCompact());
        MemorySegment sigSeg = secp256k1_ecdsa_signature.allocate(arena);   // internal format
        secp256k1_h.secp256k1_ecdsa_signature_parse_compact(ctx, sigSeg, serSigSeg);
        if (parsedPubKey instanceof SecpResult.Err<MemorySegment> err) return SecpResult.err(err.code());
        int return_val = secp256k1_h.secp256k1_ecdsa_verify(ctx,
                sigSeg,
                msg_hash,
                parsedPubKey.get());
        return SecpResult.ok(return_val == 1);
    }

    @Override
    public byte[] taggedSha256(byte[] tag, byte[] message) {
        MemorySegment hash32 = arena.allocate(32);
        MemorySegment tagSeg = arena.allocateFrom(JAVA_BYTE, tag);
        MemorySegment msgSeg = arena.allocateFrom(JAVA_BYTE, message);
        int return_val = secp256k1_h.secp256k1_tagged_sha256(ctx, hash32, tagSeg, tag.length, msgSeg, message.length);
        assert(return_val == 1);
        return hash32.toArray(JAVA_BYTE);
    }

    @Override
    public SchnorrSignature schnorrSigSign32(byte[] messageHash, SecpPrivKey privKey) {
        checkArg(messageHash.length == 32, "Message must be 32-byte (hash)");
        MemorySegment auxiliary_rand = fill_random(arena, 32);
        return schnorrSigSign32(messageHash, privKey, auxiliary_rand);
    }

    /**
     * schnorrSigSign32 using provided randomness. This is not part of the API and is intended for testing.
     * @param messageHash message hash
     * @param privKey private key
     * @param auxiliaryRandom auxiliary randomness (typically from a test vector)
     * @return the signature
     */
    public SchnorrSignature schnorrSigSign32(byte[] messageHash, SecpPrivKey privKey, byte[] auxiliaryRandom) {
        checkArg(messageHash.length == 32, "Message must be 32-byte (hash)");
        checkArg(auxiliaryRandom.length == 32, "auxiliaryRandom must be 32-byte)");
        MemorySegment auxiliary_rand = arena.allocateFrom(JAVA_BYTE, auxiliaryRandom);
        return schnorrSigSign32(messageHash, privKey, auxiliary_rand);
    }

    private SchnorrSignature schnorrSigSign32(byte[] messageHash, SecpPrivKey privKey, MemorySegment auxiliary_rand) {
        MemorySegment sig = arena.allocate(64);
        MemorySegment msg_hash = arena.allocateFrom(JAVA_BYTE, messageHash);
        MemorySegment privKeySeg = privKeyToSegment(privKey);
        int return_val = secp256k1_schnorrsig_sign32(ctx, sig, msg_hash, privKeySeg, auxiliary_rand);
        assert(return_val == 1);
        return new SchnorrSignatureImpl(sig.toArray(JAVA_BYTE));
    }

    private MemorySegment privKeyToSegment(SecpPrivKey privKey) {
        byte[] privBytes = privKey.getEncoded();
        MemorySegment privSeg = arena.allocateFrom(JAVA_BYTE, privBytes);
        MemorySegment keyPairSeg = secp256k1_keypair.allocate(arena);
        secp256k1_h.secp256k1_keypair_create(ctx, keyPairSeg, privSeg);
        return keyPairSeg;
    }

    private SecpKeyPair toKeyPair(MemorySegment keyPairSegment) {
        MemorySegment pubKeySegment = secp256k1_pubkey.allocate(Secp256k1Foreign.globalArena);
        int return_val = secp256k1_h.secp256k1_keypair_pub(ctx, pubKeySegment, keyPairSegment);
        assert(return_val == 1);
        SecpPubKey pubKey = toSecpPubKey(pubKeySegment);
        MemorySegment privKeySegment = Secp256k1Foreign.globalArena.allocate(32);
        int return_val2 = secp256k1_h.secp256k1_keypair_sec(ctx, privKeySegment, keyPairSegment);
        assert(return_val2 == 1);
        SecpPrivKey privKey = SecpPrivKey.of(privKeySegment.toArray(JAVA_BYTE));
        return new SecpKeyPairImpl(privKey, pubKey);
    }

    @Override
    public SecpResult<Boolean> schnorrSigVerify(SchnorrSignature signature, byte[] msg_hash, SecpXOnlyPubKey pubKey) {
        MemorySegment sigSegment = arena.allocateFrom(JAVA_BYTE, signature.bytes());
        MemorySegment msgSegment = arena.allocateFrom(JAVA_BYTE, msg_hash);
        MemorySegment pubKeySegment = arena.allocateFrom(JAVA_BYTE, pubKey.serialize()); // 32-byte
        MemorySegment pubKeySegmentOpaque = secp256k1_xonly_pubkey.allocate(arena); // 64-byte opaque
        int r = secp256k1_h.secp256k1_xonly_pubkey_parse(ctx, pubKeySegmentOpaque, pubKeySegment);
        if (r != 1) return SecpResult.err(r);
        int return_val = secp256k1_h.secp256k1_schnorrsig_verify(ctx, sigSegment, msgSegment, msg_hash.length, pubKeySegmentOpaque);
        return SecpResult.ok(return_val == 1);
    }

    @Override
    public SecpResult<EcdhSharedSecret> ecdh(SecpPubKey pubKey, SecpPrivKey privKey) {
        SecpResult<MemorySegment> parsedPubKey = pubKeyParse(pubKey);
        if (parsedPubKey instanceof SecpResult.Err<MemorySegment> err) return SecpResult.err(err.code());
        MemorySegment pubKeySeg = parsedPubKey.get();  // Get pubkey in 64-byte internal format
        MemorySegment privKeySeg = arena.allocateFrom(JAVA_BYTE, privKey.getEncoded());
        MemorySegment output = arena.allocate(32);
        int success = secp256k1_h.secp256k1_ecdh(ctx, output, pubKeySeg, privKeySeg, NULL, NULL);
        return SecpResult.checked(success, () -> new EcdhSharedSecretImpl(output.toArray(JAVA_BYTE)));
    }

    public List<SecpPubKey> ecPubkeySort (List<SecpPubKey> pubKeys) {
        int n = pubKeys.size();
        MemorySegment pubKeyPtrs = arena.allocate(C_POINTER, n);
        for (int i = 0; i < n; i++) {
            pubKeyPtrs.setAtIndex(C_POINTER, i, pubKeyParse(pubKeys.get(i)).get());
        }
        secp256k1_h.secp256k1_ec_pubkey_sort(ctx, pubKeyPtrs, n);
        List<SecpPubKey> result = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            result.add(toSecpPubKey(pubKeyPtrs.getAtIndex(C_POINTER, i)));
        }
        return List.copyOf(result);
    }

    public MemorySegment secNonceFromBip327(byte[] bip327) {
        checkArg(bip327.length == 97, "BIP-327 secnonce must be 97 bytes (k1||k2||pk)");

        // 33-byte compressed pubkey -> 64-byte internal X||Y (same form stored in the secnonce)
        MemorySegment pkSeg = secp256k1_pubkey.allocate(arena);
        MemorySegment in = arena.allocate(33);
        MemorySegment.copy(bip327, 64, in, JAVA_BYTE, 0, 33);
        if (secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pkSeg, in, 33) != 1)
            throw new IllegalStateException("bad secnonce pubkey");

        // Assemble secp256k1_musig_secnonce: magic | k1 | k2 | ge-bytes(pk)
        MemorySegment secNonceSeg = secp256k1_musig_secnonce.allocate(arena);
        byte[] magic = { (byte)0x22, (byte)0x0e, (byte)0xdc, (byte)0xf1 };
        MemorySegment.copy(magic,   0, secNonceSeg, JAVA_BYTE, 0, 4);
        MemorySegment.copy(bip327,  0, secNonceSeg, JAVA_BYTE, 4, 64);  // k1 || k2 contiguous
        MemorySegment.copy(pkSeg,   0, secNonceSeg, 68, 64);            // internal pubkey bytes
        return secNonceSeg;
    }

    public KeyAggCache createCache(byte[] aggpk) {  // aggpk = 32-byte x-only from the vector
        if (aggpk.length != 32) throw new IllegalArgumentException("aggpk must be 32 bytes");

        // Lift x-only -> full point by parsing a compressed pubkey (even-Y; parity is
        // irrelevant since nonce_gen only hashes the x-coordinate).
        byte[] compressed = new byte[33];
        compressed[0] = 0x02;
        System.arraycopy(aggpk, 0, compressed, 1, 32);

        MemorySegment pkSeg = secp256k1_pubkey.allocate(arena);          // 64-byte internal X||Y
        MemorySegment in = arena.allocate(33);
        MemorySegment.copy(compressed, 0, in, JAVA_BYTE, 0, 33);
        if (secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pkSeg, in, 33) != 1)
            throw new IllegalStateException("bad aggpk");

        MemorySegment seg = secp256k1_musig_keyagg_cache.allocate(arena); // zero-filled
        byte[] magic = { (byte)0xf4, (byte)0xad, (byte)0xbb, (byte)0xdf };
        MemorySegment.copy(magic, 0, seg, JAVA_BYTE, 0, 4);
        MemorySegment.copy(pkSeg, 0, seg, 4, 64);                         // pk into offset 4

        MemorySegment aggKeySeg = secp256k1_pubkey.allocate(arena);
        secp256k1_h.secp256k1_musig_pubkey_get(ctx, aggKeySeg, seg);

        return new KeyAggCache(toSecpPubKey(aggKeySeg), seg);
    }

    public KeyAggCache musigPubkeyAgg (List<SecpPubKey> pubKeys) {
        int n = pubKeys.size();
        MemorySegment pubKeyPtrs = arena.allocate(C_POINTER, n);
        for (int i = 0; i < n; i++) {
            pubKeyPtrs.setAtIndex(C_POINTER, i, pubKeyParse(pubKeys.get(i)).get());
        }

        MemorySegment keyAggCacheSeg = secp256k1_musig_keyagg_cache.allocate(arena);

        secp256k1_musig_pubkey_agg(ctx, MemorySegment.NULL, keyAggCacheSeg, pubKeyPtrs, n);

        MemorySegment aggKeySeg = secp256k1_pubkey.allocate(arena);
        secp256k1_h.secp256k1_musig_pubkey_get(ctx, aggKeySeg, keyAggCacheSeg);

        return new KeyAggCache(toSecpPubKey(aggKeySeg), keyAggCacheSeg);

    }

    public MusigNonce musigNonceGen(byte[] sessionSecRand, SecpPrivKey privKey, SecpPubKey pubKey, byte[] msg32, KeyAggCache cache, byte[] exInput) {
        checkArg(msg32.length == 32 || msg32.length == 0, "msg32 must be 32 bytes or empty");

        MemorySegment secNonceSeg = secp256k1_musig_secnonce.allocate(arena);
        MemorySegment pubNonceSeg = secp256k1_musig_pubnonce.allocate(arena);
        MemorySegment sessionSecRandSeg = arena.allocateFrom(JAVA_BYTE, sessionSecRand);
        MemorySegment privKeySeg = privKeyToSegment(privKey);
        MemorySegment pubKeySeg = pubKeyParse(pubKey).get();
        MemorySegment msgSeg = msg32.length == 32 ? arena.allocateFrom(JAVA_BYTE, msg32) : NULL;
        MemorySegment aggPubKeySeg = cache.cache;
        MemorySegment exInputSeg = arena.allocateFrom(JAVA_BYTE, exInput);

        secp256k1_h.secp256k1_musig_nonce_gen(ctx, secNonceSeg, pubNonceSeg, sessionSecRandSeg, privKeySeg, pubKeySeg, msgSeg, aggPubKeySeg, exInputSeg);

        MemorySegment pubNonceCompressedSeg = arena.allocate(66);
        secp256k1_h.secp256k1_musig_pubnonce_serialize(ctx, pubNonceCompressedSeg, pubNonceSeg);

        MusigPubNonce pubNonce = new MusigPubNonce(pubNonceSeg, pubNonceCompressedSeg.toArray(JAVA_BYTE));

        return new MusigNonce(pubNonce, secNonceSeg);
    }

    public MusigAggNonce musigNonceAgg(List<MusigPubNonce> nonces) {
        int n = nonces.size();
        MemorySegment noncePtrs = arena.allocate(C_POINTER, n);
        for (int i = 0; i < n; i++) {
            noncePtrs.setAtIndex(C_POINTER, i, nonces.get(i).pubNonce);
        }

        MemorySegment aggNonce = secp256k1_musig_aggnonce.allocate(arena);
        MemorySegment aggNonceSerialized = arena.allocate(JAVA_BYTE, 66);

        secp256k1_h.secp256k1_musig_nonce_agg(ctx, aggNonce, noncePtrs, n);

        secp256k1_h.secp256k1_musig_aggnonce_serialize(ctx, aggNonceSerialized, aggNonce);

        return new MusigAggNonce(aggNonce, aggNonceSerialized.toArray(JAVA_BYTE));
    }

    public MemorySegment musigNonceProcess(MusigAggNonce aggNonce, byte[] msg32, KeyAggCache cache) {
        checkArg(msg32.length == 32, "msg32 must be 32 bytes or empty");
        MemorySegment msgSeg = arena.allocateFrom(JAVA_BYTE, msg32);
        MemorySegment session = secp256k1_musig_session.allocate(arena);
        secp256k1_h.secp256k1_musig_nonce_process(ctx, session, aggNonce.aggNonce(), msgSeg, cache.cache());
        return session;
    }

    public PartialSig musigPartialSign(MemorySegment secNonce, SecpKeyPair keyPair, KeyAggCache cache, MemorySegment session) {
        MemorySegment partialSigSeg = secp256k1_musig_partial_sig.allocate(arena);
        MemorySegment keyPairSeg = privKeyToSegment(keyPair.privateKey());

        secp256k1_h.secp256k1_musig_partial_sign(ctx, partialSigSeg, secNonce, keyPairSeg, cache.cache(), session);

        MemorySegment partialSigSerializedSeg = arena.allocate(32);
        secp256k1_h.secp256k1_musig_partial_sig_serialize(ctx, partialSigSerializedSeg, partialSigSeg);

        byte[] partialSigSerialized = partialSigSerializedSeg.toArray(JAVA_BYTE);
        SecpScalar partialSigScalar = new SecpScalarImpl(partialSigSerialized);
        return new PartialSig(partialSigScalar, partialSigSeg, partialSigSerialized);
    }

    public boolean musigPartialSigVerify(PartialSig partialSig, MusigPubNonce nonce, SecpPubKey pubKey, KeyAggCache cache, MemorySegment session) {
        MemorySegment pubKeySeg = pubKeyParse(pubKey).get();
        return secp256k1_h.secp256k1_musig_partial_sig_verify(ctx, partialSig.segment(), nonce.pubNonce(), pubKeySeg,  cache.cache(), session) == 1;
    }

    public SchnorrSignature musigPartialSigAgg(MemorySegment session, List<PartialSig> partialSigs) {
        MemorySegment sig = arena.allocate(64);

        int n = partialSigs.size();
        MemorySegment partialSigPtrs = arena.allocate(C_POINTER, n);
        for (int i = 0; i < n; i++) {
            partialSigPtrs.setAtIndex(C_POINTER, i, partialSigs.get(i).segment());
        }

        secp256k1_h.secp256k1_musig_partial_sig_agg(ctx, sig, session, partialSigPtrs, n);

        return new SchnorrSignatureImpl(sig.toArray(JAVA_BYTE));
    }

    @Override
    public String toString() {
        return "Secp256k1/" + ProviderId.LIBSECP256K1_FFM;
    }

    /**
     *
     * @param allocator allocator to create segment with
     * @param size size in bytes of random data
     * @return A newly-allocated memory segment full of random data
     */
    private static MemorySegment fill_random(SegmentAllocator allocator, int size) {
        byte[] data = new byte[size];
        secureRandom.nextBytes(data);
        return allocator.allocateFrom(JAVA_BYTE, data);
    }

    private static void checkArg(boolean condition, String string) {
        if (!condition) {
            throw new IllegalArgumentException(string);
        }
    }
}
