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
package org.bitcoinj.secp.ffm;

import org.bitcoinj.secp.api.SPByteArray;
import org.bitcoinj.secp.api.SPFieldElement;
import org.bitcoinj.secp.api.SPKeyPair;
import org.bitcoinj.secp.api.SPXOnlyPubKey;
import org.bitcoinj.secp.api.SPPrivKey;
import org.bitcoinj.secp.api.SPPubKey;
import org.bitcoinj.secp.api.SPResult;
import org.bitcoinj.secp.api.Secp256k1;
import org.bitcoinj.secp.api.SPSignatureData;
import org.bitcoinj.secp.api.internal.SPKeyPairImpl;
import org.bitcoinj.secp.api.internal.SPPubKeyImpl;
import org.bitcoinj.secp.ffm.jextract.secp256k1_ecdsa_signature;
import org.bitcoinj.secp.ffm.jextract.secp256k1_h;
import org.bitcoinj.secp.ffm.jextract.secp256k1_keypair;
import org.bitcoinj.secp.ffm.jextract.secp256k1_pubkey;
import org.bitcoinj.secp.ffm.jextract.secp256k1_xonly_pubkey;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.ECPoint;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.C_POINTER;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.NULL;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.SECP256K1_EC_UNCOMPRESSED;
import static org.bitcoinj.secp.ffm.jextract.secp256k1_h.secp256k1_schnorrsig_sign32;

/**
 * Implementation of {@link Secp256k1} using the {@code secp256k1} C-language library and the Java Foreign Function &amp; Memory API.
 */
public class Secp256k1Foreign implements AutoCloseable, Secp256k1 {
    private final Arena arena;
    private final MemorySegment ctx;
    /* package */ static final Arena globalArena = Arena.ofAuto();
    /* package */ static final MemorySegment secp256k1StaticContext = secp256k1_h.secp256k1_context_static();
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

    public Secp256k1Foreign(int flags) {
        this(flags, true); // Randomize automatically by default
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
        secp256k1_h.secp256k1_context_destroy(ctx);
        arena.close();
    }

    int contextRandomize(byte[] randomBytes) {
        return 1;
    }

    @Override
    public SPPrivKey ecPrivKeyCreate() {
        /* If the secret key is zero or out of range (bigger than secp256k1's
         * order), we try to sample a new key. Note that the probability of this
         * happening is negligible. */
        MemorySegment seckey;
        do {
            seckey = fill_random(arena, 32);
        } while (secp256k1_h.secp256k1_ec_seckey_verify(ctx, seckey) != 1);
        SPPrivKey privKey = SPPrivKey.of(seckey.toArray(JAVA_BYTE));
        seckey.fill((byte) 0x00);   
        return privKey;
    }

    @Override
    public SPPubKey ecPubKeyCreate(SPPrivKey privkey) {
        // Should we verify the key here for safety? (Probably)
        MemorySegment privkeySegment = arena.allocateFrom(JAVA_BYTE, privkey.getEncoded());
        MemorySegment pubKey = ecPubKeyCreate(privkeySegment);
        privkeySegment.fill((byte) 0x00);
        // Return serialized pubkey
        return new SPPubKeyImpl(toPoint(pubKey));
    }

    /* package */ MemorySegment ecPubKeyCreate(MemorySegment privkeySegment) {
        /* Public key creation using a valid context with a verified private key should never fail */
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_create(ctx, pubkey, privkeySegment);
        assert(return_val == 1);
        return pubkey;
    }

    static /* package */ ECPoint toPoint(MemorySegment pubKeySegment) {
        // Serialize uncompressed
        MemorySegment serialized_pubkey = pubKeySerializeSegment(pubKeySegment, SECP256K1_EC_UNCOMPRESSED());

        // Extract x and y, create an ECPoint and return it
        byte[] uncompressed_bytes = serialized_pubkey.toArray(JAVA_BYTE);
        return toPoint(uncompressed_bytes);
    }

    static /* package */ ECPoint toPoint(byte[] uncompressed_bytes) {
        // Extract x and y, create an ECPoint and return it
        byte[] xbytes = new byte[32];
        byte[] ybytes = new byte[32];
        System.arraycopy(uncompressed_bytes,  1, xbytes, 0, 32);
        System.arraycopy(uncompressed_bytes, 33, ybytes, 0, 32);
        // TODO: How to handle point at infinity?
        BigInteger x = SPByteArray.toInteger(xbytes);
        BigInteger y = SPByteArray.toInteger(ybytes);
        return new ECPoint(x, y);
    }

    @Override
    public SPKeyPair ecKeyPairCreate() {
        MemorySegment keyPairSeg = secp256k1_keypair.allocate(arena);
        /* If the secret key is zero or out of range (bigger than secp256k1's
         * order), we try to sample a new key. Note that the probability of this
         * happening is negligible. */
        MemorySegment seckey;
        do {
            seckey = fill_random(arena, 32);
        } while (secp256k1_h.secp256k1_keypair_create(ctx, keyPairSeg, seckey) != 1);
        // TODO: Parse keyPairSeg into standard P256K1KeyPairImpl
        SPKeyPair keyPair = toKeyPair(keyPairSeg);
        keyPairSeg.fill((byte) 0x00);
        return keyPair;
    }

    @Override
    public SPKeyPair ecKeyPairCreate(SPPrivKey privKey) {
        MemorySegment keyPairSeg = secp256k1_keypair.allocate(arena);
        MemorySegment seckey = arena.allocateFrom(JAVA_BYTE, privKey.getEncoded());
        int return_val = secp256k1_h.secp256k1_keypair_create(ctx, keyPairSeg, seckey);
        assert(return_val == 1);
        // TODO: Parse keyPairSeg into standard P256K1KeyPairImpl
        SPKeyPair keyPair = toKeyPair(keyPairSeg);
        keyPairSeg.fill((byte) 0x00);
        return keyPair;
    }

    @Override
    public SPPubKey ecPubKeyTweakMul(SPPubKey pubKey, BigInteger scalarMultiplier) {
        MemorySegment pubKeySeg = pubKeyParse(pubKey);
        byte[] tweakBytes = SPFieldElement.integerTo32Bytes(scalarMultiplier);
        MemorySegment tweakSeg = arena.allocateFrom(JAVA_BYTE, tweakBytes);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_tweak_mul(ctx, pubKeySeg, tweakSeg);
        if (return_val != 1) {
            throw new IllegalStateException("Tweak_mul failed");
        }
        return new SPPubKeyImpl(toPoint(pubKeySeg));
    }

    @Override
    public SPPubKey ecPubKeyCombine(SPPubKey key1, SPPubKey key2) {
        MemorySegment resultKeySeg = secp256k1_pubkey.allocate(arena);
        MemorySegment ins = arena.allocate(C_POINTER, 2);
        ins.setAtIndex(C_POINTER, 0, pubKeyParse(key1));
        ins.setAtIndex(C_POINTER, 1, pubKeyParse(key2));
        int return_val = secp256k1_h.secp256k1_ec_pubkey_combine(ctx, resultKeySeg, ins, 2);
        if (return_val != 1) {
            throw new IllegalStateException("secp256k1_ec_pubkey_combine failed");
        }
        return new SPPubKeyImpl(toPoint(resultKeySeg));
    }

    public SPPubKey ecPubKeyCombine(SPPubKey key1) {
        MemorySegment resultKeySeg = secp256k1_pubkey.allocate(arena);
        MemorySegment ins = arena.allocate(C_POINTER, 1);
        ins.setAtIndex(C_POINTER, 0, pubKeyParse(key1));
        int return_val = secp256k1_h.secp256k1_ec_pubkey_combine(ctx, resultKeySeg, ins, 1);
        if (return_val != 1) {
            throw new IllegalStateException("secp256k1_ec_pubkey_combine failed");
        }
        return new SPPubKeyImpl(toPoint(resultKeySeg));
    }


    /**
     * Since {@code PubKeyData} is serializable without using the native lib, this method
     * serialized without a native call.
     * @param pubKey
     * @param flags
     * @return
     */
    @Override
    public byte[] ecPubKeySerialize(SPPubKey pubKey, int flags) {
        boolean compressed = switch(flags) {
            case 2 -> false;           // SECP256K1_EC_UNCOMPRESSED())
            case 258 -> true;         // SECP256K1_EC_COMPRESSED())
            default -> throw new IllegalArgumentException();
        };
        return pubKey.serialize(compressed);
    }

//    @Override
//    public P256K1Point.Uncompressed ecPointUncompress(P256K1Point.Compressed compressedPoint) {
//        return compressedPoint.uncompress();
//    }
    
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
    public SPResult<SPPubKey> ecPubKeyParse(byte[] inputData) {
        MemorySegment input = arena.allocateFrom(JAVA_BYTE, inputData);
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, input, input.byteSize());
        if (return_val != 1) {
            System.out.println("Failed parsing the public key\n");
        }
        return SPResult.checked(return_val, () -> new SPPubKeyImpl(toPoint(pubkey)));
    }

    private MemorySegment pubKeyParse(SPPubKey pubKeyData) {
        MemorySegment input = arena.allocateFrom(JAVA_BYTE, pubKeyData.getEncoded()); // 65 byte, uncompressed format
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, input, input.byteSize());
        if (return_val != 1) {
            throw new IllegalStateException("Unexpected Failure parsing uncompressed public key");
        }
        return pubkey;
    }

    @Override
    public SPResult<SPSignatureData> ecdsaSign(byte[] msg_hash_data, SPPrivKey seckey) {
        /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
         * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
         * Signing with a valid context, verified secret key
         * and the default nonce function should never fail. */
        MemorySegment msg_hash = arena.allocateFrom(JAVA_BYTE, msg_hash_data);
        MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);
        MemorySegment nullCallback =  secp256k1_h.NULL(); // Double-check this (normally you shouldn't use a NULL pointer for a null callback)
        MemorySegment nullPointer = secp256k1_h.NULL();
        MemorySegment privKeySeg = arena.allocateFrom(JAVA_BYTE, seckey.getEncoded());
        int return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, privKeySeg, nullCallback, nullPointer);
        privKeySeg.fill((byte) 0x00);
        return SPResult.checked(return_val, () -> SPSignatureData.of(sig.toArray(JAVA_BYTE)));
    }

    @Override
    public byte[] ecdsaSignatureSerializeCompact(SPSignatureData sig) {
        return sig.bytes();
    }

    @Override
    public SPResult<SPSignatureData> ecdsaSignatureParseCompact(byte[] serialized_signature) {
        MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ecdsa_signature_parse_compact(ctx, sig, arena.allocateFrom(JAVA_BYTE, serialized_signature));
        return SPResult.checked(return_val, () -> SPSignatureData.of(sig.toArray(JAVA_BYTE)));
    }

    @Override
    public SPResult<Boolean> ecdsaVerify(SPSignatureData sig, byte[] msg_hash_data, SPPubKey pubKey) {
        /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
         * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
         * Signing with a valid context, verified secret key
         * and the default nonce function should never fail. */
        MemorySegment msg_hash = arena.allocateFrom(JAVA_BYTE, msg_hash_data);
        int return_val = secp256k1_h.secp256k1_ecdsa_verify(ctx,
                arena.allocateFrom(JAVA_BYTE, sig.bytes()),
                msg_hash,
                pubKeyParse(pubKey));
        return SPResult.ok(return_val == 1);
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
    public byte[] schnorrSigSign32(byte[] messageHash, SPKeyPair keyPair) {
        MemorySegment sig = arena.allocate(64);
        MemorySegment msg_hash = arena.allocateFrom(JAVA_BYTE, messageHash);
        MemorySegment auxiliary_rand = fill_random(arena, 32);
        // TODO: Serialize standard P256K1KeyPair/P256K1KeyPairImpl here
        MemorySegment keyPairSeg = keyPairToSegment(keyPair);

        int return_val = secp256k1_schnorrsig_sign32(ctx, sig, msg_hash, keyPairSeg, auxiliary_rand);
        assert(return_val == 1);
        return sig.toArray(JAVA_BYTE);
    }

    private MemorySegment keyPairToSegment(SPKeyPair keyPair) {
        byte[] privBytes = keyPair.getEncoded();
        MemorySegment privSeg = arena.allocateFrom(JAVA_BYTE, privBytes);
        MemorySegment keyPairSeg = secp256k1_keypair.allocate(arena);
        secp256k1_h.secp256k1_keypair_create(ctx, keyPairSeg, privSeg);
        return keyPairSeg;
    }

    private SPKeyPair toKeyPair(MemorySegment keyPairSegment) {
        MemorySegment pubKeySegment = secp256k1_pubkey.allocate(Secp256k1Foreign.globalArena);
        int return_val = secp256k1_h.secp256k1_keypair_pub(ctx, pubKeySegment, keyPairSegment);
        assert(return_val == 1);
        SPPubKey pubKey = new SPPubKeyImpl(toPoint(pubKeySegment));
        MemorySegment privKeySegment = Secp256k1Foreign.globalArena.allocate(32);
        int return_val2 = secp256k1_h.secp256k1_keypair_sec(ctx, privKeySegment, keyPairSegment);
        assert(return_val2 == 1);
        SPPrivKey privKey = SPPrivKey.of(privKeySegment.toArray(JAVA_BYTE));
        return new SPKeyPairImpl(privKey, pubKey);
    }

    @Override
    public SPResult<Boolean> schnorrSigVerify(byte[] signature, byte[] msg_hash, SPXOnlyPubKey pubKey) {
        MemorySegment sigSegment = arena.allocateFrom(JAVA_BYTE, signature);
        MemorySegment msgSegment = arena.allocateFrom(JAVA_BYTE, msg_hash);
        MemorySegment pubKeySegment = arena.allocateFrom(JAVA_BYTE, pubKey.serialize()); // 32-byte
        MemorySegment pubKeySegmentOpaque = secp256k1_xonly_pubkey.allocate(arena); // 64-byte opaque
        int r = secp256k1_h.secp256k1_xonly_pubkey_parse(ctx, pubKeySegmentOpaque, pubKeySegment);
        if (r != 1) return SPResult.err(r);
        int return_val = secp256k1_h.secp256k1_schnorrsig_verify(ctx, sigSegment, msgSegment, msg_hash.length, pubKeySegmentOpaque);
        return SPResult.ok(return_val == 1);
    }

    @Override
    public SPResult<byte[]> ecdh(SPPubKey pubKey, SPPrivKey secKey) {
        MemorySegment pubKeySeg = pubKeyParse(pubKey);  // Get pubkey in 64-byte internal format
        MemorySegment secKeySeg = arena.allocateFrom(JAVA_BYTE, secKey.getEncoded());
        MemorySegment output = arena.allocate(32);
        int success = secp256k1_h.secp256k1_ecdh(ctx, output, pubKeySeg, secKeySeg, NULL(), NULL());
        return success == 1
                ? SPResult.ok(output.toArray(JAVA_BYTE))
                : SPResult.err(-1);
    }

    /**
     *
     * @param allocator allocator to create segment with
     * @param size size in bytes of random data
     * @return A newly-allocated memory segment full of random data
     */
    public static MemorySegment fill_random(SegmentAllocator allocator, int size) {
        // TODO: Verify using cryptographic random number generator properly
        var rnd = new SecureRandom();
        byte[] data = new byte[size];
        rnd.nextBytes(data);
        return allocator.allocateFrom(JAVA_BYTE, data);
    }
}
