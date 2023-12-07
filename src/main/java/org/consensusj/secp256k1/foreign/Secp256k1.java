package org.consensusj.secp256k1.foreign;

import org.consensusj.secp256k1.secp256k1_ecdsa_signature;
import org.consensusj.secp256k1.secp256k1_h;
import org.consensusj.secp256k1.secp256k1_pubkey;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.security.SecureRandom;
import java.util.Optional;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.consensusj.secp256k1.secp256k1_h.SECP256K1_EC_COMPRESSED;

/**
 *
 */
public class Secp256k1 implements AutoCloseable {
    public final Arena arena;
    public final MemorySegment ctx;
    
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
        int is_sig_valid = secp256k1_h.secp256k1_ecdsa_verify(secp256k1_h.secp256k1_context_static$get(), sig, msg_hash, pubkey);
        return is_sig_valid == 1;
    }

    public Secp256k1() {
        this(secp256k1_h.SECP256K1_CONTEXT_NONE(), true); // Randomize automatically by default
    }

    public Secp256k1(int flags) {
        this(flags, true); // Randomize automatically by default
    }
    
    public Secp256k1(int flags, boolean randomize) {
        arena = Arena.ofConfined();
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

    public Optional<MemorySegment> ecPrivKeyCreate() {
        /* If the secret key is zero or out of range (bigger than secp256k1's
         * order), we try to sample a new key. Note that the probability of this
         * happening is negligible. */
        MemorySegment seckey;
        do {
            seckey = fill_random(arena, 32);
        } while (secp256k1_h.secp256k1_ec_seckey_verify(ctx, seckey) != 1);
        return Optional.of(seckey);
    }

    public Optional<MemorySegment> ecPubKeyCreate(MemorySegment seckey) {
        /* Public key creation using a valid context with a verified secret key should never fail */
        // Should we verify the key here for safety? (Probably)
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_create(ctx, pubkey, seckey);
        assert(return_val == 1);
        return Optional.of(pubkey);
    }

    public Optional<Object> ecKeyPairCreate() {
        return Optional.empty();
    }

    public Optional<MemorySegment> ecPubKeySerialize(MemorySegment pubKey, Object flags) {
        MemorySegment compressed_pubkey = arena.allocate(33);
        MemorySegment lenSegment = arena.allocate(secp256k1_h.size_t);
        lenSegment.set(secp256k1_h.size_t, 0, compressed_pubkey.byteSize());
        int return_val = secp256k1_h.secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, lenSegment, pubKey, SECP256K1_EC_COMPRESSED());
        assert(return_val == 1);
        /* Should be the same size as the size of the output, because we passed a 33 byte array. */
        assert(lenSegment.get(secp256k1_h.size_t, 0) == compressed_pubkey.byteSize());
        return Optional.of(compressed_pubkey);
    }

    public Optional<MemorySegment> ecPubKeyParse(MemorySegment input) {
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, input, input.byteSize());
        if (return_val != 1) {
            System.out.println("Failed parsing the public key\n");
        }
        return (return_val == 1)
                ? Optional.of(pubkey)
                : Optional.empty();
    }

    public Optional<MemorySegment> ecdsaSign(byte[] msg_hash_data, MemorySegment seckey) {
        /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
         * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
         * Signing with a valid context, verified secret key
         * and the default nonce function should never fail. */
        MemorySegment msg_hash = arena.allocateArray(JAVA_BYTE, msg_hash_data);
        MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);
        MemorySegment nullCallback =  secp256k1_h.NULL(); // Double-check this (normally you shouldn't use a NULL pointer for a null callback)
        MemorySegment nullPointer = secp256k1_h.NULL();
        int return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, seckey, nullCallback, nullPointer);
        assert(return_val == 1);
        return Optional.of(sig);
    }

    public Optional<MemorySegment> ecdsaSignatureSerializeCompact(MemorySegment sig) {
        MemorySegment serialized_signature = secp256k1_ecdsa_signature.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, sig);
        assert(return_val == 1);
        return Optional.of(serialized_signature);
    }

    public Optional<MemorySegment> ecdsaSignatureParseCompact(MemorySegment serialized_signature) {
        MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ecdsa_signature_parse_compact(ctx, sig, serialized_signature);
        assert(return_val == 1);
        return Optional.of(sig);
    }

    public Optional<Boolean> ecdsaVerify(MemorySegment sig, byte[] msg_hash_data, MemorySegment privKey) {
        /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
         * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
         * Signing with a valid context, verified secret key
         * and the default nonce function should never fail. */
        MemorySegment msg_hash = arena.allocateArray(JAVA_BYTE, msg_hash_data);
        int return_val = secp256k1_h.secp256k1_ecdsa_verify(ctx, sig, msg_hash, privKey);
        return Optional.of(return_val == 1);
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
        return allocator.allocateArray(JAVA_BYTE, data);
    }
}
