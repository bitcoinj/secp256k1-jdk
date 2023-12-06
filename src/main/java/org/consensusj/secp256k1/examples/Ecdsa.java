package org.consensusj.secp256k1.examples;

import org.consensusj.secp256k1.secp256k1_ecdsa_signature;
import org.consensusj.secp256k1.secp256k1_h;
import org.consensusj.secp256k1.secp256k1_pubkey;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.security.SecureRandom;
import java.util.HexFormat;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.consensusj.secp256k1.secp256k1_h.SECP256K1_EC_COMPRESSED;

/**
 * Port of secp256k1 sample {@code ecdsa.c} to Java
 */
public class Ecdsa {
    private static final HexFormat formatter = HexFormat.of();

    public static void main(String[] args) {
        final byte[] msg_hash_data = formatter.parseHex("315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC94C75894EDD3");

        try (Arena arena = Arena.ofConfined()) {
            /* Before we can call actual API functions, we need to create a "context". */
            MemorySegment ctx = secp256k1_h.secp256k1_context_create(secp256k1_h.SECP256K1_CONTEXT_NONE());

            /* Randomizing the context is recommended to protect against side-channel
             * leakage See `secp256k1_context_randomize` in secp256k1.h for more
             * information about it. This should never fail. */
            MemorySegment randomize = fill_random(arena, 32);
            //random.set
            int return_val = secp256k1_h.secp256k1_context_randomize(ctx, randomize);
            assert(return_val == 1);

            /* Key Generation */

            /* If the secret key is zero or out of range (bigger than secp256k1's
             * order), we try to sample a new key. Note that the probability of this
             * happening is negligible. */
            MemorySegment seckey;
            do {
                seckey = fill_random(arena, 32);
            } while (secp256k1_h.secp256k1_ec_seckey_verify(ctx, seckey) != 1);

            /* Public key creation using a valid context with a verified secret key should never fail */
            MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
            return_val = secp256k1_h.secp256k1_ec_pubkey_create(ctx, pubkey, seckey);
            assert(return_val == 1);

            /* Serialize the pubkey in a compressed form(33 bytes). Should always return 1. */
            MemorySegment compressed_pubkey = arena.allocate(33);
            MemorySegment lenSegment = arena.allocate(secp256k1_h.size_t);
            lenSegment.set(secp256k1_h.size_t, 0, compressed_pubkey.byteSize());
            return_val = secp256k1_h.secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, lenSegment, pubkey, SECP256K1_EC_COMPRESSED());
            assert(return_val == 1);
            /* Should be the same size as the size of the output, because we passed a 33 byte array. */
            assert(lenSegment.get(secp256k1_h.size_t, 0) == compressed_pubkey.byteSize());

            /* Signing */

            /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
             * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
             * Signing with a valid context, verified secret key
             * and the default nonce function should never fail. */
            MemorySegment msg_hash = arena.allocateArray(JAVA_BYTE, msg_hash_data);
            MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);
            MemorySegment nullCallback =  secp256k1_h.NULL(); // Double-check this (normally you shouldn't use a NULL pointer for a null callback)
            MemorySegment nullPointer = secp256k1_h.NULL();
            return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, seckey, nullCallback, nullPointer);
            assert(return_val == 1);

            /* Serialize the signature in a compact form. Should always return 1
             * according to the documentation in secp256k1.h. */
            MemorySegment serialized_signature = secp256k1_ecdsa_signature.allocate(arena);
            return_val = secp256k1_h.secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, sig);
            assert(return_val == 1);

            /* Verification */

            /* Deserialize the signature. This will return 0 if the signature can't be parsed correctly. */
            if (secp256k1_h.secp256k1_ecdsa_signature_parse_compact(ctx, sig, serialized_signature) != 1) {
                System.out.println("Failed parsing the signature\n");
                System.exit(1);
            }

            /* Deserialize the public key. This will return 0 if the public key can't be parsed correctly. */
            if (secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, compressed_pubkey, compressed_pubkey.byteSize()) != 1) {
                System.out.println("Failed parsing the public key\n");
                System.exit(1);
            }

            /* Verify a signature. This will return 1 if it's valid and 0 if it's not. */
            int is_signature_valid = secp256k1_h.secp256k1_ecdsa_verify(ctx, sig, msg_hash, pubkey);

            System.out.printf("Is the signature valid? %s\n", is_signature_valid == 1 ? "true" : "false");
            System.out.printf("Secret Key: %s\n", formatter.formatHex(seckey.toArray(JAVA_BYTE)));
            System.out.printf("Public Key: %s\n", formatter.formatHex(compressed_pubkey.toArray(JAVA_BYTE)));
            System.out.printf("Signature: %s\n", formatter.formatHex(serialized_signature.toArray(JAVA_BYTE)));
        }
    }

    /**
     * 
     * @param allocator allocator to create segment with
     * @param size size in bytes of random data
     * @return A newly-allocated memory segment full of random data
     */
    public static MemorySegment fill_random(SegmentAllocator allocator, int size) {
        // TODO: Verify using cryptographic random number generator
        var rnd = new SecureRandom();
        byte[] data = new byte[size];
        rnd.nextBytes(data);
        return allocator.allocateArray(JAVA_BYTE, data);
    }
}