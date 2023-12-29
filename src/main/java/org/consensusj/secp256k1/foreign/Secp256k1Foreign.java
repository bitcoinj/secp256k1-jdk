package org.consensusj.secp256k1.foreign;

import org.consensusj.secp256k1.api.Secp256k1;
import org.consensusj.secp256k1.api.CompressedPubKeyData;
import org.consensusj.secp256k1.api.CompressedSignatureData;
import org.consensusj.secp256k1.api.P256k1PrivKey;
import org.consensusj.secp256k1.api.P256k1PubKey;
import org.consensusj.secp256k1.api.SignatureData;
import org.consensusj.secp256k1.secp256k1_ecdsa_signature;
import org.consensusj.secp256k1.secp256k1_h;
import org.consensusj.secp256k1.secp256k1_pubkey;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.ECPoint;
import java.util.Optional;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.consensusj.secp256k1.secp256k1_h.SECP256K1_EC_UNCOMPRESSED;

/**
 *
 */
public class Secp256k1Foreign implements AutoCloseable, Secp256k1 {
    public final Arena arena;
    public final MemorySegment ctx;
    /* package */ static final Arena globalArena = Arena.ofAuto();
    /* package */ static final MemorySegment secp256k1StaticContext = secp256k1_h.secp256k1_context_static$get();
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
    public P256k1PrivKey ecPrivKeyCreate() {
        /* If the secret key is zero or out of range (bigger than secp256k1's
         * order), we try to sample a new key. Note that the probability of this
         * happening is negligible. */
        MemorySegment seckey;
        do {
            seckey = fill_random(arena, 32);
        } while (secp256k1_h.secp256k1_ec_seckey_verify(ctx, seckey) != 1);
        return new PrivKeyPojo(seckey);
    }

    @Override
    public P256k1PubKey ecPubKeyCreate(P256k1PrivKey privkey) {
        // Should we verify the key here for safety? (Probably)
        MemorySegment privkeySegment = arena.allocateArray(JAVA_BYTE, privkey.bytes());
        MemorySegment pubKey = ecPubKeyCreate(privkeySegment);
        // Return serialized pubkey
        return new PubKeyPojo(toPoint(pubKey));
    }

    /* package */ MemorySegment ecPubKeyCreate(MemorySegment privkeySegment) {
        /* Public key creation using a valid context with a verified private key should never fail */
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_create(ctx, pubkey, privkeySegment);
        assert(return_val == 1);
        return pubkey;
    }

    /* package */ ECPoint toPoint(MemorySegment pubKeySegment) {
        // Serialize uncompressed
        MemorySegment serialized_pubkey = pubKeySerializeSegment(pubKeySegment, SECP256K1_EC_UNCOMPRESSED());

        // Extract x and y, create an ECPoint and return it
        byte[] uncompressed_bytes = serialized_pubkey.toArray(JAVA_BYTE);
        return toPoint(uncompressed_bytes);
    }

    /* package */ ECPoint toPoint(byte[] uncompressed_bytes) {
        // Extract x and y, create an ECPoint and return it
        byte[] xbytes = new byte[32];
        byte[] ybytes = new byte[32];
        System.arraycopy(uncompressed_bytes,  1, xbytes, 0, 32);
        System.arraycopy(uncompressed_bytes, 33, ybytes, 0, 32);
        // TODO: How to handle point at infinity?
        BigInteger x = P256k1PrivKey.toInteger(xbytes);
        BigInteger y = P256k1PrivKey.toInteger(ybytes);
        return new ECPoint(x, y);
    }

    @Override
    public Optional<Object> ecKeyPairCreate() {
        return Optional.empty();  // TBD
    }

    /**
     * Since {@code PubKeyData} is serializable without using the native lib, this method
     * serialized without a native call.
     * @param pubKey
     * @param flags
     * @return
     */
    @Override
    public CompressedPubKeyData ecPubKeySerialize(P256k1PubKey pubKey, int flags) {
        boolean compressed = switch(flags) {
            case 2 -> false;           // SECP256K1_EC_UNCOMPRESSED())
            case 258 -> true;         // SECP256K1_EC_COMPRESSED())
            default -> throw new IllegalArgumentException();
        };
        return new CompressedPubKeyPojo(pubKey.getSerialized(compressed));
    }

    /* package */ MemorySegment pubKeySerializeSegment(MemorySegment pubKeySegment, int flags) {
        int byteSize = switch(flags) {
            case 2 -> 65;           // SECP256K1_EC_UNCOMPRESSED())
            case 258 -> 33;         // SECP256K1_EC_COMPRESSED())
            default -> throw new IllegalArgumentException();
        };
        MemorySegment serialized_pubkey = arena.allocate(byteSize);
        MemorySegment lenSegment = arena.allocate(secp256k1_h.size_t);
        lenSegment.set(secp256k1_h.size_t, 0, serialized_pubkey.byteSize());
        int return_val = secp256k1_h.secp256k1_ec_pubkey_serialize(ctx,
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
    public Optional<P256k1PubKey> ecPubKeyParse(CompressedPubKeyData inputData) {
        MemorySegment input = arena.allocateArray(JAVA_BYTE, inputData.bytes());
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, input, input.byteSize());
        if (return_val != 1) {
            System.out.println("Failed parsing the public key\n");
        }
        return (return_val == 1)
                ? Optional.of(new PubKeyPojo(toPoint(pubkey)))
                : Optional.empty();
    }

    private MemorySegment pubKeyParse(P256k1PubKey pubKeyData) {
        MemorySegment input = arena.allocateArray(JAVA_BYTE, pubKeyData.getEncoded()); // 65 byte, uncompressed format
        MemorySegment pubkey = secp256k1_pubkey.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ec_pubkey_parse(ctx, pubkey, input, input.byteSize());
        if (return_val != 1) {
            throw new IllegalStateException("Unexpected Failure parsing uncompressed public key\n");
        }
        return pubkey;
    }

    @Override
    public Optional<SignatureData> ecdsaSign(byte[] msg_hash_data, P256k1PrivKey seckey) {
        /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
         * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
         * Signing with a valid context, verified secret key
         * and the default nonce function should never fail. */
        MemorySegment msg_hash = arena.allocateArray(JAVA_BYTE, msg_hash_data);
        MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);
        MemorySegment nullCallback =  secp256k1_h.NULL(); // Double-check this (normally you shouldn't use a NULL pointer for a null callback)
        MemorySegment nullPointer = secp256k1_h.NULL();
        int return_val = secp256k1_h.secp256k1_ecdsa_sign(ctx, sig, msg_hash, arena.allocateArray(JAVA_BYTE, seckey.bytes()), nullCallback, nullPointer);
        assert(return_val == 1);
        return Optional.of(new SignaturePojo(sig));
    }

    @Override
    public Optional<CompressedSignatureData> ecdsaSignatureSerializeCompact(SignatureData sig) {
        MemorySegment serialized_signature = secp256k1_ecdsa_signature.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, arena.allocateArray(JAVA_BYTE, sig.bytes()));
        assert(return_val == 1);
        return Optional.of(new CompressedSignaturePojo(serialized_signature));
    }

    @Override
    public Optional<SignatureData> ecdsaSignatureParseCompact(CompressedSignatureData serialized_signature) {
        MemorySegment sig = secp256k1_ecdsa_signature.allocate(arena);
        int return_val = secp256k1_h.secp256k1_ecdsa_signature_parse_compact(ctx, sig, arena.allocateArray(JAVA_BYTE, serialized_signature.bytes()));
        assert(return_val == 1);
        return Optional.of(new SignaturePojo(sig));
    }

    @Override
    public Optional<Boolean> ecdsaVerify(SignatureData sig, byte[] msg_hash_data, P256k1PubKey pubKey) {
        /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
         * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
         * Signing with a valid context, verified secret key
         * and the default nonce function should never fail. */
        MemorySegment msg_hash = arena.allocateArray(JAVA_BYTE, msg_hash_data);
        int return_val = secp256k1_h.secp256k1_ecdsa_verify(ctx,
                arena.allocateArray(JAVA_BYTE, sig.bytes()),
                msg_hash,
                pubKeyParse(pubKey));
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
