package org.consensusj.secp256k1;

import org.consensusj.secp256k1.api.P256k1PrivKey;
import org.consensusj.secp256k1.api.P256k1PubKey;
import org.consensusj.secp256k1.bouncy.Bouncy256k1;
import org.consensusj.secp256k1.bouncy.BouncyPrivKey;
import org.consensusj.secp256k1.foreign.Secp256k1Foreign;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.Random;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.consensusj.secp256k1.secp256k1_h.SECP256K1_EC_COMPRESSED;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 */
public class CurveTest {

    @Test
    void smokeTest() {
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

            System.out.printf("Pubkey compressed: %s", HexFormat.of().formatHex(compressed_pubkey.toArray(JAVA_BYTE.withByteAlignment(1))));
        }
    }

    //@Test
    void pubKeyCalc() {
        try (var secp = new Secp256k1Foreign(); var bouncyp = new Bouncy256k1()) {
            /* Return a non-zero, in-range private key */
            //PrivKeyData privkey = secp.ecPrivKeyCreate();
            P256k1PrivKey privkey = new BouncyPrivKey(BigInteger.ONE);

            /* Public key creation using a valid context with a verified secret key should never fail */
            P256k1PubKey pubkey = secp.ecPubKeyCreate(privkey);
            P256k1PubKey pubkey2 = bouncyp.ecPubKeyCreate(privkey);
            P256k1PubKey g = bouncyp.g();

            assertEquals(g.getW(), pubkey.getW());
            assertEquals(g.getW(), pubkey2.getW());

            System.out.println(pubkey);
            System.out.println(pubkey2);
            assertEquals(pubkey.getW(), pubkey2.getW());
        }
    }


    public static MemorySegment fill_random(Arena arena, int size) {
        // TODO: Use cryptographic random number generator
        Random rnd = new Random();
        byte[] data = new byte[size];
        rnd.nextBytes(data);
        // WARNING: This is NOT RANDOMIZING YET
        MemoryLayout layout = MemoryLayout.sequenceLayout(size, JAVA_BYTE);
        MemorySegment seg = arena.allocateArray(layout, size);
        seg.set(JAVA_BYTE.withByteAlignment(1), 0, (byte) 1);   // Return non-zero to avoid infinite loop
        return seg;
    }
}
