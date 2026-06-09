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
package org.bitcoinj.secp.integration;

import org.bitcoinj.secp.SchnorrSignature;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Function;

public class BIP327TestVectorTests implements SecpTestSupport {

    static final Secp256k1Foreign secp = new Secp256k1Foreign();

    static ObjectMapper mapper = JsonMapper.builder()
            .addModule(new SimpleModule()
                    .addDeserializer(byte[].class,     hexDeser(b -> b))
                    .addDeserializer(SecpPrivKey.class, hexDeser(SecpPrivKey::of))
                    .addDeserializer(SecpPubKey.class,  hexDeser(b -> secp.ecPubKeyParse(b).get()))
                    .addDeserializer(Secp256k1Foreign.MusigPubNonce.class, hexDeser(secp::parsePubNonce))
                    .addDeserializer(Secp256k1Foreign.MusigAggNonce.class, hexDeser(secp::parseAggNonce))
            ).build();

    @Test
    void sortKeysTest() {
        KeySortTestVector vec = parseJson("/key_sort_vectors.json", KeySortTestVector.class);

        List<SecpPubKey> result = secp.ecPubKeySort(vec.pubkeys);

        Assertions.assertEquals(vec.sorted_pubkeys().size(), result.size());

        for (int i = 0; i < vec.sorted_pubkeys().size(); i++) {
            Assertions.assertArrayEquals(vec.sorted_pubkeys().get(i).serialize(), result.get(i).serialize());
        }

    }

    @ParameterizedTest
    @MethodSource("keyAggTestVectors")
    void keyAgg(KeyAggTestVector vec) {
        try (var secp = new Secp256k1Foreign()) {
            Secp256k1Foreign.KeyAggCache result = secp.musigPubKeyAgg(vec.pubkeys());

            Assertions.assertArrayEquals(vec.expected(), result.aggKey().xOnly().serialize());
        }
    }

    @ParameterizedTest
    @MethodSource("nonceGenVectors")
    void pubNonceGen(NonceGenTestVector vec) {
        MemorySegment keyAggCacheSeg = secp.arrayToSeg(createCache(vec.aggpk()));
        SecpPubKey key = secp.ecPubKeyFromXOnly(secp.xOnlyPubKeyParse(vec.aggpk).get());
        Secp256k1Foreign.KeyAggCache keyAggCache = new Secp256k1Foreign.KeyAggCache(key, keyAggCacheSeg);

        Secp256k1Foreign.MusigNonce nonce = secp.musigNonceGen(vec.rand_(), vec.sk(), vec.pk(), vec.msg(), keyAggCache, vec.extra_in());

        Assertions.assertArrayEquals(vec.expected_pubnonce(), nonce.pubNonce().serialized());
    }

    @ParameterizedTest
    @MethodSource("nonceAggTestVectors")
    void nonceAgg(NonceAggTestVector vec) {
        Secp256k1Foreign.MusigAggNonce result = secp.musigNonceAgg(vec.pnonces());

        Assertions.assertArrayEquals(vec.expected(), result.serialized());
    }

    @ParameterizedTest
    @MethodSource("partialSignTestVectors")
    void partialSign(PartialSignTestVector vec) {

        Secp256k1Foreign.KeyAggCache cache = secp.musigPubKeyAgg(vec.pubkeys());
        MemorySegment session = secp.musigNonceProcess(vec.aggnonce(), vec.msg(), cache);

        Secp256k1Foreign.PartialSig sig = secp.musigPartialSign(vec.secnonce(), secp.ecKeyPairCreate(vec.sk()), cache, session);

        Assertions.assertArrayEquals(vec.expected(), sig.serialized());
    }

    @ParameterizedTest
    @MethodSource("partialSigVerifyTestVectors")
    void partialSigVerify(PartialSigVerifyTestVector vec) {

        Secp256k1Foreign.KeyAggCache cache = secp.musigPubKeyAgg(vec.pubkeys());
        MemorySegment session = secp.musigNonceProcess(vec.aggnonce(), vec.msg, cache);

        boolean result = secp.musigPartialSigVerify(vec.psig(), vec.signer_pnonce(), vec.signer_pubkey(), cache, session);

        Assertions.assertTrue(result);
    }

    @ParameterizedTest
    @MethodSource("sigAggTestVectors")
    void sigAgg(SigAggTestVector vec) {
        Secp256k1Foreign.KeyAggCache cache = secp.musigPubKeyAgg(vec.pubkeys());
        MemorySegment session = secp.musigNonceProcess(vec.aggnonce(), vec.msg(), cache);

        SchnorrSignature sig = secp.musigPartialSigAgg(session, vec.psigs());

        Assertions.assertArrayEquals(vec.expected(), sig.bytes());
    }

     static List<NonceGenTestVector> nonceGenVectors() {
        return parseJson("/nonce_gen_vectors.json", NonceGenTestData.class)
                .test_cases()
                .stream()
                .filter(test -> test.msg() != null && test.msg().length == 32) // msg must be 32 bytes
                .toList();
    }

     static List<KeyAggTestVector> keyAggTestVectors() {
        KeyAggTestData data = parseJson("/key_agg_vectors.json", KeyAggTestData.class);
        List<KeyAggTestVector> vecs  = new ArrayList<>();
        for (var c : data.valid_test_cases()) {
            List<SecpPubKey> pubkeys = sublistFromIndexListAndParse(data.pubkeys(), c.key_indices(), b -> secp.ecPubKeyParse(b).get());
            vecs.add(new KeyAggTestVector(pubkeys, c.expected()));
        }
        return vecs;
    }

     static List<NonceAggTestVector> nonceAggTestVectors() {
        NonceAggTestData data = parseJson(("/nonce_agg_vectors.json"), NonceAggTestData.class);
        List<NonceAggTestVector> vecs  = new ArrayList<>();
        for (var c : data.valid_test_cases()) {
            List<Secp256k1Foreign.MusigPubNonce> pnonces = sublistFromIndexListAndParse(data.pnonces(), c.pnonce_indices(), secp::parsePubNonce);
            vecs.add(new NonceAggTestVector(pnonces, c.expected()));
        }
        return vecs;
    }

     static List<PartialSignTestVector> partialSignTestVectors() {
        PartialSignVerifyTestData data = parseJson("/sign_verify_vectors.json", PartialSignVerifyTestData.class);
        List<PartialSignTestVector> vecs  = new ArrayList<>();
        data.secnonces.set(0, secNonceFromBip327(data.secnonces.getFirst()));
        for (var c : data.valid_test_cases()) {
            byte[] msg = data.msgs().get(c.msg_index());
            if (msg != null && msg.length == 32) {
                List<SecpPubKey> pubkeys = sublistFromIndexListAndParse(data.pubkeys(), c.key_indices(), b -> secp.ecPubKeyParse(b).get());
                List<Secp256k1Foreign.MusigPubNonce> pnonces = sublistFromIndexListAndParse(data.pnonces(), c.nonce_indices, secp::parsePubNonce);
                MemorySegment secnonce = secp.arrayToSeg(data.secnonces().getFirst());
                vecs.add(new PartialSignTestVector(data.sk(), data.aggnonces().get(c.aggnonce_index()), pubkeys, secnonce, pnonces, data.msgs().get(c.msg_index()), c.expected()));
            }
        }
        return vecs;
    }

     static List<PartialSigVerifyTestVector> partialSigVerifyTestVectors() {
        PartialSignVerifyTestData data = parseJson("/sign_verify_vectors.json", PartialSignVerifyTestData.class);
        List<PartialSigVerifyTestVector> vecs  = new ArrayList<>();
        for (var c : data.valid_test_cases()) {
            byte[] msg = data.msgs().get(c.msg_index());
            if (msg != null && msg.length == 32) {
                List<SecpPubKey> pubkeys = sublistFromIndexListAndParse(data.pubkeys(), c.key_indices(), b -> secp.ecPubKeyParse(b).get());
                List<Secp256k1Foreign.MusigPubNonce> pnonces = sublistFromIndexListAndParse(data.pnonces(), c.nonce_indices, secp::parsePubNonce);
                vecs.add(new PartialSigVerifyTestVector(pubkeys, pnonces, pubkeys.get(c.signer_index()), pnonces.get(c.signer_index()), data.aggnonces.get(c.aggnonce_index()), msg, secp.parsePartialSig(c.expected())));
            }
        }
        return vecs;
    }

    static List<SigAggTestVector> sigAggTestVectors() {
        SigAggTestData data = parseJson("/sig_agg_vectors.json",  SigAggTestData.class);
        List<SigAggTestVector> vecs  = new ArrayList<>();
        for (var c : data.valid_test_cases()) {
            if (c.tweak_indices().isEmpty()) { // not supporting tweaks
                List<SecpPubKey> pubkeys = sublistFromIndexList(data.pubkeys(), c.key_indices());
                List<Secp256k1Foreign.MusigPubNonce> pnonces = sublistFromIndexList(data.pnonces(), c.nonce_indices());
                List<Secp256k1Foreign.PartialSig> psigs = sublistFromIndexListAndParse(data.psigs(), c.psig_indices(), secp::parsePartialSig);

                vecs.add(new SigAggTestVector(pubkeys, pnonces, psigs, c.aggnonce(), data.msg(), c.expected()));
            }
        }
        return vecs;
    }

    // Record for keySort test
    record KeySortTestVector(List<SecpPubKey> pubkeys, List<SecpPubKey> sorted_pubkeys) {}

    // Records for keyAgg test
    record KeyAggTestVector(List<SecpPubKey> pubkeys, byte[] expected) {}
    record KeyAggCase(List<Integer> key_indices, byte[] expected) {}
    record KeyAggTestData(List<byte[]> pubkeys, List<KeyAggCase> valid_test_cases) {}

    // Records for pubNonceGen test
    record NonceGenTestVector(byte[] rand_, SecpPrivKey sk, SecpPubKey pk, byte[] aggpk, byte[] msg, byte[] extra_in, byte[] expected_secnonce, byte[] expected_pubnonce) {}
    record NonceGenTestData(List<NonceGenTestVector> test_cases) {}

    // Records for nonceAgg test
    record NonceAggTestVector(List<Secp256k1Foreign.MusigPubNonce> pnonces, byte[] expected) {}
    record NonceAggCase(List<Integer> pnonce_indices, byte[] expected) {}
    record NonceAggTestData(List<byte[]> pnonces, List<NonceAggCase> valid_test_cases) {}

    // Record for partialSign test
    record PartialSignTestVector(SecpPrivKey sk, Secp256k1Foreign.MusigAggNonce aggnonce, List<SecpPubKey> pubkeys, MemorySegment secnonce, List<Secp256k1Foreign.MusigPubNonce> pnonces, byte[] msg, byte[] expected) {}

    // Record for partialSigVerify test
    record PartialSigVerifyTestVector(List<SecpPubKey> pubkeys, List<Secp256k1Foreign.MusigPubNonce> pnonces, SecpPubKey signer_pubkey, Secp256k1Foreign.MusigPubNonce signer_pnonce, Secp256k1Foreign.MusigAggNonce aggnonce, byte[] msg, Secp256k1Foreign.PartialSig psig) {}

    // Records for both partialSign and partialSigVerify tests (they pull from the same json)
    record PartialSignVerifyCase(List<Integer> key_indices, List<Integer> nonce_indices, int aggnonce_index, int msg_index, int signer_index, byte[] expected) {}
    record PartialSignVerifyTestData(SecpPrivKey sk, List<byte[]> pubkeys, List<byte[]> secnonces, List<byte[]> pnonces, List<Secp256k1Foreign.MusigAggNonce> aggnonces, List<byte[]> msgs, List<PartialSignVerifyCase> valid_test_cases) {}

    // Records for sigAgg test
    record SigAggTestVector(List<SecpPubKey> pubkeys, List<Secp256k1Foreign.MusigPubNonce> pnonces, List<Secp256k1Foreign.PartialSig> psigs, Secp256k1Foreign.MusigAggNonce aggnonce, byte[] msg, byte[] expected) {}
    record SigAggTestCase(Secp256k1Foreign.MusigAggNonce aggnonce, List<Integer> nonce_indices, List<Integer> key_indices, List<Integer> psig_indices, List<Integer> tweak_indices, byte[] expected) {}
    record SigAggTestData(List<SecpPubKey> pubkeys, List<Secp256k1Foreign.MusigPubNonce> pnonces, List<byte[]> psigs, byte[] msg, List<SigAggTestCase> valid_test_cases) {}

    static byte[] secNonceFromBip327(byte[] bip327) {
        try (var secp = new Secp256k1Foreign()) {
            // 33-byte compressed pubkey -> 64-byte internal X||Y (same form stored in the secnonce)
            byte[] magic = {(byte) 0x22, (byte) 0x0e, (byte) 0xdc, (byte) 0xf1};

            byte[] pkArray = Arrays.copyOfRange(bip327, 64, 97);
            SecpPubKey key = secp.ecPubKeyParse(pkArray).get();
            byte[] keyX = key.x().serialize();
            byte[] keyY = key.y().serialize();

            byte[] keyUncompressed = new byte[64];
            for (int i = 0; i < 32; i++) {
                keyUncompressed[i] = keyX[31 - i];
                keyUncompressed[32 + i] = keyY[31 - i];
            }
            byte[] secNonceArray = new byte[132];
            System.arraycopy(magic, 0, secNonceArray, 0, 4);
            System.arraycopy(bip327, 0, secNonceArray, 4, 64);
            System.arraycopy(keyUncompressed, 0, secNonceArray, 68, 64);

            return secNonceArray;
        }
    }

    byte[] createCache(byte[] aggpk) {
        try (var secp  = new Secp256k1Foreign()) {
            // aggpk = 32-byte x-only from the vector
            if (aggpk.length != 32) throw new IllegalArgumentException("aggpk must be 32 bytes");

            SecpXOnlyPubKey keyXOnly = secp.xOnlyPubKeyParse(aggpk).get();
            SecpPubKey key = secp.ecPubKeyFromXOnly(keyXOnly);
            byte[] keyX = key.x().serialize();
            byte[] keyY = key.y().serialize();

            byte[] keyUncompressed = new byte[64];
            for (int i = 0; i < 32; i++) {
                keyUncompressed[i] = keyX[31 - i];
                keyUncompressed[32 + i] = keyY[31 - i];
            }

            byte[] magic = {(byte) 0xf4, (byte) 0xad, (byte) 0xbb, (byte) 0xdf};

            byte[] cache = new byte[68];

            System.arraycopy(magic, 0, cache, 0, 4);
            System.arraycopy(keyUncompressed, 0, cache, 4, 64);

            return cache;
        }
    }

    static <T> T parseJson(String path, Class<T> type) {
        try (InputStream in = BIP327TestVectorTests.class.getResourceAsStream(path)) {
            return mapper.readValue(in, type);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static <T> ValueDeserializer<T> hexDeser(Function<byte[], T> conv) {
        return new ValueDeserializer<>() {
            @Override public T deserialize(JsonParser p, DeserializationContext ctxt) {
                return conv.apply(HexFormat.of().parseHex(p.getString()));
            }
        };
    }

    static <T> List<T> sublistFromIndexList(List<T> list, List<Integer> indices) {
        List<T> sublist = new ArrayList<>();
        for (int i : indices) {
            sublist.add(list.get(i));
        }
        return sublist;
    }

    static <T, E> List<T> sublistFromIndexListAndParse(List<E> list, List<Integer> indices, Function<E, T> parser) {
        List<T> sublist = new ArrayList<>();
        for (int i : indices) {
            sublist.add(parser.apply(list.get(i)));
        }
        return sublist;
    }
}
