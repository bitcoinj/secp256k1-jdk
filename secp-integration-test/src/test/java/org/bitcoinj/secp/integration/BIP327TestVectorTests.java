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
import org.bitcoinj.secp.SecpKeyPair;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.bitcoinj.secp.internal.SecpKeyPairImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Function;

public class BIP327TestVectorTests implements SecpTestSupport {

    static final Secp256k1Foreign secp = new Secp256k1Foreign();

    static final ObjectMapper mapper = JsonMapper.builder().build();

    @Test
    void sortKeysTest() {
        JsonNode root = readTree("/key_sort_vectors.json");
        List<SecpPubKey> pubkeys = mapHex(root.get("pubkeys"), b -> secp.ecPubKeyParse(b).get());
        List<SecpPubKey> expected = mapHex(root.get("sorted_pubkeys"), b -> secp.ecPubKeyParse(b).get());

        List<SecpPubKey> result = secp.ecPubKeySort(pubkeys);

        Assertions.assertEquals(expected.size(), result.size());
        for (int i = 0; i < expected.size(); i++) {
            Assertions.assertArrayEquals(expected.get(i).serialize(), result.get(i).serialize());
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

    @ParameterizedTest
    @MethodSource("tweakTestVectors")
    void tweak(TweakTestVector vec) {
        Secp256k1Foreign.KeyAggCache cache = secp.musigPubKeyAgg(vec.pubkeys);
        for (int i = 0; i < vec.tweaks.size(); i++) {
            cache = vec.is_xonly.get(i) ? secp.musigPubkeyXonlyTweakAdd(cache, vec.tweaks.get(i)) :
                    secp.musigPubkeyEcTweakAdd(cache, vec.tweaks.get(i));
        }

        MemorySegment session = secp.musigNonceProcess(vec.aggnonce, vec.msg, cache);
        Secp256k1Foreign.PartialSig psig = secp.musigPartialSign(vec.secnonce, vec.sk, cache, session);

        Assertions.assertArrayEquals(vec.expected, psig.serialized());
    }

    static List<KeyAggTestVector> keyAggTestVectors() {
        JsonNode root = readTree("/key_agg_vectors.json");
        JsonNode pubkeys = root.get("pubkeys");
        return root.get("valid_test_cases").valueStream()
                .map(c -> new KeyAggTestVector(
                        pick(pubkeys, c.get("key_indices"), b -> secp.ecPubKeyParse(b).get()),
                        hex(c.get("expected"))))
                .toList();
    }

    static List<NonceGenTestVector> nonceGenVectors() {
        return readTree("/nonce_gen_vectors.json").get("test_cases").valueStream()
                .filter(c -> !c.get("msg").isNull() && hex(c.get("msg")).length == 32) // msg must be 32 bytes
                .map(c -> new NonceGenTestVector(
                        hex(c.get("rand_")),
                        SecpPrivKey.of(hex(c.get("sk"))),
                        secp.ecPubKeyParse(hex(c.get("pk"))).get(),
                        hex(c.get("aggpk")),
                        hex(c.get("msg")),
                        hex(c.get("extra_in")),
                        hex(c.get("expected_pubnonce"))))
                .toList();
    }

    static List<NonceAggTestVector> nonceAggTestVectors() {
        JsonNode root = readTree("/nonce_agg_vectors.json");
        JsonNode pnonces = root.get("pnonces");
        return root.get("valid_test_cases").valueStream()
                .map(c -> new NonceAggTestVector(
                        pick(pnonces, c.get("pnonce_indices"), secp::parsePubNonce),
                        hex(c.get("expected"))))
                .toList();
    }

    static List<PartialSignTestVector> partialSignTestVectors() {
        JsonNode root = readTree("/sign_verify_vectors.json");
        SecpPrivKey sk = SecpPrivKey.of(hex(root.get("sk")));
        JsonNode pubkeys = root.get("pubkeys");
        JsonNode pnonces = root.get("pnonces");
        JsonNode aggnonces = root.get("aggnonces");
        JsonNode msgs = root.get("msgs");
        // secnonces[0] is given in BIP327 form (33-byte pubkey suffix); convert once to the internal layout.
        byte[] secnonceBytes = secNonceFromBip327(hex(root.get("secnonces").get(0)));

        return root.get("valid_test_cases").valueStream()
                .filter(c -> hex(msgs.get(c.get("msg_index").asInt())).length == 32)
                .map(c -> new PartialSignTestVector(
                        sk,
                        secp.parseAggNonce(hex(aggnonces.get(c.get("aggnonce_index").asInt()))),
                        pick(pubkeys, c.get("key_indices"), b -> secp.ecPubKeyParse(b).get()),
                        secp.arrayToSeg(secnonceBytes), // fresh segment per case: libsecp zeroes the secnonce after signing
                        pick(pnonces, c.get("nonce_indices"), secp::parsePubNonce),
                        hex(msgs.get(c.get("msg_index").asInt())),
                        hex(c.get("expected"))))
                .toList();
    }

    static List<PartialSigVerifyTestVector> partialSigVerifyTestVectors() {
        JsonNode root = readTree("/sign_verify_vectors.json");
        JsonNode pubkeys = root.get("pubkeys");
        JsonNode pnonces = root.get("pnonces");
        JsonNode aggnonces = root.get("aggnonces");
        JsonNode msgs = root.get("msgs");

        return root.get("valid_test_cases").valueStream()
                .filter(c -> hex(msgs.get(c.get("msg_index").asInt())).length == 32)
                .map(c -> {
                    List<SecpPubKey> keys = pick(pubkeys, c.get("key_indices"), b -> secp.ecPubKeyParse(b).get());
                    List<Secp256k1Foreign.MusigPubNonce> pns = pick(pnonces, c.get("nonce_indices"), secp::parsePubNonce);
                    int signer = c.get("signer_index").asInt();
                    return new PartialSigVerifyTestVector(keys, pns, keys.get(signer), pns.get(signer),
                            secp.parseAggNonce(hex(aggnonces.get(c.get("aggnonce_index").asInt()))),
                            hex(msgs.get(c.get("msg_index").asInt())),
                            secp.parsePartialSig(hex(c.get("expected"))));
                })
                .toList();
    }

    static List<SigAggTestVector> sigAggTestVectors() {
        JsonNode root = readTree("/sig_agg_vectors.json");
        JsonNode pubkeys = root.get("pubkeys");
        JsonNode pnonces = root.get("pnonces");
        JsonNode psigs = root.get("psigs");
        byte[] msg = hex(root.get("msg"));

        return root.get("valid_test_cases").valueStream()
                .filter(c -> c.get("tweak_indices").isEmpty()) // not supporting tweaks
                .map(c -> new SigAggTestVector(
                        pick(pubkeys, c.get("key_indices"), b -> secp.ecPubKeyParse(b).get()),
                        pick(pnonces, c.get("nonce_indices"), secp::parsePubNonce),
                        pick(psigs, c.get("psig_indices"), secp::parsePartialSig),
                        secp.parseAggNonce(hex(c.get("aggnonce"))),
                        msg,
                        hex(c.get("expected"))))
                .toList();
    }

    static List<TweakTestVector> tweakTestVectors() {
        JsonNode root = readTree("/tweak_vectors.json");
        SecpPrivKey privKey = SecpPrivKey.of(hex(root.get("sk")));
        SecpKeyPair sk = new SecpKeyPairImpl(privKey, secp.ecPubKeyCreate(privKey));
        JsonNode pubkeys = root.get("pubkeys");
        byte[] secnonce = secNonceFromBip327(hex(root.get("secnonce")));
        JsonNode pnonces = root.get("pnonces");
        Secp256k1Foreign.MusigAggNonce aggnonce = secp.parseAggNonce(hex(root.get("aggnonce")));
        JsonNode tweaks = root.get("tweaks");
        byte[] msg = hex(root.get("msg"));

        return root.get("valid_test_cases").valueStream()
                .map(c -> new TweakTestVector(
                        sk,
                        pick(pubkeys, c.get("key_indices"), b -> secp.ecPubKeyParse(b).get()),
                        secp.arrayToSeg(secnonce),
                        pick(pnonces, c.get("nonce_indices"), secp::parsePubNonce),
                        aggnonce,
                        pick(tweaks, c.get("tweak_indices"), b -> b),
                        c.get("is_xonly").valueStream().map(JsonNode::asBoolean).toList(),
                        c.get("signer_index").asInt(),
                        msg,
                        hex(c.get("expected"))
                )).toList();
    }


    // One record per parameterized test, holding the inputs that test consumes.
    record KeyAggTestVector(List<SecpPubKey> pubkeys, byte[] expected) {}
    record NonceGenTestVector(byte[] rand_, SecpPrivKey sk, SecpPubKey pk, byte[] aggpk, byte[] msg, byte[] extra_in, byte[] expected_pubnonce) {}
    record NonceAggTestVector(List<Secp256k1Foreign.MusigPubNonce> pnonces, byte[] expected) {}
    record PartialSignTestVector(SecpPrivKey sk, Secp256k1Foreign.MusigAggNonce aggnonce, List<SecpPubKey> pubkeys, MemorySegment secnonce, List<Secp256k1Foreign.MusigPubNonce> pnonces, byte[] msg, byte[] expected) {}
    record PartialSigVerifyTestVector(List<SecpPubKey> pubkeys, List<Secp256k1Foreign.MusigPubNonce> pnonces, SecpPubKey signer_pubkey, Secp256k1Foreign.MusigPubNonce signer_pnonce, Secp256k1Foreign.MusigAggNonce aggnonce, byte[] msg, Secp256k1Foreign.PartialSig psig) {}
    record SigAggTestVector(List<SecpPubKey> pubkeys, List<Secp256k1Foreign.MusigPubNonce> pnonces, List<Secp256k1Foreign.PartialSig> psigs, Secp256k1Foreign.MusigAggNonce aggnonce, byte[] msg, byte[] expected) {}
    record TweakTestVector(SecpKeyPair sk, List<SecpPubKey> pubkeys, MemorySegment secnonce, List<Secp256k1Foreign.MusigPubNonce> pnonces, Secp256k1Foreign.MusigAggNonce aggnonce, List<byte[]> tweaks, List<Boolean> is_xonly, int signer_index, byte[] msg, byte[] expected) {}

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

    static JsonNode readTree(String path) {
        try (InputStream in = BIP327TestVectorTests.class.getResourceAsStream(path)) {
            return mapper.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static byte[] hex(JsonNode node) {
        return HexFormat.of().parseHex(node.asString());
    }

    /** Parse every hex string in an array node. */
    static <T> List<T> mapHex(JsonNode array, Function<byte[], T> parser) {
        return array.valueStream().map(n -> parser.apply(hex(n))).toList();
    }

    /** Parse the elements of {@code array} selected by the {@code indices} array node. */
    static <T> List<T> pick(JsonNode array, JsonNode indices, Function<byte[], T> parser) {
        return indices.valueStream().map(i -> parser.apply(hex(array.get(i.asInt())))).toList();
    }
}