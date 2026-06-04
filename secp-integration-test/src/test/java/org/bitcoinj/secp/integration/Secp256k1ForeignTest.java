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
import org.bitcoinj.secp.SecpResult;
import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.bitcoinj.secp.internal.SchnorrSignatureImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

/**
 *
 */
public class Secp256k1ForeignTest {
    @Test
    void pubKeyAdditionTestOne() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            SecpPubKey pubKey = secp.ecKeyPairCreate(SecpPrivKey.of(BigInteger.ONE)).publicKey();
            // TODO: For some reason this method only exists in FFM implementation
            SecpPubKey added = secp.ecPubKeyCombine(pubKey);
            SecpPubKey multiplied = secp.ecPubKeyTweakMul(pubKey, BigInteger.valueOf(1));
            Assertions.assertEquals(added.getW(), multiplied.getW());
        }
    }

    @Test
    void pubKeyAdditionTestTwo() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            SecpPubKey pubKey = secp.ecKeyPairCreate(SecpPrivKey.of(BigInteger.ONE)).publicKey();
            SecpPubKey added = secp.ecPubKeyCombine(pubKey, pubKey);
            SecpPubKey multiplied = secp.ecPubKeyTweakMul(pubKey, BigInteger.valueOf(2));
            Assertions.assertEquals(added.getW(), multiplied.getW());
        }
    }

    @Test
    void sortKeysTest() {
        try (Secp256k1Foreign secp = new Secp256k1Foreign()) {
            List<SecpPubKey> input = Stream.of(
                    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                    "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
                    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF",
                    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"
            ).map(HexFormat.of()::parseHex)
                    .map(secp::ecPubKeyParse)
                    .map(SecpResult::get)
                    .toList();
            List<SecpPubKey> sorted = Stream.of(
                    "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
                    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
                    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
                    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF",
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                    "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
            ).map(HexFormat.of()::parseHex)
                    .map(secp::ecPubKeyParse)
                    .map(SecpResult::get)
                    .toList();

            List<SecpPubKey> result = secp.ecPubkeySort(input);

            for (int i = 0; i < sorted.size(); i++) {
                Assertions.assertArrayEquals(sorted.get(i).serialize(), result.get(i).serialize());
            }
        }
    }

    @Test
    void keyAgg() {
        try (var secp = new Secp256k1Foreign()) {
            List<SecpPubKey> input = Stream.of(
                            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                            "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                            "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"//,
//                            "020000000000000000000000000000000000000000000000000000000000000005",
//                            "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
//                            "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
//                            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
                    ).map(HexFormat.of()::parseHex)
                    .map(secp::ecPubKeyParse)
                    .map(SecpResult::get)
                    .toList();
            byte[] expected = HexFormat.of().parseHex("90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C");

            Secp256k1Foreign.KeyAggCache result = secp.musigPubkeyAgg(input);

            Assertions.assertArrayEquals(expected, result.aggKey().xOnly().serialize());
        }
    }

    @Test
    void pubNonceGen() {
        try (var secp = new Secp256k1Foreign()) {
            byte[] rand = HexFormat.of().parseHex("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F");
            SecpPrivKey sk = SecpPrivKey.of(
                    HexFormat.of().parseHex("0202020202020202020202020202020202020202020202020202020202020202"));
            SecpPubKey pk = secp.ecPubKeyParse(
                    HexFormat.of()
                            .parseHex("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766"))
                            .get();
            byte[] aggpk = HexFormat.of().parseHex("0707070707070707070707070707070707070707070707070707070707070707");
            byte[] msg = HexFormat.of().parseHex("0101010101010101010101010101010101010101010101010101010101010101");
            byte[] extraIn = HexFormat.of().parseHex("0808080808080808080808080808080808080808080808080808080808080808");

            byte[] expectedSecnonce = HexFormat.of().parseHex("B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766");
            byte[] expectedPubnonce = HexFormat.of().parseHex("02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A");

            Secp256k1Foreign.KeyAggCache keyAggCacheSeg = secp.createCache(aggpk);

            Secp256k1Foreign.MusigNonce nonce = secp.musigNonceGen(rand, sk, pk, msg, keyAggCacheSeg, extraIn);
            Assertions.assertArrayEquals(expectedPubnonce, nonce.pubNonce().serialized());
        }
    }

    @Test
    void nonceAgg() {
        try (var secp = new Secp256k1Foreign()) {
            List<Secp256k1Foreign.MusigPubNonce> in = Stream.of(
                    "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
                    "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833"
            ).map(HexFormat.of()::parseHex).map(secp::parsePubNonce).toList();

            byte[] expected = HexFormat.of().parseHex(
                    "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8"
            );

            Secp256k1Foreign.MusigAggNonce result = secp.musigNonceAgg(in);

            Assertions.assertArrayEquals(expected, result.serialized());
        }
    }

    @Test
    void partialSign() {
        try (var secp = new Secp256k1Foreign()) {
            SecpPrivKey sk = SecpPrivKey.of(HexFormat.of().parseHex("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"));
            List<SecpPubKey> pubKeyList = Stream.of(
                    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661"
            ).map(HexFormat.of()::parseHex).map(secp::ecPubKeyParse).map(SecpResult::get).toList();
            List<Secp256k1Foreign.MusigPubNonce> pubNonceList = Stream.of(
                    "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
                    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                    "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046"
            ).map(HexFormat.of()::parseHex).map(secp::parsePubNonce).toList();
            Secp256k1Foreign.MusigAggNonce aggNonce = secp.parseAggNonce(
                    HexFormat.of().parseHex("028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9")
            );
            byte[] msg32 = HexFormat.of().parseHex("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF");
            MemorySegment secNonce = secp.secNonceFromBip327(
                    HexFormat.of().parseHex("508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9")
            );
            Secp256k1Foreign.PartialSig expected = secp.parsePartialSig(
                    HexFormat.of().parseHex("012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB")
            );

            Secp256k1Foreign.KeyAggCache cache = secp.musigPubkeyAgg(pubKeyList);
            MemorySegment session = secp.musigNonceProcess(aggNonce, msg32, cache);
            Secp256k1Foreign.PartialSig sig = secp.musigPartialSign(secNonce, secp.ecKeyPairCreate(sk), cache, session);

            Assertions.assertArrayEquals(expected.serialized(), sig.serialized());
        }
    }

    @Test
    void partialSigVerify() {
        try (var secp = new Secp256k1Foreign()) {
            SecpPrivKey sk = SecpPrivKey.of(HexFormat.of().parseHex("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"));
            List<SecpPubKey> pubKeyList = Stream.of(
                    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661"
            ).map(HexFormat.of()::parseHex).map(secp::ecPubKeyParse).map(SecpResult::get).toList();
            List<Secp256k1Foreign.MusigPubNonce> pubNonceList = Stream.of(
                    "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
                    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                    "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046"
            ).map(HexFormat.of()::parseHex).map(secp::parsePubNonce).toList();
            Secp256k1Foreign.MusigAggNonce aggNonce = secp.parseAggNonce(
                    HexFormat.of().parseHex("028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9")
            );
            byte[] msg32 = HexFormat.of().parseHex("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF");
            MemorySegment secNonce = secp.secNonceFromBip327(
                    HexFormat.of().parseHex("508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9")
            );
            Secp256k1Foreign.PartialSig partialSig = secp.parsePartialSig(
                    HexFormat.of().parseHex("012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB")
            );

            Secp256k1Foreign.KeyAggCache cache = secp.musigPubkeyAgg(pubKeyList);
            MemorySegment session = secp.musigNonceProcess(aggNonce, msg32, cache);

            boolean good = secp.musigPartialSigVerify(partialSig, pubNonceList.getFirst(), pubKeyList.getFirst(), cache, session);
            Assertions.assertTrue(good);
        }
    }

    @Test
    void sigAgg() {
        try (var secp = new Secp256k1Foreign()) {
            List<Secp256k1Foreign.MusigPubNonce> pubNonceList = Stream.of(
                    "036E5EE6E28824029FEA3E8A9DDD2C8483F5AF98F7177C3AF3CB6F47CAF8D94AE902DBA67E4A1F3680826172DA15AFB1A8CA85C7C5CC88900905C8DC8C328511B53E",
                    "03E4F798DA48A76EEC1C9CC5AB7A880FFBA201A5F064E627EC9CB0031D1D58FC5103E06180315C5A522B7EC7C08B69DCD721C313C940819296D0A7AB8E8795AC1F00"
            ).map(HexFormat.of()::parseHex).map(secp::parsePubNonce).toList();
            List<SecpPubKey> pubKeyList = Stream.of(
                    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                    "02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05"
            ).map(HexFormat.of()::parseHex).map(secp::ecPubKeyParse).map(SecpResult::get).toList();
            List<Secp256k1Foreign.PartialSig> partialSigList = Stream.of(
                    "B15D2CD3C3D22B04DAE438CE653F6B4ECF042F42CFDED7C41B64AAF9B4AF53FB",
                    "6193D6AC61B354E9105BBDC8937A3454A6D705B6D57322A5A472A02CE99FCB64"
            ).map(HexFormat.of()::parseHex).map(secp::parsePartialSig).toList();
            byte[] msg32 = HexFormat.of().parseHex("599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869");
            Secp256k1Foreign.MusigAggNonce aggNonce = secp.parseAggNonce(
                    HexFormat.of().parseHex("0341432722C5CD0268D829C702CF0D1CBCE57033EED201FD335191385227C3210C03D377F2D258B64AADC0E16F26462323D701D286046A2EA93365656AFD9875982B")
            );

            byte[] expected = HexFormat.of().parseHex("041DA22223CE65C92C9A0D6C2CAC828AAF1EEE56304FEC371DDF91EBB2B9EF0912F1038025857FEDEB3FF696F8B99FA4BB2C5812F6095A2E0004EC99CE18DE1E");

            Secp256k1Foreign.KeyAggCache cache = secp.musigPubkeyAgg(pubKeyList);
            MemorySegment session = secp.musigNonceProcess(aggNonce, msg32, cache);
            SchnorrSignature sig = secp.musigPartialSigAgg(session, partialSigList);

            Assertions.assertArrayEquals(expected, sig.bytes());
        }
    }

}
