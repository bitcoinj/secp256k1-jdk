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

import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpResult;
import org.bitcoinj.secp.ffm.Secp256k1Foreign;
import org.bitcoinj.secp.internal.SecpPubKeyImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
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

}
