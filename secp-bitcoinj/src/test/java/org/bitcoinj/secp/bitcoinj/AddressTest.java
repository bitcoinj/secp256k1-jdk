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
package org.bitcoinj.secp.bitcoinj;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.secp.SecpKeyPair;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.internal.SecpPubKeyImpl;
import org.bitcoinj.secp.internal.SecpScalarImpl;
import org.bitcoinj.secp.internal.UInt256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.FieldSource;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;

import static org.bitcoinj.secp.Secp256k1.ProviderId.BOUNCY_CASTLE;
import static org.bitcoinj.secp.bitcoinj.WitnessMaker.calcTweak;

/**
 * Work-in-progress experiments to create Taproot addresses from private keys.
 * Needs to be rewritten using known test vectors.
 */
public class AddressTest {
    final static Network network = BitcoinNetwork.MAINNET;
    @FieldSource("keyAddressArgs")
    @ParameterizedTest(name = "key {0} -> Address {1}")
    void createAddressTest(BigInteger key, String address) throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.getById(BOUNCY_CASTLE)) {
            SecpKeyPair keyPair = secp.ecKeyPairCreate(SecpPrivKey.of(key));
            WitnessMaker maker = new WitnessMaker(secp);
            byte[] witnessProgram = maker.calcWitnessProgram(keyPair.publicKey());
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals(address, tapRootAddress.toString());
    }

    @FieldSource("keyAddressArgs")
    @ParameterizedTest(name = "key {0} -> Address {1}")
    void createAddressTestBouncy(BigInteger key, String address) throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.getById(BOUNCY_CASTLE)) {
            SecpKeyPair keyPair = secp.ecKeyPairCreate(SecpPrivKey.of(key));
            WitnessMaker maker = new WitnessMaker(secp);
            byte[] witnessProgram = maker.calcWitnessProgram(keyPair.publicKey());
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals(address, tapRootAddress.toString());
    }

    @Test
    void createAddressTestBouncyXO() throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.getById(BOUNCY_CASTLE)) {
            WitnessMaker maker = new WitnessMaker(secp);
            byte[] serial = HexFormat.of().parseHex("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
            // TODO: Use `secp.xOnlyPubKeyParse(serial)` here instead of `SecpXOnlyPubKey.parse(serial)`
            // We need a Bouncy Castle Implementation first
            SecpXOnlyPubKey xOnlyKey = SecpXOnlyPubKey.parse(serial).get();
            byte[] witnessProgram = maker.calcWitnessProgram(xOnlyKey);
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals("bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5", tapRootAddress.toString());
    }

    private static final List<Arguments> keyAddressArgs = List.of(
            Arguments.of(BigInteger.ONE, "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"),
            Arguments.of(BigInteger.TEN, "bc1pz6sunwdvdy6t4df4wynddj8wv7rttzl8m384h72ghnxlu2wcquks3sgk7p")
    );

    @Test
    void createAddressTest2() throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.get()) {
            BigInteger internalPubKey = new BigInteger("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d", 16);
            byte[] compressed = new byte[33];
            compressed[0] = 0x02;
            byte[] xbytes = SecpScalarImpl.integerTo32Bytes(internalPubKey);
            System.arraycopy(xbytes, 0, compressed, 1, 32);
            ECKey ecKey = ECKey.fromPublicOnly(compressed);
            SecpPubKey pubkey = secp.ecPubKeyParse(compressed).get();
            // TODO: Use `secp.xOnlyPubKeyParse(serial)` here instead of `SecpXOnlyPubKey.parse(serial)`
            // We need a Bouncy Castle Implementation first
            SecpXOnlyPubKey xOnlyKey = SecpXOnlyPubKey.parse(UInt256.integerTo32Bytes(internalPubKey)).get();
            BigInteger tweakInt = calcTweak(xOnlyKey);
            SecpPubKey G = new SecpPubKeyImpl(Secp256k1.G);
            SecpPubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
            SecpPubKey Q = secp.ecPubKeyCombine(pubkey, P2);
            byte[] witnessProgram = Q.xOnly().serialize();
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        System.out.println(tapRootAddress);
    }
}
