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
package org.bitcoinj.secp.bitcoinj;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.secp.P256K1FieldElement;
import org.bitcoinj.secp.P256K1KeyPair;
import org.bitcoinj.secp.P256K1XOnlyPubKey;
import org.bitcoinj.secp.P256k1PrivKey;
import org.bitcoinj.secp.P256k1PubKey;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.internal.P256k1PubKeyImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.HexFormat;
import java.util.stream.Stream;

import static org.bitcoinj.secp.Secp256k1.ProviderId.BOUNCY_CASTLE;
import static org.bitcoinj.secp.bitcoinj.WitnessMaker.calcTweak;

/**
 *
 */
public class AddressTest {
    final static Network network = BitcoinNetwork.MAINNET;
    @MethodSource("keyAddressArgs")
    @ParameterizedTest(name = "key {0} -> Address {1}")
    void createAddressTest(BigInteger key, String address) throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.getById(BOUNCY_CASTLE)) {
            P256K1KeyPair keyPair = secp.ecKeyPairCreate(P256k1PrivKey.of(key));
            WitnessMaker maker = new WitnessMaker(secp);
//            P256K1XOnlyPubKey xOnlyKey = keyPair.getPublic().getXOnly();
//            BigInteger tweakInt = calcTweak(xOnlyKey);
//            P256k1PubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
//            P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
//            P256k1PubKey Q = secp.ecPubKeyCombine(keyPair.getPublic(), P2);
//            byte[] witnessProgram = Q.getXOnly().getSerialized();
            byte[] witnessProgram = maker.calcWitnessProgram(keyPair.publicKey());
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals(address, tapRootAddress.toString());
    }

    @MethodSource("keyAddressArgs")
    @ParameterizedTest(name = "key {0} -> Address {1}")
    void createAddressTestBouncy(BigInteger key, String address) throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.getById(BOUNCY_CASTLE)) {
            P256K1KeyPair keyPair = secp.ecKeyPairCreate(P256k1PrivKey.of(key));
            WitnessMaker maker = new WitnessMaker(secp);
//            P256K1XOnlyPubKey xOnlyKey = keyPair.getPublic().getXOnly();
//            BigInteger tweakInt = calcTweak(xOnlyKey);
//            P256k1PubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
//            P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
//            P256k1PubKey Q = secp.ecPubKeyCombine(keyPair.getPublic(), P2);
//            byte[] witnessProgram = Q.getXOnly().getSerialized();
            byte[] witnessProgram = maker.calcWitnessProgram(keyPair.publicKey());
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals(address, tapRootAddress.toString());
    }

    @Test
    void createAddressTestBouncyXO() throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.getById(BOUNCY_CASTLE)) {
            byte[] serial = HexFormat.of().parseHex("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
            P256K1XOnlyPubKey xOnlyKey = P256K1XOnlyPubKey.parse(serial).get();
            BigInteger tweakInt = calcTweak(xOnlyKey);
            P256k1PubKey G = new P256k1PubKeyImpl(Secp256k1.G);
            P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
            P256k1PubKey Q = secp.ecPubKeyCombine(new P256k1PubKeyImpl(new ECPoint(xOnlyKey.getX(), BigInteger.ZERO)), P2);
            byte[] witnessProgram = Q.xOnly().serialize();
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals("bc1p87m65znsydcvkaqf9ysanum8aca8j3kvadxrs6agqztm9fpxsfus698zka", tapRootAddress.toString());
    }


    private static Stream<Arguments> keyAddressArgs() {
        return Stream.of(
                Arguments.of(BigInteger.ONE, "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"),
                Arguments.of(BigInteger.TEN, "bc1pz6sunwdvdy6t4df4wynddj8wv7rttzl8m384h72ghnxlu2wcquks3sgk7p")
        );
    }
    @Test
    void createAddressTest2() throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.get()) {
            BigInteger internalPubKey = new BigInteger("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d", 16);
            byte[] compressed = new byte[33];
            compressed[0] = 0x02;
            byte[] xbytes = P256K1FieldElement.integerTo32Bytes(internalPubKey);
            System.arraycopy(xbytes, 0, compressed, 1, 32);
            ECKey ecKey = ECKey.fromPublicOnly(compressed);
            P256k1PubKey pubkey = BC.toP256K1PubKey(ecKey.getPubKeyPoint());
            P256K1XOnlyPubKey xOnlyKey = P256K1XOnlyPubKey.of(internalPubKey);
            BigInteger tweakInt = calcTweak(xOnlyKey);
            P256k1PubKey G = new P256k1PubKeyImpl(Secp256k1.G);
            P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
            P256k1PubKey Q = secp.ecPubKeyCombine(pubkey, P2);
            byte[] witnessProgram = Q.xOnly().serialize();
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        System.out.println(tapRootAddress);
    }

}
