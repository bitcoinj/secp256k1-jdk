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
import org.bitcoinj.secp.internal.SecpFieldElementImpl;
import org.bitcoinj.secp.internal.SecpPubKeyImpl;
import org.bitcoinj.secp.internal.SecpScalarImpl;
import org.bitcoinj.secp.internal.UInt256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.HexFormat;
import java.util.List;

import static org.bitcoinj.secp.Secp256k1.ProviderId.BOUNCY_CASTLE;
import static org.bitcoinj.secp.bitcoinj.WitnessMaker.calcTweak;

/**
 *
 */
public class AddressTest {
    final static Network network = BitcoinNetwork.MAINNET;
    @FieldSource("keyAddressArgs")
    @ParameterizedTest()
    void createAddressTest(PrivKeyAddrVector vec) throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.getById(BOUNCY_CASTLE)) {
            SecpKeyPair keyPair = secp.ecKeyPairCreate(SecpPrivKey.of(vec.privKey));
            WitnessMaker maker = new WitnessMaker(secp);
//            SecpXOnlyPubKey xOnlyKey = keyPair.getPublic().getXOnly();
//            BigInteger tweakInt = calcTweak(xOnlyKey);
//            SecpPubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
//            SecpPubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
//            SecpPubKey Q = secp.ecPubKeyCombine(keyPair.getPublic(), P2);
//            byte[] witnessProgram = Q.getXOnly().getSerialized();
            byte[] witnessProgram = maker.calcWitnessProgram(keyPair.publicKey());
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals(vec.address, tapRootAddress.toString());
    }

    @FieldSource("keyAddressArgs")
    @ParameterizedTest()
    void createAddressTestBouncy(PrivKeyAddrVector vec) throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.getById(BOUNCY_CASTLE)) {
            SecpKeyPair keyPair = secp.ecKeyPairCreate(SecpPrivKey.of(vec.privKey));
            WitnessMaker maker = new WitnessMaker(secp);
//            SecpXOnlyPubKey xOnlyKey = keyPair.getPublic().getXOnly();
//            BigInteger tweakInt = calcTweak(xOnlyKey);
//            SecpPubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
//            SecpPubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
//            SecpPubKey Q = secp.ecPubKeyCombine(keyPair.getPublic(), P2);
//            byte[] witnessProgram = Q.getXOnly().getSerialized();
            byte[] witnessProgram = maker.calcWitnessProgram(keyPair.publicKey());
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals(vec.address, tapRootAddress.toString());
    }

    @Test
    void createAddressTestBouncyXO() throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = Secp256k1.getById(BOUNCY_CASTLE)) {
            byte[] serial = HexFormat.of().parseHex("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
            // TODO: Use `secp.xOnlyPubKeyParse(serial)` here instead of `SecpXOnlyPubKey.parse(serial)`
            // We need a Bouncy Castle Implementation first
            SecpXOnlyPubKey xOnlyKey = SecpXOnlyPubKey.parse(serial).get();
            BigInteger tweakInt = calcTweak(xOnlyKey);
            SecpPubKey G = new SecpPubKeyImpl(Secp256k1.G);
            SecpPubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
            SecpPubKey Q = secp.ecPubKeyCombine(new SecpPubKeyImpl(new ECPoint(xOnlyKey.getX(), BigInteger.ZERO)), P2);
            byte[] witnessProgram = Q.xOnly().serialize();
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals("bc1p87m65znsydcvkaqf9ysanum8aca8j3kvadxrs6agqztm9fpxsfus698zka", tapRootAddress.toString());
    }

    record PrivKeyAddrVector(BigInteger privKey, String address) {};
    private static final List<PrivKeyAddrVector> keyAddressArgs = List.of(
            new PrivKeyAddrVector(BigInteger.ONE, "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"),
            new PrivKeyAddrVector(BigInteger.TEN, "bc1pz6sunwdvdy6t4df4wynddj8wv7rttzl8m384h72ghnxlu2wcquks3sgk7p")
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
