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
import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpKeyPair;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpScalar;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.internal.UInt256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.FieldSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

/**
 * Work-in-progress experiments to create Taproot addresses from keys.
 */
@ParameterizedClass
@MethodSource("secpImplementations")
public class AddressTest {
    /**
     * Return an instance of {@link Secp256k1} for all known providers.
     * @return stream of all providers
     */
    static Stream<Secp256k1> secpImplementations() {
        return Secp256k1.all().map(Secp256k1.Provider::get);
    }

    final static Network network = BitcoinNetwork.MAINNET;
    private final Secp256k1 secp;

    /// @param secp injected Secp256k1 implementation to test
    AddressTest(Secp256k1 secp) {
        this.secp = secp;
    }

    @FieldSource("keyAddressArgs")
    @ParameterizedTest(name = "key {0} -> Address {1}")
    void createAddressTest(BigInteger key, String address) throws Exception {
        Address tapRootAddress;
        SecpKeyPair keyPair = secp.ecKeyPairCreate(SecpPrivKey.of(key));
        WitnessMaker maker = new WitnessMaker(secp);
        SecpFieldElement tweakedPubKey = maker.tweakedPubKey(keyPair.publicKey().xOnly());
        tapRootAddress = SegwitAddress.fromProgram(network, 1, tweakedPubKey.serialize());
        Assertions.assertEquals(address, tapRootAddress.toString());
    }

    /// Run the 0th BIP-341 test vector, without checking intermediate values
    @Test
    void bipVector0() {
        byte[] serializedInternalPubKey = parseHex("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
        String expectedBip350Address = "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5";

        WitnessMaker maker = new WitnessMaker(secp);
        SecpXOnlyPubKey internalPubkey = secp.xOnlyPubKeyParse(serializedInternalPubKey).get();
        SecpFieldElement tweakedPubKey = maker.tweakedPubKey(internalPubkey);
        Address tapRootAddress = SegwitAddress.fromProgram(network, 1, tweakedPubKey.serialize());

        Assertions.assertEquals(expectedBip350Address, tapRootAddress.toString());
    }

    private static final List<Arguments> keyAddressArgs = List.of(
            Arguments.of(BigInteger.ONE, "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"),
            Arguments.of(BigInteger.TEN, "bc1p5mmme8n7pqk4x55sky33h3xxu0hp9tnuszt78szmhv8su25a4y3smy8tg3")
    );

    /// Run the 0th BIP-341 test vector, checking intermediate values
    /// Q = P + int(hashTapTweak(bytes(P)))G
    @Test
    void bipVector0WithIntermediateChecks() {
        byte[] serializedInternalPubKey = parseHex("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
        byte[] expectedTweak = parseHex("b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70");
        byte[] expectedTweakedPubkey = parseHex("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
        String expectedBip350Address = "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5";

        WitnessMaker maker = new WitnessMaker(secp);
        SecpXOnlyPubKey internalPubkey = secp.xOnlyPubKeyParse(serializedInternalPubKey).get();
        // tweak = int(hashTapTweak(bytes(P))))
        SecpScalar tweak = maker.hashTapTweak(internalPubkey);

        Assertions.assertArrayEquals(expectedTweak, tweak.serialize());

        // tweakedPubKey (aka Q.x(), where Q = P + int(hashTapTweak(bytes(P)))G)
        SecpFieldElement tweakedPubKey = maker.tweakedPubKey(internalPubkey, tweak);

        Assertions.assertArrayEquals(expectedTweakedPubkey, tweakedPubKey.serialize());

        Address tapRootAddress = SegwitAddress.fromProgram(network, 1, tweakedPubKey.serialize());
        Assertions.assertEquals(expectedBip350Address, tapRootAddress.toString());
    }

    byte[] parseHex(String hexString) {
        return HexFormat.of().parseHex(hexString);
    }
}
