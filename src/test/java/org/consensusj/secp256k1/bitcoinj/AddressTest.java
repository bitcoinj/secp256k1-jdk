package org.consensusj.secp256k1.bitcoinj;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.secp256k1.api.P256K1KeyPair;
import org.bitcoinj.secp256k1.api.P256K1XOnlyPubKey;
import org.bitcoinj.secp256k1.api.P256k1PubKey;
import org.bitcoinj.secp256k1.api.Secp256k1;
import org.bitcoinj.secp256k1.bouncy.Bouncy256k1;
import org.bitcoinj.secp256k1.bouncy.BouncyPrivKey;
import org.bitcoinj.secp256k1.bouncy.BouncyPubKey;
import org.bitcoinj.secp256k1.foreign.PubKeyPojo;
import org.bitcoinj.secp256k1.foreign.Secp256k1Foreign;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;
import java.util.HexFormat;
import java.util.stream.Stream;

/**
 *
 */
public class AddressTest {
    final static Network network = BitcoinNetwork.MAINNET;
    @MethodSource("keyAddressArgs")
    @ParameterizedTest(name = "key {0} -> Address {1}")
    void createAddressTest(BigInteger key, String address) throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = new Secp256k1Foreign()) {
            P256K1KeyPair keyPair = secp.ecKeyPairCreate(new BouncyPrivKey(key));
            WitnessMaker maker = new WitnessMaker(secp);
//            P256K1XOnlyPubKey xOnlyKey = keyPair.getPublic().getXOnly();
//            BigInteger tweakInt = calcTweak(xOnlyKey);
//            P256k1PubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
//            P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
//            P256k1PubKey Q = secp.ecPubKeyCombine(keyPair.getPublic(), P2);
//            byte[] witnessProgram = Q.getXOnly().getSerialized();
            byte[] witnessProgram = maker.calcWitnessProgram(keyPair.getPublic());
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals(address, tapRootAddress.toString());
    }

    @MethodSource("keyAddressArgs")
    @ParameterizedTest(name = "key {0} -> Address {1}")
    void createAddressTestBouncy(BigInteger key, String address) throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = new Bouncy256k1()) {
            P256K1KeyPair keyPair = secp.ecKeyPairCreate(new BouncyPrivKey(key));
            WitnessMaker maker = new WitnessMaker(secp);
//            P256K1XOnlyPubKey xOnlyKey = keyPair.getPublic().getXOnly();
//            BigInteger tweakInt = calcTweak(xOnlyKey);
//            P256k1PubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
//            P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
//            P256k1PubKey Q = secp.ecPubKeyCombine(keyPair.getPublic(), P2);
//            byte[] witnessProgram = Q.getXOnly().getSerialized();
            byte[] witnessProgram = maker.calcWitnessProgram(keyPair.getPublic());
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        Assertions.assertEquals(address, tapRootAddress.toString());
    }

    @Test
    void createAddressTestBouncyXO() throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = new Bouncy256k1()) {
            byte[] serial = HexFormat.of().parseHex("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
            P256K1XOnlyPubKey xOnlyKey = P256K1XOnlyPubKey.parse(serial).orElseThrow();
            BigInteger tweakInt = calcTweak(xOnlyKey);
            P256k1PubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
            P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
            P256k1PubKey Q = secp.ecPubKeyCombine(new PubKeyPojo(new ECPoint(xOnlyKey.getX(), BigInteger.ZERO)), P2);
            byte[] witnessProgram = Q.getXOnly().getSerialized();
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
        try (Secp256k1 secp = new Secp256k1Foreign()) {
            BigInteger internalPubKey = new BigInteger("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d", 16);
            byte[] compressed = new byte[33];
            compressed[0] = 0x02;
            byte[] xbytes = P256k1PubKey.integerTo32Bytes(internalPubKey);
            System.arraycopy(xbytes, 0, compressed, 1, 32);
            ECKey ecKey = ECKey.fromPublicOnly(compressed);
            P256k1PubKey pubkey = new BouncyPubKey(ecKey.getPubKeyPoint());
            P256K1XOnlyPubKey xOnlyKey = new P256K1XOnlyPubKey(internalPubKey);
            BigInteger tweakInt = calcTweak(xOnlyKey);
            P256k1PubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
            P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
            P256k1PubKey Q = secp.ecPubKeyCombine(pubkey, P2);
            byte[] witnessProgram = Q.getXOnly().getSerialized();
            tapRootAddress = SegwitAddress.fromProgram(network, 1, witnessProgram);
        }
        System.out.println(tapRootAddress);
    }

    public class WitnessMaker {
        private final Secp256k1 secp;

        public WitnessMaker(Secp256k1 secp) {
            this.secp = secp;
        }

        public byte[] calcWitnessProgram(P256k1PubKey pubKey) {
            P256K1XOnlyPubKey xOnlyKey = pubKey.getXOnly();
            BigInteger tweakInt = calcTweak(xOnlyKey);
            P256k1PubKey G = new PubKeyPojo(Secp256k1.EC_PARAMS.getGenerator());
            P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
            P256k1PubKey Q = secp.ecPubKeyCombine(pubKey, P2);
            return Q.getXOnly().getSerialized();
        }
    }

    private BigInteger calcTweak(P256K1XOnlyPubKey xOnlyPubKey) {
        var digest = newDigest();
        digest.update(tweakPrefix);
        byte[] hash  = digest.digest(xOnlyPubKey.getSerialized());
        return new BigInteger(1, hash);
    }
    
    /** 64-byte concatenation of two 32-byte hashes of "TapTweak" */
    private static final byte[] tweakPrefix =  calcTagPrefix64("TapTweak");

    public static byte[] calcTagPrefix64(String tag) {
        byte[] hash = hash256(tag.getBytes(StandardCharsets.UTF_8));
        return ByteBuffer.allocate(64)
                .put(hash)
                .put(hash)
                .array();
    }
    private static byte[] hash256(byte[] message) {
        return newDigest().digest(message);
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }
}
