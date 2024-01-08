package org.consensusj.secp256k1.bitcoinj;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.ECKey;
import org.consensusj.secp256k1.api.P256K1KeyPair;
import org.consensusj.secp256k1.api.P256K1XOnlyPubKey;
import org.consensusj.secp256k1.api.P256k1PubKey;
import org.consensusj.secp256k1.api.Secp256k1;
import org.consensusj.secp256k1.bouncy.Bouncy256k1;
import org.consensusj.secp256k1.bouncy.BouncyPrivKey;
import org.consensusj.secp256k1.bouncy.BouncyPubKey;
import org.consensusj.secp256k1.foreign.PubKeyPojo;
import org.consensusj.secp256k1.foreign.Secp256k1Foreign;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 *
 */
public class AddressTest {
    final static Network network = BitcoinNetwork.MAINNET;
    @Test
    void createAddressTest() throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = new Secp256k1Foreign()) {
            P256K1KeyPair keyPair = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE));
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
        System.out.println(tapRootAddress);
    }

    @Test
    void createAddressTestBouncy() throws Exception {
        Address tapRootAddress;
        try (Secp256k1 secp = new Bouncy256k1()) {
            P256K1KeyPair keyPair = secp.ecKeyPairCreate(new BouncyPrivKey(BigInteger.ONE));
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
        System.out.println(tapRootAddress);
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
        var digest = Sha256Hash.newDigest();
        digest.update("TapTweak".getBytes(StandardCharsets.UTF_8));
        digest.update("TapTweak".getBytes(StandardCharsets.UTF_8));
        digest.update(xOnlyPubKey.getSerialized());
        byte[] hash = digest.digest();
        return new BigInteger(1, hash);
    }
}
