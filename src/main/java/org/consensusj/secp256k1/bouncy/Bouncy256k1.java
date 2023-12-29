package org.consensusj.secp256k1.bouncy;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.consensusj.secp256k1.api.Secp256k1;
import org.consensusj.secp256k1.api.CompressedPubKeyData;
import org.consensusj.secp256k1.api.CompressedSignatureData;
import org.consensusj.secp256k1.api.P256k1PrivKey;
import org.consensusj.secp256k1.api.P256k1PubKey;
import org.consensusj.secp256k1.api.SignatureData;
import org.consensusj.secp256k1.eggcc.EggPubKey;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Optional;

/**
 *
 */
public class Bouncy256k1 implements Secp256k1 {

    // The parameters of the secp256k1 curve that Bitcoin uses.
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    private static final ECDomainParameters CURVE;

    /**
     * Equal to CURVE.getN().shiftRight(1), used for canonicalising the S value of a signature. If you aren't
     * sure what this is about, you can ignore it.
     */
    private static final BigInteger HALF_CURVE_ORDER;

    private static final SecureRandom secureRandom;

    static {
        // Tell Bouncy Castle to precompute data that's needed during secp256k1 calculations.
        FixedPointUtil.precompute(CURVE_PARAMS.getG());
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH());
        HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);
        secureRandom = new SecureRandom();
    }

    public Bouncy256k1() {
    }
    
    @Override
    public P256k1PrivKey ecPrivKeyCreate() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(CURVE, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        return new BouncyPrivKey(privParams.getD());
    }

    @Override
    public P256k1PubKey ecPubKeyCreate(P256k1PrivKey seckey) {
        ECPoint G = CURVE.getG();
        BigInteger secInt = seckey.integer();
        ECPoint pub = new FixedPointCombMultiplier().multiply(G, secInt).normalize();
        return new BouncyPubKey(pub);
    }

    @Override
    public Optional<Object> ecKeyPairCreate() {
        return Optional.empty();
    }

    @Override
    public CompressedPubKeyData ecPubKeySerialize(P256k1PubKey pubKey, int flags) {
        return null;
    }

    @Override
    public Optional<P256k1PubKey> ecPubKeyParse(CompressedPubKeyData inputData) {
        return Optional.empty();
    }

    @Override
    public Optional<SignatureData> ecdsaSign(byte[] msg_hash_data, P256k1PrivKey seckey) {
        return Optional.empty();
    }

    @Override
    public Optional<CompressedSignatureData> ecdsaSignatureSerializeCompact(SignatureData sig) {
        return Optional.empty();
    }

    @Override
    public Optional<SignatureData> ecdsaSignatureParseCompact(CompressedSignatureData serialized_signature) {
        return Optional.empty();
    }

    @Override
    public Optional<Boolean> ecdsaVerify(SignatureData sig, byte[] msg_hash_data, P256k1PubKey pubKey) {
        return Optional.empty();
    }

    @Override
    public void close() {

    }

    public P256k1PubKey g() {
        ECPoint G = CURVE.getG();
        return new EggPubKey(G.getXCoord().toBigInteger(), G.getYCoord().toBigInteger());
    }
}
