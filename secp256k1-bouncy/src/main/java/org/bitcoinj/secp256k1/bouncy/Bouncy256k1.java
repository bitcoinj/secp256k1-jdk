/*
 * Copyright 2023-2024 secp256k1-jdk Developers.
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
package org.bitcoinj.secp256k1.bouncy;

import org.bitcoinj.secp256k1.api.Result;
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
import org.bitcoinj.secp256k1.api.P256K1KeyPair;
import org.bitcoinj.secp256k1.api.P256K1XOnlyPubKey;
import org.bitcoinj.secp256k1.api.Secp256k1;
import org.bitcoinj.secp256k1.api.CompressedPubKeyData;
import org.bitcoinj.secp256k1.api.CompressedSignatureData;
import org.bitcoinj.secp256k1.api.P256k1PrivKey;
import org.bitcoinj.secp256k1.api.P256k1PubKey;
import org.bitcoinj.secp256k1.api.SignatureData;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Optional;

/**
 *
 */
public class Bouncy256k1 implements Secp256k1 {

    // The parameters of the secp256k1 curve that Bitcoin uses.
    private static final X9ECParameters BC_CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    static final ECDomainParameters BC_CURVE;

    /**
     * Equal to CURVE.getN().shiftRight(1), used for canonicalising the S value of a signature. If you aren't
     * sure what this is about, you can ignore it.
     */
    private static final BigInteger HALF_CURVE_ORDER;

    private static final SecureRandom secureRandom;

    static {
        // Tell Bouncy Castle to precompute data that's needed during secp256k1 calculations.
        FixedPointUtil.precompute(BC_CURVE_PARAMS.getG());
        BC_CURVE = new ECDomainParameters(BC_CURVE_PARAMS.getCurve(),
                BC_CURVE_PARAMS.getG(),
                BC_CURVE_PARAMS.getN(),
                BC_CURVE_PARAMS.getH());
        HALF_CURVE_ORDER = BC_CURVE_PARAMS.getN().shiftRight(1);
        secureRandom = new SecureRandom();
    }

    public Bouncy256k1() {
    }
    
    @Override
    public BouncyPrivKey ecPrivKeyCreate() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(BC_CURVE, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        return new BouncyPrivKey(privParams.getD());
    }

    @Override
    public BouncyPubKey ecPubKeyCreate(P256k1PrivKey seckey) {
        ECPoint G = BC_CURVE.getG();
        BigInteger secInt = seckey.getS();
        ECPoint pub = new FixedPointCombMultiplier().multiply(G, secInt).normalize();
        return new BouncyPubKey(pub);
    }

    @Override
    public P256K1KeyPair ecKeyPairCreate() {
        BouncyPrivKey priv = ecPrivKeyCreate();
        BouncyPubKey pub = ecPubKeyCreate(priv);
        return new BouncyKeyPair(priv, pub);
    }

    @Override
    public P256K1KeyPair ecKeyPairCreate(P256k1PrivKey privKey) {
        BouncyPrivKey priv = new BouncyPrivKey(privKey.getS());
        BouncyPubKey pub = ecPubKeyCreate(priv);
        return new BouncyKeyPair(priv, pub);
    }

    @Override
    public P256k1PubKey ecPubKeyTweakMul(P256k1PubKey pubKey, BigInteger scalarMultiplier) {
        ECPoint pubKeyBC = BC_CURVE.getCurve().createPoint(pubKey.getW().getAffineX(), pubKey.getW().getAffineY());
        ECPoint pub = new FixedPointCombMultiplier().multiply(pubKeyBC, scalarMultiplier).normalize();
        return new BouncyPubKey(pub);
    }

    @Override
    public P256k1PubKey ecPubKeyCombine(P256k1PubKey key1, P256k1PubKey key2) {
        ECPoint pubKey1BC = BC_CURVE.getCurve().createPoint(key1.getW().getAffineX(), key1.getW().getAffineY());
        ECPoint pubKey2BC = BC_CURVE.getCurve().createPoint(key2.getW().getAffineX(), key2.getW().getAffineY());
        ECPoint result = pubKey1BC.add(pubKey2BC);
        return new BouncyPubKey(result);
    }

    @Override
    public CompressedPubKeyData ecPubKeySerialize(P256k1PubKey pubKey, int flags) {
        return null;
    }

    @Override
    public Result<P256k1PubKey> ecPubKeyParse(CompressedPubKeyData inputData) {
        return Result.err(-1);
    }

    @Override
    public Result<SignatureData> ecdsaSign(byte[] msg_hash_data, P256k1PrivKey seckey) {
        return Result.err(-1);
    }

    @Override
    public Result<CompressedSignatureData> ecdsaSignatureSerializeCompact(SignatureData sig) {
        return Result.err(-1);
    }

    @Override
    public Result<SignatureData> ecdsaSignatureParseCompact(CompressedSignatureData serialized_signature) {
        return Result.err(-1);
    }

    @Override
    public Result<Boolean> ecdsaVerify(SignatureData sig, byte[] msg_hash_data, P256k1PubKey pubKey) {
        return Result.err(-1);
    }
    @Override
    public byte[] taggedSha256(byte[] tag, byte[] message) {
        return new byte[0];
    }

    @Override
    public byte[] schnorrSigSign32(byte[] msg_hash, P256K1KeyPair keyPair) {
        return null;
    }

    @Override
    public Result<Boolean> schnorrSigVerify(byte[] signature, byte[] msg_hash, P256K1XOnlyPubKey pubKey) {
        return Result.err(-1);
    }

    @Override
    public void close() {

    }
}
