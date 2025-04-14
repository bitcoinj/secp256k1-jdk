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
package org.bitcoinj.secp.bouncy;

import org.bitcoinj.secp.api.CompressedPubKeyData;
import org.bitcoinj.secp.api.CompressedSignatureData;
import org.bitcoinj.secp.api.P256K1KeyPair;
import org.bitcoinj.secp.api.P256K1XOnlyPubKey;
import org.bitcoinj.secp.api.P256k1PrivKey;
import org.bitcoinj.secp.api.P256k1PubKey;
import org.bitcoinj.secp.api.Result;
import org.bitcoinj.secp.api.Secp256k1;
import org.bitcoinj.secp.api.SignatureData;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.FixedPointUtil;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

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
    public P256k1PrivKey ecPrivKeyCreate() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(BC_CURVE, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        return P256k1PrivKey.of(privParams.getD());
    }

    @Override
    public P256k1PubKey ecPubKeyCreate(P256k1PrivKey seckey) {
        ECPoint G = BC_CURVE.getG();
        BigInteger secInt = seckey.getS();
        ECPoint pub = new FixedPointCombMultiplier().multiply(G, secInt).normalize();
        return BC.toP256K1PubKey(pub);
    }

    @Override
    public P256K1KeyPair ecKeyPairCreate() {
        P256k1PrivKey priv = ecPrivKeyCreate();
        P256k1PubKey pub = ecPubKeyCreate(priv);
        return new BouncyKeyPair(priv, pub);
    }

    @Override
    public P256K1KeyPair ecKeyPairCreate(P256k1PrivKey privKey) {
        P256k1PrivKey priv = P256k1PrivKey.of(privKey.getS());
        P256k1PubKey pub = ecPubKeyCreate(priv);
        return new BouncyKeyPair(priv, pub);
    }

    @Override
    public P256k1PubKey ecPubKeyTweakMul(P256k1PubKey pubKey, BigInteger scalarMultiplier) {
        ECPoint pubKeyBC = BC_CURVE.getCurve().createPoint(pubKey.getW().getAffineX(), pubKey.getW().getAffineY());
        ECPoint pub = new FixedPointCombMultiplier().multiply(pubKeyBC, scalarMultiplier).normalize();
        return BC.toP256K1PubKey(pub);
    }

    @Override
    public P256k1PubKey ecPubKeyCombine(P256k1PubKey key1, P256k1PubKey key2) {
        ECPoint pubKey1BC = BC_CURVE.getCurve().createPoint(key1.getW().getAffineX(), key1.getW().getAffineY());
        ECPoint pubKey2BC = BC_CURVE.getCurve().createPoint(key2.getW().getAffineX(), key2.getW().getAffineY());
        ECPoint result = pubKey1BC.add(pubKey2BC);
        return BC.toP256K1PubKey(result);
    }

    @Override
    public byte[] ecPubKeySerialize(P256k1PubKey pubKey, int flags) {
        boolean compressed;
        switch(flags) {
            case 2: compressed = false; break;          // SECP256K1_EC_UNCOMPRESSED())
            case 258: compressed = true; break;         // SECP256K1_EC_COMPRESSED())
            default: throw new  IllegalArgumentException();
        }
        return pubKey.getEncoded(compressed);
    }

    @Override
    public Result<P256k1PubKey> ecPubKeyParse(CompressedPubKeyData inputData) {
        return ecPubKeyParse(inputData.bytes());
    }

    @Override
    public Result<P256k1PubKey> ecPubKeyParse(byte[] inputData) {
        org.bouncycastle.math.ec.ECPoint bcPoint = BC_CURVE.getCurve().decodePoint(inputData);
        return Result.ok(BC.toP256K1PubKey(bcPoint));
    }

    // TODO: Add constructor to create SignatureData from r and s
    @Override
    public Result<SignatureData> ecdsaSign(byte[] msg_hash_data, P256k1PrivKey seckey) {
        BigInteger privateKeyForSigning = seckey.getS();
        Objects.requireNonNull(privateKeyForSigning);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, BC_CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(msg_hash_data);
        //return new ECDSASignature(components[0], components[1]).toCanonicalised();
        SignatureData signatureData = new BouncySignature(components[0], components[1]);
        return Result.ok(signatureData);
    }

    @Override
    public Result<CompressedSignatureData> ecdsaSignatureSerializeCompact(SignatureData sig) {
        return Result.err(-1);
    }

    @Override
    public Result<SignatureData> ecdsaSignatureParseCompact(CompressedSignatureData serialized_signature) {
        return Result.err(-1);
    }

    // TODO: Add getters to SignatureData to return r and s
    @Override
    public Result<Boolean> ecdsaVerify(SignatureData sig, byte[] msg_hash_data, P256k1PubKey pubKey) {
        ECDSASigner signer = new ECDSASigner();
        java.security.spec.ECPoint jPoint = pubKey.getW();
        org.bouncycastle.math.ec.ECPoint pubPoint = BC.fromECPoint(jPoint);
        ECPublicKeyParameters params = new ECPublicKeyParameters(pubPoint, BC_CURVE);
        signer.init(false, params);
        BouncySignature signature = (BouncySignature) sig;
        boolean result;
        try {
            result = signer.verifySignature(msg_hash_data, signature.r(), signature.s());
        } catch (NullPointerException e) {
            // Bouncy Castle contains a bug that can cause NPEs given specially crafted signatures. Those signatures
            // are inherently invalid/attack sigs so we just fail them here rather than crash the thread.
            //log.error("Caught NPE inside bouncy castle", e);
            result = false;
        }
        return Result.ok(result);
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
    public Result<byte[]> ecdh(P256k1PubKey pubKey, P256k1PrivKey secKey) {
        ECPoint point = BC.fromECPoint(pubKey.getW());
        ECPoint ssPoint = point.multiply(secKey.getS()).normalize();
        byte[] hashed = ecdhHash(BC.toP256K1PubKey(ssPoint));
        return Result.ok(hashed);
    }
    
    private byte[] ecdhHash(P256k1PubKey sspk) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
        digest.update(sspk.getCompressed());
        return digest.digest();
    }

    @Override
    public void close() {

    }
}
