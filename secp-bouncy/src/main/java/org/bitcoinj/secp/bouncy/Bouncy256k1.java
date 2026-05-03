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
package org.bitcoinj.secp.bouncy;

import org.bitcoinj.secp.EcdhSharedSecret;
import org.bitcoinj.secp.SecpKeyPair;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpResult;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.SchnorrSignature;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.EcdsaSignature;
import org.bitcoinj.secp.internal.EcdhSharedSecretImpl;
import org.bitcoinj.secp.internal.SecpKeyPairImpl;
import org.bitcoinj.secp.internal.SecpScalarImpl;
import org.bitcoinj.secp.internal.SecpXOnlyPubKeyImpl;
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
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Implementation of {@link Secp256k1} using the Bouncy Castle library.
 */
public class Bouncy256k1 implements Secp256k1 {

    // The Bouncy Castle class containing parameters of the secp256k1 curve that Bitcoin uses.
    private static final X9ECParameters BC_CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    /** The Bouncy Castle class containing parameters of the secp256k1 curve that Bitcoin uses. */
    static final ECDomainParameters BC_CURVE;

    /**
     * Equal to CURVE.getN().shiftRight(1), used for canonicalizing the S value of a signature. If you aren't
     * sure what this is about, you can ignore it.
     */
    static final BigInteger HALF_CURVE_ORDER;

    private static final SecureRandom secureRandom;

    static {
        // Tell Bouncy Castle to precompute data that's needed during secp256k1 calculations.
        FixedPointUtil.precompute(BC_CURVE_PARAMS.getG());
        BC_CURVE = new ECDomainParameters(BC_CURVE_PARAMS.getCurve(),
                BC_CURVE_PARAMS.getG(),
                BC_CURVE_PARAMS.getN(),
                BC_CURVE_PARAMS.getH());
        HALF_CURVE_ORDER = BC_CURVE_PARAMS.getN().shiftRight(1);
        // TODO: Verify using cryptographic random number generator properly
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            // This should never happen. The Javadoc for getInstanceStrong() says
            // "Every implementation of the Java platform is required to support
            // at least one strong SecureRandom implementation."
            throw new RuntimeException("No strong SecureRandom available", e);
        }
    }

    /**
     * Default constructor.
     */
    public Bouncy256k1() {
    }

    @Override
    public SecpPrivKey ecPrivKeyCreate() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(BC_CURVE, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        return SecpPrivKey.of(privParams.getD());
    }

    @Override
    public SecpPubKey ecPubKeyCreate(SecpPrivKey privKey) {
        ECPoint pub = BC_CURVE.getG().multiply(privKey.getS()).normalize();
        return BC.toSecpPubKey(pub);
    }

    @Override
    public SecpKeyPair ecKeyPairCreate() {
        SecpPrivKey priv = ecPrivKeyCreate();
        SecpPubKey pub = ecPubKeyCreate(priv);
        return new SecpKeyPairImpl(priv, pub);
    }

    @Override
    public SecpKeyPair ecKeyPairCreate(SecpPrivKey privKey) {
        SecpPrivKey priv = SecpPrivKey.of(privKey.getS());
        SecpPubKey pub = ecPubKeyCreate(priv);
        return new SecpKeyPairImpl(priv, pub);
    }

    @Override
    public SecpPubKey ecPubKeyTweakMul(SecpPubKey pubKey, BigInteger scalarMultiplier) {
        ECPoint pubKeyBC = BC_CURVE.getCurve().createPoint(pubKey.getW().getAffineX(), pubKey.getW().getAffineY());
        ECPoint pub = new FixedPointCombMultiplier().multiply(pubKeyBC, scalarMultiplier).normalize();
        return BC.toSecpPubKey(pub);
    }

    @Override
    public SecpPubKey ecPubKeyCombine(SecpPubKey key1, SecpPubKey key2) {
        ECPoint pubKey1BC = BC_CURVE.getCurve().createPoint(key1.getW().getAffineX(), key1.getW().getAffineY());
        ECPoint pubKey2BC = BC_CURVE.getCurve().createPoint(key2.getW().getAffineX(), key2.getW().getAffineY());
        ECPoint result = pubKey1BC.add(pubKey2BC);
        return BC.toSecpPubKey(result);
    }

    @Override
    public byte[] ecPubKeySerialize(SecpPubKey pubKey, int flags) {
        boolean compressed;
        switch(flags) {
            case 2: compressed = false; break;          // SECP256K1_EC_UNCOMPRESSED())
            case 258: compressed = true; break;         // SECP256K1_EC_COMPRESSED())
            default: throw new  IllegalArgumentException();
        }
        return pubKey.serialize(compressed);
    }

    @Override
    public SecpResult<SecpPubKey> ecPubKeyParse(byte[] inputData) {
        ECPoint bcPoint = BC_CURVE.getCurve().decodePoint(inputData);
        return SecpResult.ok(BC.toSecpPubKey(bcPoint));
    }

    @Override
    public SecpResult<SecpXOnlyPubKey> xOnlyPubKeyParse(byte[] inputData) {
        try {
            // Bouncy Castle expects compressed format, not X-Only
            byte[] serialized = prependByte(inputData, (byte) 0x2);
            BC_CURVE.getCurve().decodePoint(serialized);
        } catch (IllegalArgumentException e) {
            // If `decodePoint` fails, pubkey is invalid
            return SecpResult.err(0);
        }
        return SecpResult.ok(SecpXOnlyPubKeyImpl.ofVerifiedBytes(inputData));
    }

    private byte[] prependByte(byte[] inputArray, byte toPrepend) {
        return ByteBuffer.allocate(inputArray.length + 1)
                .put(toPrepend)
                .put(inputArray)
                .array();
    }

    @Override
    public SecpResult<EcdsaSignature> ecdsaSign(byte[] msg_hash_data, SecpPrivKey privKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters bouncyPrivKey = new ECPrivateKeyParameters(privKey.getS(), BC_CURVE);
        signer.init(true, bouncyPrivKey);
        BigInteger[] components = signer.generateSignature(msg_hash_data);
        return SecpResult.ok(ecdsaSignature(components));
    }

    @Override
    public SecpResult<EcdsaSignature> ecdsaSignLowR(byte[] messageHashData, SecpPrivKey privKey) {
        HMacDSAKCalculatorWithEntropy kCalculator = new HMacDSAKCalculatorWithEntropy(new SHA256Digest());
        ECDSASigner signer = new ECDSASigner(kCalculator);
        ECPrivateKeyParameters bouncyPrivKey = new ECPrivateKeyParameters(privKey.getS(), BC_CURVE);
        signer.init(true, bouncyPrivKey);
        BigInteger[] components = signer.generateSignature(messageHashData);
        // grind for low R values by adding entropy to the K calculation via RFC 6979 section 3.6.
        // see discussion at https://github.com/bitcoin/bitcoin/pull/13666
        for (int counter = 1; !hasLowR(components[0]) && counter < Integer.MAX_VALUE; counter++) {
            kCalculator.setEntropy(counter);
            components = signer.generateSignature(messageHashData);
        }
        return SecpResult.ok(ecdsaSignature(components));
    }

    private static boolean hasLowR(BigInteger r) {
        // TODO: check low-r directly on BigInteger
        return SecpScalarImpl.integerTo32Bytes(r)[0] >= 0;
    }

    // Convert and canonicalize signature
    private EcdsaSignature ecdsaSignature(BigInteger[] components) {
        return EcdsaSignature.of(
                new SecpScalarImpl(components[0]),
                new SecpScalarImpl(canonicalize(components[1]))
        );
    }

    BigInteger canonicalize(BigInteger s) {
        return s.compareTo(HALF_CURVE_ORDER) <= 0
                ? s
                : BC_CURVE.getN().subtract(s);
    }

    @Override
    public byte[] ecdsaSignatureSerializeCompact(EcdsaSignature sig) {
        return sig.serializeCompact();
    }

    @Override
    public SecpResult<EcdsaSignature> ecdsaSignatureParseCompact(byte[] serialized_signature) {
        try {
            return SecpResult.ok(EcdsaSignature.of(serialized_signature));
        } catch (IllegalArgumentException iae) {
            return SecpResult.err(0);
        }
    }

    @Override
    public SecpResult<Boolean> ecdsaVerify(EcdsaSignature signature, byte[] msg_hash_data, SecpPubKey pubKey) {
        ECDSASigner signer = new ECDSASigner();
        ECPoint pubPoint = BC.fromSecpPoint(pubKey.point());
        ECPublicKeyParameters params = new ECPublicKeyParameters(pubPoint, BC_CURVE);
        signer.init(false, params);
        boolean result;
        try {
            result = signer.verifySignature(msg_hash_data, signature.r().toBigInteger(), signature.s().toBigInteger());
        } catch (NullPointerException e) {
            // Bouncy Castle contains a bug that can cause NPEs given specially crafted signatures. Those signatures
            // are inherently invalid/attack sigs so we just fail them here rather than crash the thread.
            //log.error("Caught NPE inside bouncy castle", e);
            result = false;
        }
        return SecpResult.ok(result);
    }

    @Override
    public byte[] taggedSha256(byte[] tag, byte[] message) {
        return new byte[0];
    }

    @Override
    public SchnorrSignature schnorrSigSign32(byte[] msg_hash, SecpPrivKey privKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    public SecpResult<Boolean> schnorrSigVerify(SchnorrSignature signature, byte[] msg_hash, SecpXOnlyPubKey pubKey) {
        return SecpResult.err(-1);
    }

    @Override
    public SecpResult<EcdhSharedSecret> ecdh(SecpPubKey pubKey, SecpPrivKey privKey) {
        ECPoint point = BC.fromSecpPoint(pubKey.point());
        ECPoint ssPoint = point.multiply(privKey.getS()).normalize();
        byte[] hashed = ecdhHash(BC.toSecpPubKey(ssPoint));
        return SecpResult.ok(new EcdhSharedSecretImpl(hashed));
    }
    
    private byte[] ecdhHash(SecpPubKey sspk) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
        digest.update(sspk.serialize(true));
        return digest.digest();
    }

    @Override
    public void close() {

    }

    @Override
    public String toString() {
        return "Secp256k1/" + ProviderId.BOUNCY_CASTLE;
    }
}
