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
import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpPubKey;
import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpResult;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.SchnorrSignature;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.EcdsaSignature;
import org.bitcoinj.secp.internal.EcdhSharedSecretImpl;
import org.bitcoinj.secp.internal.SchnorrSignatureImpl;
import org.bitcoinj.secp.internal.SecpKeyPairImpl;
import org.bitcoinj.secp.internal.SecpPrivKeyImpl;
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
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.BIP340Signer;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Point;
import org.bouncycastle.util.Arrays;

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

    static final SecP256K1Curve BC_CURVE = (SecP256K1Curve) BC_CURVE_PARAMS.getCurve();
    /** The Bouncy Castle class containing parameters of the secp256k1 curve that Bitcoin uses. */
    static final ECDomainParameters BC_ECDOMAIN_PARAMS;

    /**
     * Equal to CURVE.getN().shiftRight(1), used for canonicalizing the S value of a signature. If you aren't
     * sure what this is about, you can ignore it.
     */
    static final BigInteger HALF_CURVE_ORDER;

    private final SecureRandom secureRandom;

    static {
        // Tell Bouncy Castle to precompute data that's needed during secp256k1 calculations.
        FixedPointUtil.precompute(BC_CURVE_PARAMS.getG());
        BC_ECDOMAIN_PARAMS = new ECDomainParameters(BC_CURVE,
                BC_CURVE_PARAMS.getG(),
                BC_CURVE_PARAMS.getN(),
                BC_CURVE_PARAMS.getH());
        HALF_CURVE_ORDER = BC_CURVE_PARAMS.getN().shiftRight(1);
    }

    /**
     * Default constructor.
     */
    public Bouncy256k1() {
        // TODO: Verify using cryptographic random number generator properly
        // We initialize a new `SecureRandom` per instance for the following reasons:
        // 1. Per-instance allocation avoids the static being contained in GraalVM
        //    native-image instances (GraalVM may special-case this) or being cloned when the
        //    containing process is cloned (may occur with containers, etc.)
        // 2. On certain JDK/OS configurations it's possible `SecureRandom.getInstanceStrong()`
        //    can cause a delay. It's better to not incur this during static initialization.
        // 3. Some implementations of `SecureRandom` may have locking contention
        //    that could show up in a multi-threaded environment.
        // 4. Per-instance allocation allows for override for testing or custom
        //    configurations, though this will require adding new constructors.
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            // This should never happen. The Javadoc for getInstanceStrong() says
            // "Every implementation of the Java platform is required to support
            // at least one strong SecureRandom implementation."
            throw new RuntimeException("No strong SecureRandom available", e);
        }
    }

    @Override
    public SecpPrivKeyBc ecPrivKeyCreate() {
        BigInteger privKey = ((ECPrivateKeyParameters) bcKeyPairCreate().getPrivate()).getD();
        return new SecpPrivKeyBc(privKey);
    }

    @Override
    public SecpPrivKeyBc ecPrivKeyImport(BigInteger privKeyInt) {
        return SecpPrivKeyBc.of(privKeyInt);
    }

    @Override
    public SecpPrivKeyBc ecPrivKeyImport(byte[] privKeyBytes) {
        return SecpPrivKeyBc.of(privKeyBytes);
    }

    @Override
    public SecpPubKey ecPubKeyCreate(SecpPrivKey privKey) {
        ECPoint pub = BC_ECDOMAIN_PARAMS.getG().multiply(privKey.getS());
        return toSecpPubKey(pub);
    }

    @Override
    public SecpKeyPair ecKeyPairCreate() {
        AsymmetricCipherKeyPair bcKeyPair = bcKeyPairCreate();
        BigInteger privKey = ((ECPrivateKeyParameters) bcKeyPair.getPrivate()).getD();
        ECPoint pubPoint = (((ECPublicKeyParameters) bcKeyPair.getPublic()).getQ());
        return new SecpKeyPairImpl(new SecpPrivKeyBc(privKey), toSecpPubKey(pubPoint));
    }

    @Override
    public SecpKeyPair ecKeyPairCreate(SecpPrivKey privKey) {
        SecpPrivKeyBc priv = (privKey instanceof SecpPrivKeyBc)
                ? (SecpPrivKeyBc) privKey
                : new SecpPrivKeyBc(privKey.getS());
        SecpPubKey pub = ecPubKeyCreate(priv);
        return new SecpKeyPairImpl(priv, pub);
    }

    /**
     * Generate a Bouncy Castle secp256k1 {@link AsymmetricCipherKeyPair}.
     * @return key pair
     */
    private AsymmetricCipherKeyPair bcKeyPairCreate() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(BC_ECDOMAIN_PARAMS, secureRandom);
        generator.init(keygenParams);
        return generator.generateKeyPair();
    }

    @Override
    public SecpPubKeyBc ecPubKeyTweakMul(SecpPoint.Uncompressed pubKey, BigInteger scalarMultiplier) {
        SecP256K1Point pubKeyBC = fromSecpPoint(pubKey);
        ECPoint pub = new FixedPointCombMultiplier().multiply(pubKeyBC, scalarMultiplier);
        return toSecpPubKey(pub);
    }

    @Override
    public SecpPubKeyBc ecPubKeyCombine(SecpPoint.Uncompressed  key1, SecpPoint.Uncompressed  key2) {
        SecP256K1Point pubKey1BC = fromSecpPoint(key1);
        SecP256K1Point pubKey2BC = fromSecpPoint(key2);
        ECPoint result = pubKey1BC.add(pubKey2BC);
        return toSecpPubKey(result);
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
        try {
            ECPoint bcPoint = BC_CURVE.decodePoint(inputData);
            return SecpResult.ok(toSecpPubKey(bcPoint));
        } catch (IllegalArgumentException e) {
            return SecpResult.err(0);
        }

    }

    @Override
    public SecpResult<SecpXOnlyPubKey> xOnlyPubKeyParse(byte[] inputData) {
        try {
            // Bouncy Castle expects compressed format, not X-Only
            byte[] serialized = prependByte(inputData, (byte) 0x2);
            BC_CURVE.decodePoint(serialized);
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
        checkArg(msg_hash_data.length == 32, "Message must be 32-byte (hash)");
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters bouncyPrivKey = new ECPrivateKeyParameters(privKey.getS(), BC_ECDOMAIN_PARAMS);
        signer.init(true, bouncyPrivKey);
        BigInteger[] components = signer.generateSignature(msg_hash_data);
        return SecpResult.ok(ecdsaSignature(components));
    }

    @Override
    public SecpResult<EcdsaSignature> ecdsaSignLowR(byte[] messageHashData, SecpPrivKey privKey) {
        checkArg(messageHashData.length == 32, "Message must be 32-byte (hash)");
        HMacDSAKCalculatorWithEntropy kCalculator = new HMacDSAKCalculatorWithEntropy(new SHA256Digest());
        ECDSASigner signer = new ECDSASigner(kCalculator);
        ECPrivateKeyParameters bouncyPrivKey = new ECPrivateKeyParameters(privKey.getS(), BC_ECDOMAIN_PARAMS);
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
        return !r.testBit(255);
    }

    // Convert and canonicalize signature
    private EcdsaSignature ecdsaSignature(BigInteger[] components) {
        return new EcdsaSignatureBc(components[0], canonicalize(components[1]));
    }

    BigInteger canonicalize(BigInteger s) {
        return s.compareTo(HALF_CURVE_ORDER) <= 0
                ? s
                : Secp256k1.N.subtract(s);
    }

    @Override
    public byte[] ecdsaSignatureSerializeCompact(EcdsaSignature sig) {
        return sig.serializeCompact();
    }

    @Override
    public SecpResult<EcdsaSignature> ecdsaSignatureParseCompact(byte[] serializedSignature) {
        try {
            if (serializedSignature.length != 64) {
                throw new IllegalArgumentException("Serialized signature is not 64 bytes");
            }
            BigInteger r = SecpScalarImpl.bytes32ToInteger(java.util.Arrays.copyOfRange(serializedSignature, 0, 32));
            BigInteger s = SecpScalarImpl.bytes32ToInteger(java.util.Arrays.copyOfRange(serializedSignature, 32, 64));
            return SecpResult.ok(new EcdsaSignatureBc(r, s));
        } catch (IllegalArgumentException iae) {
            return SecpResult.err(0);
        }
    }

    @Override
    public SecpResult<Boolean> ecdsaVerify(EcdsaSignature signature, byte[] msg_hash_data, SecpPubKey pubKey) {
        checkArg(msg_hash_data.length == 32, "Message must be 32-byte (hash)");
        if (!signature.hasLowS()) return SecpResult.ok(false);
        ECDSASigner signer = new ECDSASigner();
        SecP256K1Point pubPoint = fromSecpPoint(pubKey);
        ECPublicKeyParameters params = new ECPublicKeyParameters(pubPoint, BC_ECDOMAIN_PARAMS);
        signer.init(false, params);
        boolean result;
        try {
            result = signer.verifySignature(msg_hash_data, signature.rBigInteger(), signature.sBigInteger());
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
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] tagHash;

            digest.update(tag, 0, tag.length);
            tagHash = digest.digest();

            digest.reset();
            digest.update(tagHash, 0, 32);
            digest.update(tagHash, 0, 32);
            digest.update(message, 0, message.length);

            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public SchnorrSignature schnorrSigSign32(byte[] msg_hash, SecpPrivKey privKey) {
        checkArg(msg_hash.length == 32, "Message must be 32-byte (hash)");
        byte[] auxiliaryRandom = new byte[32];
        try {
            fillRandom(auxiliaryRandom);
            return schnorrSigSign32(msg_hash, privKey, auxiliaryRandom);
        } finally {
            Arrays.fill(auxiliaryRandom, (byte) 0);
        }
    }

    @Override
    public SchnorrSignature schnorrSigSign32(byte[] msg_hash, SecpPrivKey privKey, byte[] auxiliaryRandom) {
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(privKey.getS(), BC_ECDOMAIN_PARAMS);

        BIP340Signer signer = new BIP340Signer();

        signer.init(true, new ParametersWithRandom(priv, new FixedBytesRandom(auxiliaryRandom)));
        signer.update(msg_hash, 0, msg_hash.length);

        return SchnorrSignatureImpl.of(signer.generateSignature());
    }

    @Override
    public SecpResult<Boolean> schnorrSigVerify(SchnorrSignature signature, byte[] msg_hash, SecpXOnlyPubKey pubKey) {
        ECPublicKeyParameters pub = new ECPublicKeyParameters(BC_CURVE.decodePoint(pubKey.serializeCompressed()), BC_ECDOMAIN_PARAMS);

        BIP340Signer verifier = new BIP340Signer();
        verifier.init(false, pub);
        verifier.update(msg_hash, 0, msg_hash.length);

        return SecpResult.ok(verifier.verifySignature(signature.serialize()));
    }

    /**
     * Emits a fixed byte buffer once for the next {@code nextBytes} call — used to replay {@code aux_rand} from the
     * BIP-340 vectors. Vectors only sign once per row, so the single-shot behaviour is sufficient.
     */
    private static final class FixedBytesRandom
            extends SecureRandom
    {
        private static final long serialVersionUID = 1L;
        private final byte[] bytes;

        FixedBytesRandom(byte[] bytes)
        {
            this.bytes = Arrays.clone(bytes);
        }

        public void nextBytes(byte[] out)
        {
            if (out.length != bytes.length)
            {
                throw new IllegalStateException("FixedBytesRandom asked for " + out.length
                        + " bytes, held " + bytes.length);
            }
            System.arraycopy(bytes, 0, out, 0, out.length);
        }
    }

    @Override
    public SecpResult<EcdhSharedSecret> ecdh(SecpPubKey pubKey, SecpPrivKey privKey) {
        SecP256K1Point point = fromSecpPoint(pubKey);
        SecP256K1Point ssPoint = (SecP256K1Point) point.multiply(privKey.getS());
        byte[] hashed = ecdhHash(ssPoint);
        return SecpResult.ok(new EcdhSharedSecretImpl(hashed));
    }

    private byte[] ecdhHash(SecP256K1Point point) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
        digest.update(SecpPubKeyBc.serializeCompressed(point));
        return digest.digest();
    }

    @Override
    public byte[] ellswiftEncode(SecpPubKey pubKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    public SecpPubKey ellswiftDecode(byte[] encodedPubKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] ellswiftCreate(SecpPrivKey privKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] ellswiftXDH(byte[] encodedPubKeyA, byte[] encodedPubKeyB, SecpPrivKey privKey, boolean isPartyA) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void close() {

    }

    @Override
    public String toString() {
        return "Secp256k1/" + ProviderId.BOUNCY_CASTLE;
    }

    static SecpPubKeyBc toSecpPubKey(ECPoint bcPoint) {
        return SecpPubKeyBc.of(bcPoint);
    }

    static SecpPubKeyBc toSecpPoint(ECPoint bcPoint) {
        return SecpPubKeyBc.of(bcPoint);
    }

    static SecP256K1Point fromSecpPoint(SecpPoint.Uncompressed point) {
        return point instanceof SecpPubKeyBc
                ? ((SecpPubKeyBc) point).getQ()
                : (SecP256K1Point) BC_CURVE.createPoint(point.x().toBigInteger(), point.y().toBigInteger());
    }

    private static void checkArg(boolean condition, String string) {
        if (!condition) {
            throw new IllegalArgumentException(string);
        }
    }

    /**
     * @param data an array to fill with random data
     */
    private void fillRandom(byte[] data) {
        secureRandom.nextBytes(data);
    }
}
