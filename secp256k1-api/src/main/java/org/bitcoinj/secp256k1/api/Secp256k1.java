package org.bitcoinj.secp256k1.api;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Optional;

/**
 *
 */
public interface Secp256k1 extends AutoCloseable {


    ECFieldFp FIELD = new ECFieldFp(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16));
    EllipticCurve CURVE = new EllipticCurve(FIELD, BigInteger.ZERO, BigInteger.valueOf(7));
    ECParameterSpec EC_PARAMS = new ECParameterSpec(CURVE,
        new ECPoint(
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),     // G.x
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)),    // G.y
        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),         // n
        1);                                                                                                       // h

    P256k1PrivKey ecPrivKeyCreate();

    P256k1PubKey ecPubKeyCreate(P256k1PrivKey seckey);

    P256K1KeyPair ecKeyPairCreate();
    P256K1KeyPair ecKeyPairCreate(P256k1PrivKey privKey);

    P256k1PubKey ecPubKeyTweakMul(P256k1PubKey pubKey, BigInteger scalarMultiplier);

    P256k1PubKey ecPubKeyCombine(P256k1PubKey key1, P256k1PubKey key2);

    CompressedPubKeyData ecPubKeySerialize(P256k1PubKey pubKey, int flags);

    Optional<P256k1PubKey> ecPubKeyParse(CompressedPubKeyData inputData);

    Optional<SignatureData> ecdsaSign(byte[] msg_hash_data, P256k1PrivKey seckey);

    Optional<CompressedSignatureData> ecdsaSignatureSerializeCompact(SignatureData sig);

    Optional<SignatureData> ecdsaSignatureParseCompact(CompressedSignatureData serialized_signature);

    Optional<Boolean> ecdsaVerify(SignatureData sig, byte[] msg_hash_data, P256k1PubKey pubKey);

    default byte[] taggedSha256(String tag, String message) {
        return  taggedSha256(tag.getBytes(StandardCharsets.UTF_8), message.getBytes(StandardCharsets.UTF_8));
    }

    byte[] taggedSha256(byte[] tag, byte[] message);

    Object schnorrSigSign32(byte[] msg_hash, P256K1KeyPair keyPair);

    Optional<Boolean> schnorrSigVerify(byte[] signature, byte[] msg_hash, P256K1XOnlyPubKey pubKey);
}