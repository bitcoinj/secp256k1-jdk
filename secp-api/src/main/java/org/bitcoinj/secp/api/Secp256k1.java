/*
 * Copyright 2023-2025 secp256k1-jdk Developers.
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
package org.bitcoinj.secp.api;

import java.io.Closeable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * Main interface providing <i>Elliptic Curve Cryptography</i> functions using the <a href="https://www.secg.org">SECG</a> curve.
 * <a href="https://en.bitcoin.it/wiki/Secp256k1">secp256k1</a>.
 * <p>
 * The API is based on the C-language API of <a href="https://github.com/bitcoin-core/secp256k1">libsecp256k1</a>, but
 * is here adapted to modern, idiomatic, functional-style Java and use Elliptic Curve <i>types</i> from the Java Class Library,
 * such as {@link ECPublicKey} via the specialized {@link SPPubKey} subclass.
 * <p>
 * Two implementations are being developed.
 * <ul>
 *     <li>
 *      Module {@code org.bitcoinj.secp.ffm}: Using a
 *      <a href="https://openjdk.org/jeps/454">Java Foreign Function and Memory API</a> interface to the
 *      <a href="https://github.com/bitcoin-core/secp256k1">secp256k1</a> library.
 *     </li>
 *     <li>
 *      Module {@code org.bitcoinj.secp.bouncy}: Using the <a href="https://www.bouncycastle.org">Bouncy Castle</a>
 *      Java library.
 *     </li>
 * </ul>
 */
public interface Secp256k1 extends Closeable {
    /** The secp256k1 field definition using the standard Java type */
    ECFieldFp FIELD = new ECFieldFp(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16));
    /** The secp256k1 curve definition using the standard Java type */
    EllipticCurve CURVE = new EllipticCurve(FIELD, BigInteger.ZERO, BigInteger.valueOf(7));
    /** The secp256k1 domain parameters definition using the standard Java type */
    ECParameterSpec EC_PARAMS = new ECParameterSpec(CURVE,
        new ECPoint(
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),     // G.x
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)),    // G.y
        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),         // n
        1);                                                                                                       // h

    /**
     * Create a new, randomly-generated private key.
     * @return the private key
     */
    SPPrivKey ecPrivKeyCreate();

    /**
     * Create a public key from the given private key.
     * @param seckey the private key
     * @return derived public key
     */
    SPPubKey ecPubKeyCreate(SPPrivKey seckey);

    /**
     * Create a new, randomly-generated private key and return it with its matching public key
     * @return newly generated key pair
     */
    SPKeyPair ecKeyPairCreate();

    /** Create a key pair structure from a known private key
     * @param privKey the private key
     * @return object containing both public and private key
     */
    SPKeyPair ecKeyPairCreate(SPPrivKey privKey);

    /**
     * Multiply a public key by a scalar, this is known as key "tweaking"
     * @param pubKey public key representing a point on the curve
     * @param scalarMultiplier scalar multiplier
     * @return the product
     */
    SPPubKey ecPubKeyTweakMul(SPPubKey pubKey, BigInteger scalarMultiplier);

    /**
     * Combine two public keys by adding them.
     * @param key1 first key
     * @param key2 second key
     * @return the sum
     */
    SPPubKey ecPubKeyCombine(SPPubKey key1, SPPubKey key2);

    /**
     * Serialize a public key
     * @param pubKey public key to serialize
     * @param flags serialization flags
     * @return pubKey serialized as a byte array
     */
    byte[] ecPubKeySerialize(SPPubKey pubKey, int flags);

    /**
     * Calculate an uncompressed point from a compressed point.
     * @param compressedPoint a compressed point
     * @return The same point, in uncompressed format
     */
    default SPPoint.Uncompressed ecPointUncompress(SPPoint.Compressed compressedPoint) {
        byte[] serializedCompressed = compressedPoint.getEncoded();
        SPPubKey pub = ecPubKeyParse(serializedCompressed).get();
        return pub.point();
    }

    /**
     * Parse a byte array as a public key
     * @param inputData raw data to parse as public key
     * @return public key result or error
     */
    SPResult<SPPubKey> ecPubKeyParse(byte[] inputData);

    /**
     * Sign a message hash using the ECDSA algorithm
     * @param msg_hash_data hash of message to sign
     * @param seckey private key
     * @return the signature
     */
    SPResult<SPSignatureData> ecdsaSign(byte[] msg_hash_data, SPPrivKey seckey);

    /**
     * Serialize a {@link SPSignatureData} as a Bitcoin <i>compact signature</i>. A compact signature is
     * the two signature component field integers (known as {@code r} and {@code s}) serialized in-order as
     * binary data in big-endian format.
     * @param sig signature object
     * @return compact signature bytes
     */
    byte[] ecdsaSignatureSerializeCompact(SPSignatureData sig);

    /**
     * Parse a Bitcoin <i>compact signature</i>. A compact signature is
     * the two signature component field integers (known as {@code r} and {@code s}) serialized in-order as
     * binary data in big-endian format.
     * @param serialized_signature compact signature bytes
     * @return signature object
     */
    SPResult<SPSignatureData> ecdsaSignatureParseCompact(byte[] serialized_signature);

    /**
     * Verify an ECDSA signature.
     * @param sig The signature to verify.
     * @param msg_hash_data A hash of the message to verify.
     * @param pubKey The pubkey that must have signed the message
     * @return true, false, or error
     */
    SPResult<Boolean> ecdsaVerify(SPSignatureData sig, byte[] msg_hash_data, SPPubKey pubKey);

    /**
     * Generate a tagged SHA-256 hash.
     * @param tag a tag specifying the context of usage
     * @param message the message itself
     * @return the SHA-256 HASH
     */
    default byte[] taggedSha256(String tag, String message) {
        return  taggedSha256(tag.getBytes(StandardCharsets.UTF_8), message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate a tagged SHA-256 hash.
     * @param tag a tag specifying the context of usage
     * @param message the message itself
     * @return the SHA-256 HASH
     */
    byte[] taggedSha256(byte[] tag, byte[] message);

    /**
     * Create a Schnorr signature for a message.
     * @param msg_hash a hash of a message to sign
     * @param keyPair the keypair for signing
     * @return the signature
     */
    byte[] schnorrSigSign32(byte[] msg_hash, SPKeyPair keyPair);

    /**
     * Verify a Schnorr signature.
     * @param signature the signature to verify
     * @param msg_hash hash of the message
     * @param pubKey pubkey that must have signed the message
     * @return true, false, or error
     */
    SPResult<Boolean> schnorrSigVerify(byte[] signature, byte[] msg_hash, SPXOnlyPubKey pubKey);

    /**
     * ECDH key agreement
     * @param pubKey pubkey of the other party
     * @param secKey secret key
     * @return ecdh key agreement
     */
    SPResult<byte[]> ecdh(SPPubKey pubKey, SPPrivKey secKey);

    /**
     * Override close and declare that no checked exceptions are thrown
     */
    void close();

    /**
     * Get the default implementation
     * @return A Secp256k1 instance using the <i>default</i> implementation
     */
    static Secp256k1 get() {
        return Secp256k1Provider.find().get();
    }

    /**
     * Get implementation by name
     * @param name implementation name
     * @return A Secp256k1 instance using the <i>default</i> implementation
     */
    static Secp256k1 getByName(String name) {
        return Secp256k1Provider.byName(name).get();
    }
}
