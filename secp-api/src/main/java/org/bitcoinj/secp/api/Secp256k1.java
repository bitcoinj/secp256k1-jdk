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
 * A Java interface for <i>Elliptic Curve Cryptography</i> using the <a href="https://www.secg.org">SECG</a> curve
 * <a href="https://en.bitcoin.it/wiki/Secp256k1">secp256k1</a>.
 * <p>
 * The API is based on the C-language API of <a href="https://github.com/bitcoin-core/secp256k1">libsecp256k1</a>, but
 * is here adapted to modern, idiomatic, functional-style Java and use Elliptic Curve <i>types</i> from the Java Class Library,
 * such as {@link ECPublicKey} via the specialized {@link P256k1PubKey} subclass.
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

    Result<P256k1PubKey> ecPubKeyParse(CompressedPubKeyData inputData);

    Result<SignatureData> ecdsaSign(byte[] msg_hash_data, P256k1PrivKey seckey);

    Result<CompressedSignatureData> ecdsaSignatureSerializeCompact(SignatureData sig);

    Result<SignatureData> ecdsaSignatureParseCompact(CompressedSignatureData serialized_signature);

    Result<Boolean> ecdsaVerify(SignatureData sig, byte[] msg_hash_data, P256k1PubKey pubKey);

    default byte[] taggedSha256(String tag, String message) {
        return  taggedSha256(tag.getBytes(StandardCharsets.UTF_8), message.getBytes(StandardCharsets.UTF_8));
    }

    byte[] taggedSha256(byte[] tag, byte[] message);

    byte[] schnorrSigSign32(byte[] msg_hash, P256K1KeyPair keyPair);

    Result<Boolean> schnorrSigVerify(byte[] signature, byte[] msg_hash, P256K1XOnlyPubKey pubKey);

    Result<byte[]> ecdh(P256k1PubKey pubKey, P256k1PrivKey secKey);

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
