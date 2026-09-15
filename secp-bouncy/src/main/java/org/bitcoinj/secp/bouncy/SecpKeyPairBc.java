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

import org.bitcoinj.secp.SecpKeyPair;
import org.bitcoinj.secp.internal.SecpScalarImpl;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Point;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

/**
 * Bouncy Castle implementation of SecpKeyPair using {@link ECPrivateKeyParameters} and {@link ECPublicKeyParameters}.
 * {@link #getBcKeyPair()} returns {@link AsymmetricCipherKeyPair} which can be used by {@link org.bouncycastle.crypto.signers.BIP340Signer}.
 */
public class SecpKeyPairBc implements SecpKeyPair {
    private final ECPublicKeyParameters pubKeyParams;
    private final ECPrivateKeyParameters privKeyParams;

    SecpKeyPairBc(ECPublicKeyParameters pubKeyParams, ECPrivateKeyParameters privKeyParams) {
        this.pubKeyParams = pubKeyParams;
        this.privKeyParams = privKeyParams;
    }

    @Override
    public SecpPubKeyBc publicKey() {
        return new SecpPubKeyBc(getQ());
    }

    @Override
    public SecpPrivKeyBc privateKey() {
        if (privKeyParams.isDestroyed()) throwKeyDestroyed();
        return new SecpPrivKeyBc(privKeyParams.getD());
    }

    @Override
    public byte[] getEncoded() {
        if (privKeyParams.isDestroyed()) throwKeyDestroyed();
        return SecpScalarImpl.integerTo32Bytes(privKeyParams.getD());
    }

    @Override
    public BigInteger getS() {
        if (privKeyParams.isDestroyed()) throwKeyDestroyed();
        return privKeyParams.getD();
    }

    AsymmetricCipherKeyPair getBcKeyPair() {
        if (privKeyParams.isDestroyed()) throwKeyDestroyed();
        return new AsymmetricCipherKeyPair(pubKeyParams, privKeyParams);
    }

    // Method to get pubkey as SecP256K1Point directly
    SecP256K1Point getQ() {
        return (SecP256K1Point)(pubKeyParams.getQ());
    }

    @Override
    public void destroy() {
        privKeyParams.destroy();
    }

    @Override
    public boolean isDestroyed() {
        return privKeyParams.isDestroyed();
    }

    private void throwKeyDestroyed() {
        throw new IllegalStateException("Private Key has been destroyed");
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        throw new NotSerializableException("Serialization of private keys is prohibited.");
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        throw new NotSerializableException("Deserialization of private keys is prohibited.");
    }
}
