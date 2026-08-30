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
import org.bouncycastle.math.ec.custom.sec.SecP256K1Point;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

/**
 * Bouncy Castle implementation of SecpKeyPair using {@link BigInteger} and {@link SecP256K1Point}.
 */
public class SecpKeyPairBc implements SecpKeyPair {
    private @Nullable BigInteger privKey;
    private final SecP256K1Point bcPoint;

    SecpKeyPairBc(SecP256K1Point bcPoint, BigInteger privKey) {
        this.privKey = privKey;
        this.bcPoint = bcPoint;
    }

    @Override
    public SecpPubKeyBc publicKey() {
        return new SecpPubKeyBc(bcPoint);
    }

    @Override
    public SecpPrivKeyBc privateKey() {
        if (privKey == null) throwKeyDestroyed();
        return new SecpPrivKeyBc(privKey);
    }

    @Override
    public byte[] getEncoded() {
        if (privKey == null) throwKeyDestroyed();
        return SecpScalarImpl.integerTo32Bytes(privKey);
    }

    @Override
    public BigInteger getS() {
        if (privKey == null) throwKeyDestroyed();
        return privKey;
    }

    // Method to get pubkey as SecP256K1Point directly
    SecP256K1Point getQ() {
        return bcPoint;
    }

    @Override
    public void destroy() {
        privKey = null;
    }

    @Override
    public boolean isDestroyed() {
        return privKey == null;
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
