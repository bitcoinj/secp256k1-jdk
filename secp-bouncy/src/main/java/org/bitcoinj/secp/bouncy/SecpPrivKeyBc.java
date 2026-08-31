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

import org.bitcoinj.secp.SecpPrivKey;
import org.bitcoinj.secp.SecpScalar;
import org.bitcoinj.secp.internal.SecpScalarImpl;
import org.bitcoinj.secp.internal.UInt256;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

/**
 * Private key implementation that stores the private key as a {@link BigInteger}.
 */
public class SecpPrivKeyBc implements SecpPrivKey {
    private @Nullable BigInteger privKey;

    // Unchecked, for internal-use only
    SecpPrivKeyBc(BigInteger privKey) {
        this.privKey = privKey;
    }

    // Checked, use for import, etc.
    static SecpPrivKeyBc of(BigInteger privKey) {
         return new SecpPrivKeyBc(SecpScalar.checkInRange(privKey));
    }

    // Checked, use for import, etc.
    static SecpPrivKeyBc of(byte[] privKeyBytes) {
        return new SecpPrivKeyBc(UInt256.toBigInteger(SecpScalarImpl.checkInRange(privKeyBytes)));
    }

    @Override
    public byte[] getEncoded() {
        if (privKey == null) throwKeyDestroyed();
        byte[] result = new byte[32];
        UInt256.writeTo32Bytes(privKey, result, 0);
        return result;
    }

    @Override
    public BigInteger getS() {
        if (privKey == null) throwKeyDestroyed();
        return privKey;
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
