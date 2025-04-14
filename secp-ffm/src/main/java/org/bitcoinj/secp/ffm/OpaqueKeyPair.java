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
package org.bitcoinj.secp.ffm;

import org.bitcoinj.secp.api.P256K1KeyPair;
import org.bitcoinj.secp.api.P256k1PrivKey;
import org.bitcoinj.secp.api.P256k1PubKey;
import org.bitcoinj.secp.ffm.jextract.secp256k1_h;
import org.bitcoinj.secp.ffm.jextract.secp256k1_pubkey;

import java.lang.foreign.MemorySegment;
import java.security.spec.ECPoint;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 *
 */
public class OpaqueKeyPair implements P256K1KeyPair {
    private final byte[] opaque;

    public OpaqueKeyPair(byte[] opaque) {
        this.opaque = opaque.clone();
    }

    @Override
    public P256k1PubKey getPublic() {
        MemorySegment keyPairSegment = Secp256k1Foreign.globalArena.allocateFrom(JAVA_BYTE, opaque);
        MemorySegment pubKeySegment = secp256k1_pubkey.allocate(Secp256k1Foreign.globalArena);
        int return_val = secp256k1_h.secp256k1_keypair_pub(secp256k1_h.secp256k1_context_static(), pubKeySegment, keyPairSegment);
        assert(return_val == 1);
        ECPoint pubKeyPoint = Secp256k1Foreign.toPoint(pubKeySegment);
        return new P256k1PubKey.P256k1PubKeyImpl(pubKeyPoint);
    }

    public byte[] getOpaque() {
        return opaque.clone();
    }

    public P256k1PrivKey getPrivate() {
        return new PrivKeyPojo(getEncoded());
    }

    @Override
    public byte[] getEncoded() {
        MemorySegment keyPairSegment = Secp256k1Foreign.globalArena.allocateFrom(JAVA_BYTE, opaque);
        MemorySegment privKeySegment = Secp256k1Foreign.globalArena.allocate(32);
        int return_val = secp256k1_h.secp256k1_keypair_sec(secp256k1_h.secp256k1_context_static(), privKeySegment, keyPairSegment);
        assert(return_val == 1);
        return privKeySegment.toArray(JAVA_BYTE);
    }

    @Override
    public void destroy() {
        // TODO
    }
}
