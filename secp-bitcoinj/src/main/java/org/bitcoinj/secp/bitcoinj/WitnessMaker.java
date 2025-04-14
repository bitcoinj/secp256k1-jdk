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
package org.bitcoinj.secp.bitcoinj;

import org.bitcoinj.secp.api.P256K1XOnlyPubKey;
import org.bitcoinj.secp.api.P256k1PubKey;
import org.bitcoinj.secp.api.Secp256k1;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Experimental class for making P2TR witness programs
 */
public class WitnessMaker {
    /**
     * 64-byte concatenation of two 32-byte hashes of "TapTweak"
     */
    private static final byte[] tweakPrefix = calcTagPrefix64("TapTweak");
    private final Secp256k1 secp;

    public WitnessMaker(Secp256k1 secp) {
        this.secp = secp;
    }

    public byte[] calcWitnessProgram(P256k1PubKey pubKey) {
        P256K1XOnlyPubKey xOnlyKey = pubKey.getXOnly();
        BigInteger tweakInt = calcTweak(xOnlyKey);
        P256k1PubKey G = new P256k1PubKey.P256k1PubKeyImpl(Secp256k1.EC_PARAMS.getGenerator());
        P256k1PubKey P2 = secp.ecPubKeyTweakMul(G, tweakInt);
        P256k1PubKey Q = secp.ecPubKeyCombine(pubKey, P2);
        return Q.getXOnly().getSerialized();
    }

    public static BigInteger calcTweak(P256K1XOnlyPubKey xOnlyPubKey) {
        var digest = newDigest();
        digest.update(tweakPrefix);
        byte[] hash = digest.digest(xOnlyPubKey.getSerialized());
        return new BigInteger(1, hash);
    }

    public static byte[] calcTagPrefix64(String tag) {
        byte[] hash = hash256(tag.getBytes(StandardCharsets.UTF_8));
        return ByteBuffer.allocate(64)
                .put(hash)
                .put(hash)
                .array();
    }

    private static byte[] hash256(byte[] message) {
        return newDigest().digest(message);
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }
}
